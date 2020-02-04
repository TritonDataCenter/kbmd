/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

#include <bunyan.h>
#include <ctype.h>
#include <door.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libzfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/mnttab.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <umem.h>
#include "kbmadm.h"
#include "pivy/errf.h"
#include "pivy/libssh/sshbuf.h"

#define	ZPOOL_CMD		"/sbin/zpool"

typedef struct cmd {
	const char *name;
	errf_t *(*cmd)(int, char **);
} cmd_t;

static boolean_t show_door_nvlist;
static int door_fd = -1;
libzfs_handle_t *g_zfs;

static errf_t *parse_log_level(const char *, bunyan_level_t *);
static errf_t *parse_guid(const char *, uint8_t guid[GUID_LEN]);
static errf_t *read_template_file(const char *, char **);
static errf_t *read_template_stdin(char **);
static errf_t *run_zpool_cmd(char **, const uint8_t *, size_t);

static errf_t *do_create_zpool(int, char **);
static errf_t *do_unlock(int, char **);
static errf_t *do_recover(int, char **);
static errf_t *do_recovery(int, char **);
static errf_t *do_add_recovery(int, char **);
static errf_t *do_show_recovery(int, char **);
static errf_t *do_activate_recovery(int, char **);
static errf_t *do_cancel_recovery(int, char **);
static errf_t *do_set_syspool(int, char **);
static errf_t *do_set_systoken(int, char **);

static cmd_t cmd_tbl[] = {
	{ "create-zpool", do_create_zpool },
	{ "recover", do_recover },
	{ "recovery", do_recovery },
	{ "set-syspool", do_set_syspool },
	{ "set-systoken", do_set_systoken },
	{ "unlock", do_unlock },
};

static cmd_t recovery_cmd_tbl[] = {
	{ "add", do_add_recovery },
	{ "list", do_show_recovery },
	{ "activate", do_activate_recovery },
	{ "cancel", do_cancel_recovery }
};

static void __NORETURN
usage(void)
{
	const char *name = getprogname();

/*BEGIN CSTYLED*/
	(void) fprintf(stderr,
	    "Usage: %1$s create-zpool [-g guid] [-t template] -- "
	    "<zpool create args>...\n"
	    "       %1$s recover [-c cfgnum] dataset\n"
	    "       %1$s unlock [-r] dataset...\n"
	    "       %1$s recovery add [-f] [-t template] [-r recovery_token] dataset\n"
	    "       %1$s recovery list [-p]\n"
            "       %1$s recovery activate dataset\n"
	    "       %1$s recovery cancel dataset\n",
	    name);
/*END CSTYLED*/

	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	errf_t *ret = ERRF_OK;
	bunyan_level_t log_level = BUNYAN_L_INFO;
	size_t i;
	int c;

	if (getenv("KBMADM_DOOR_DEBUG") != NULL)
		show_door_nvlist = B_TRUE;

	alloc_init();

	while ((c = getopt(argc, argv, "l:")) != -1) {
		switch (c) {
		case 'l':
			if ((ret = parse_log_level(optarg,
			    &log_level)) != ERRF_OK) {
				errfx(EXIT_FAILURE, ret, "Invalid log level");
			}
			break;
		}
	}

	if ((ret = init_log(log_level)) != ERRF_OK) {
		errfx(EXIT_FAILURE, ret, "Failed to set log level");
	}

	argc += optind - 1;
	argv += optind - 1;
	optind = 1;

	/*
	 * We only have one thread, but some things (e.g. the spawning code)
	 * wants the per-thread logger.
	 */
	tlog = blog;

	if (argc <= 1)
		usage();

	for (i = 0; i < ARRAY_SIZE(cmd_tbl); i++) {
		if (strcmp(argv[1], cmd_tbl[i].name) == 0) {
			ret = cmd_tbl[i].cmd(argc - 1, argv + 1);
			break;
		}
	}

	if (i == ARRAY_SIZE(cmd_tbl)) {
		(void) fprintf(stderr, "Unrecognized command '%s'\n", argv[1]);
		usage();
	}

	if (ret != ERRF_OK)
		errfx(EXIT_FAILURE, ret, "%s command failed", cmd_tbl[i].name);

	if (door_fd >= 0)
		VERIFY0(close(door_fd));

	return (0);
}

static errf_t *
add_create_arg(strarray_t *args, nvlist_t *arg)
{
	errf_t *ret;
	char *option = NULL;
	char *value = NULL;

	if ((ret = envlist_lookup_string(arg, "option", &option)) != ERRF_OK ||
	    (ret = envlist_lookup_string(arg, "value", &value)) != ERRF_OK)
		return (ret);

	if ((ret = strarray_append(args, "-O")) != ERRF_OK ||
	    (ret = strarray_append(args, "%s=%s", option, value)) != ERRF_OK)
		return (ret);

	return (ERRF_OK);
}

static errf_t *
add_create_args(strarray_t *args, nvlist_t *resp)
{
	errf_t *ret;
	nvlist_t **nvlargs = { 0 };
	uint_t nvlarglen = 0;

	if ((ret = envlist_lookup_nvlist_array(resp, KBM_NV_CREATE_ARGS,
	    &nvlargs, &nvlarglen)) != ERRF_OK)
		return (ret);

	for (size_t i = 0; i < nvlarglen; i++) {
		if ((ret = add_create_arg(args, nvlargs[i])) != ERRF_OK)
			return (ret);
	}

	return (ERRF_OK);
}

static errf_t *
parse_guid(const char *str, uint8_t guid[GUID_LEN])
{
	const char *p = str;
	size_t n = 0;
	size_t shift = 4;

	while (*p != '\0') {
		const char c = *p++;

		if (n == GUID_LEN) {
			return (errf("LengthError", NULL,
			    "'%s' is not a valid GUID", str));
		}

		switch (c) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			guid[n] |= (c - '0') << shift;
			break;
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
			guid[n] |= (c - 'A' + 10) << shift;
			break;
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
			guid[n] |= (c - 'a' + 10) << shift;
			break;
		case ' ': case ':': case '\t':
			continue;
		default:
			return (errf("InvalidCharacter", NULL,
			    "%c is not a valid hex digit", c));
		}

		if (shift == 4) {
			shift = 0;
		} else {
			shift = 4;
			n++;
		}
	}

	if (n != GUID_LEN) {
		return (errf("LengthError", NULL, "'%s' is not a valid GUID",
		    str));
	}

	/*
	 * If the GUID length is correct, we shouldn't have an odd number of
	 * bytes.
	 */
	ASSERT0(shift);

	return (ERRF_OK);
}

/*
 * Decode base64 encoded data 'b64' and add to nvl as a uint8 array w/
 * name 'name' to nvl
 */
static errf_t *
add_b64(nvlist_t *restrict nvl, const char *name, const char *b64)
{
	errf_t *ret = ERRF_OK;
	uint8_t *buf = NULL;
	size_t b64len = strlen(b64);
	int buflen;

	if ((buf = malloc(b64len)) == NULL)
		return (errfno("malloc", errno, ""));

	if ((buflen = b64_pton(b64, (unsigned char *)buf, b64len)) < 0) {
		ret = errf("DecodeError", NULL, "cannot decode base64 data");
		goto done;
	}

	ret = envlist_add_uint8_array(nvl, name, buf, (uint_t)buflen);

done:
	freezero(buf, b64len);
	return (ret);
}

static errf_t *
add_guidstr(nvlist_t *nvl, const char *name, const char *guidstr)
{
	errf_t *ret = ERRF_OK;
	uint8_t guid[GUID_LEN] = { 0 };

	if ((ret = parse_guid(guidstr, guid)) != ERRF_OK)
		return (ret);

	return (envlist_add_uint8_array(nvl, name, guid, GUID_LEN));
}

static errf_t *
add_template_file(nvlist_t *nvl, const char *name, const char *fname)
{
	errf_t *ret = ERRF_OK;
	char *buf = NULL;

	if (fname != NULL) {
		ret = read_template_file(fname, &buf);
	} else {
		ret = read_template_stdin(&buf);
	}

	if (ret != ERRF_OK) {
		goto done;
	}

	ret = add_b64(nvl, name, buf);
	/*
	 * A recovery template does not contain any sensitive information,
	 * so freezero(3C) isn't necessary.
	 */

done:
	free(buf);
	return (ret);
}

static errf_t *
do_create_zpool(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;
	uint8_t *key = NULL;
	const char *dataset = NULL;
	const char *guidstr = NULL;
	const char *template_f = NULL;
	uint_t keylen = 0;
	int c;
	strarray_t args = STRARRAY_INIT;

	while ((c = getopt(argc, argv, "g:t:")) != -1) {
		switch (c) {
		case 'g':
			guidstr = optarg;
			break;
		case 't':
			template_f = optarg;
			break;
		case '?':
			(void) fprintf(stderr, "Unknown option -%c\n",
			    optopt);
			usage();
		}
	}

	/*
	 * When 'kbmadm create-zpool args...' is invoked, due to the
	 * complexity of interpreting the zpool creation arguments, we
	 * ideally want to just pass them through, with the necessary
	 * options for creating the ebox as a dataset property prepended
	 * to the argument list (i.e.
	 * -O com.joyent.kbm:ebox=... -O encryption=on ...).
	 * However, we want to be able to link the ebox with the dataset at
	 * creation time.  As the intention is that most of the kbmd
	 * functionality will hopefully eventually be usable outside of Triton,
	 * we don't want to assume that mkzpool will be the only program that
	 * ever invokes 'kbmadm create-zpool' and as such we cannot assume the
	 * pool name will always be 'zones'.  This unfortnately means we must
	 * do a small amount of interpretation of the create-zpool arguments.
	 *
	 * Fortunately, in all 'zpool create' invocations, the pool name is
	 * always the first non-option argument, so the amount of argument
	 * processing is fairly minimal.  The getopt(3C) option string for
	 * the 'zpool create' command has been copied here only to allow us
	 * to correctly skip past any options and option arguments.  It does
	 * mean that any new options added to 'zpool create' should also
	 * be reflected here for full compatability.
	 *
	 * We first need to reset our state for getopt(3C) after processing
	 * our arguments.
	 */
	argc -= optind - 1;
	argv += optind - 1;
	optind = 1;

	while ((c = getopt(argc, argv, ":fndBR:m:o:O:t:")) != -1)
		;

	argc -= optind - 1;
	argv += optind - 1;

	if ((dataset = argv[1]) == NULL) {
		return (errf("ArgumentError", NULL, "zpool name is missing"));
	}

	fprintf(stderr, "dataset = %s\n", dataset);

	if ((ret = req_new(KBM_CMD_ZPOOL_CREATE, &req)) != ERRF_OK)
		goto done;

	if (guidstr != NULL &&
	    (ret = add_guidstr(req, KBM_NV_GUID, guidstr)) != ERRF_OK)
		goto done;

	if (template_f != NULL &&
	    (ret = add_template_file(req, KBM_NV_TEMPLATE,
	    template_f)) != ERRF_OK)
		goto done;

	if ((ret = envlist_add_string(req, KBM_NV_DATASET,
	    dataset)) != ERRF_OK)
		goto done;

	if ((ret = send_request(req, &resp)) != ERRF_OK)
		goto done;

	/*
	 * Build zpool create command line:
	 * 'zpool create <options from kbmd>'
	 */
	if ((ret = strarray_append(&args, "zpool")) != ERRF_OK ||
	    (ret = strarray_append(&args, "create")) != ERRF_OK ||
	    (ret = add_create_args(&args, resp)) != ERRF_OK)
		goto done;

	/*
	 * Append arguments from kbmadm create-zpool command line.
	 * argv[] looks similar to:
	 *	create-zpool
	 *	arg1
	 *	arg2
	 *	...
	 * So we start at arg[1].
	 */
	for (size_t i = 1; i < argc; i++) {
		if ((ret = strarray_append(&args, "%s", argv[i])) != ERRF_OK)
			goto done;
	}

	if ((ret = envlist_lookup_uint8_array(resp, KBM_NV_ZPOOL_KEY, &key,
	    &keylen)) != ERRF_OK)
		goto done;

	ret = run_zpool_cmd(args.sar_strs, key, keylen);

done:
	nvlist_free(req);
	nvlist_free(resp);
	strarray_fini(&args);
	return (ret);
}

static errf_t *
run_zpool_cmd(char **argv, const uint8_t *key, size_t keylen)
{
	errf_t *ret = ERRF_OK;
	custr_t *out[2] = { 0 };
	int fds[3] = { -1, STDOUT_FILENO, STDERR_FILENO };
	int status;
	pid_t pid;

	if ((ret = spawn(ZPOOL_CMD, argv, _environ, &pid, fds)) != ERRF_OK ||
	    (ret = interact(pid, fds, key, keylen, out, &status,
	    B_FALSE)) != ERRF_OK)
		return (ret);

	if (status != 0) {
		return (errf("CommandError", NULL, "zpool create returned %d",
		    status));
	}

	return (ERRF_OK);
}

static errf_t *
unlock_dataset(const char *dataset)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;

	if ((ret = req_new(KBM_CMD_ZFS_UNLOCK, &req)) != ERRF_OK ||
	    (ret = envlist_add_string(req, KBM_NV_ZFS_DATASET,
	    dataset)) != ERRF_OK) {
		goto done;
	}

	ret = send_request(req, &resp);

done:
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

static errf_t *
do_unlock(int argc, char **argv)
{
	errf_t *ret;
	int c;
	boolean_t recover_if_needed = B_FALSE;

	while ((c = getopt(argc, argv, "r")) != -1) {
		switch (c) {
		case 'r':
			recover_if_needed = B_TRUE;
			break;
		case '?':
			(void) fprintf(stderr, "Unknown option -%c\n",
			    optopt);
			usage();
		}
	}

	if (argv[optind] == NULL) {
		return (errf("ArgumentError", NULL, "dataset name is missing"));
	}

	for (int i = 1; i < argc; i++) {
		ret = unlock_dataset(argv[i]);
		if (ret != ERRF_OK) {
			if (errf_caused_by(ret, "RecoveryNeeded") &&
			    recover_if_needed) {
				warnfx(ret, "");
				errf_free(ret);

				ret = recover(argv[i], 0);
			}

			if (ret != ERRF_OK) {
				goto done;
			}
		}

		if (IS_ZPOOL(argv[i])) {
			mount_zpool(argv[i], NULL);
		}
	}

done:
	return (ret);
}

static errf_t *
do_recover(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = NULL;
	ulong_t cfgnum = 0;
	int c;

	while ((c = getopt(argc, argv, "c:")) != -1) {
		switch (c) {
		case 'c':
			if ((ret = eparse_ulong(optarg, &cfgnum)) == ERRF_OK) {
				if (cfgnum == 0) {
					ret = errf("RangeError", NULL,
					    "'0' is not a valid config number");
				} else if (cfgnum > UINT32_MAX) {
					ret = errf("RangeError", NULL,
					    "config number %lu is too large",
					    cfgnum);
				}
			}

			if (ret != ERRF_OK) {
				errfx(EXIT_FAILURE, ret,
				    "Invalid config number '%s'", optarg);
			}

			break;
		default:
			errx(EXIT_FAILURE, "Invalid option %-c", optopt);
		}
	}

	if ((dataset = argv[optind - 1]) == NULL) {
		return (errf("ArgumentError", NULL, "dataset name is missing"));
	}

	ret = recover(dataset, (uint32_t)cfgnum);
	return (ret);
}

static errf_t *
do_recovery(int argc, char **argv)
{
	if (argc < 2) {
		(void) fprintf(stderr, "missing subcommand\n");
		usage();
	}

	for (size_t i = 0; i < ARRAY_SIZE(recovery_cmd_tbl); i++) {
		if (strcmp(argv[1], recovery_cmd_tbl[i].name) != 0)
			continue;
		return (recovery_cmd_tbl[i].cmd(argc - 1, argv + 1));
	}

	return (errf("Unknown command", NULL,
	    "unrecognized recovery command '%s'", argv[1]));
}

static errf_t *
do_add_recovery(int argc, char **argv)
{
	const char *dataset = "zones";
	const char *template_f = NULL;
	const char *rtoken_str = NULL;
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;
	int c;
	boolean_t force = B_FALSE;

	while ((c = getopt(argc, argv, "ft:r:")) != -1) {
		switch (c) {
		case 'f':
			force = B_TRUE;
			break;
		case 'r':
			rtoken_str = optarg;
			break;
		case 't':
			template_f = optarg;
			break;
		default:
			(void) fprintf(stderr, "Invalid flag -%c\n", optopt);
			usage();
		}
	}

	if ((dataset = argv[optind]) == NULL) {
		return (errf("ArgumentError", NULL, "dataset name is missing"));
	}

	if ((ret = req_new(KBM_CMD_ADD_RECOVERY, &req)) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_add_string(req, KBM_NV_DATASET,
	    dataset)) != ERRF_OK)
		goto done;

	if ((ret = envlist_add_boolean_value(req, KBM_NV_STAGE,
	    !force)) != ERRF_OK)
		goto done;

	if ((ret = add_template_file(req, KBM_NV_TEMPLATE,
	    template_f)) != ERRF_OK) {
		goto done;
	}

	if (rtoken_str != NULL &&
	    (ret = add_b64(req, KBM_NV_RTOKEN, rtoken_str)) != ERRF_OK) {
		goto done;
	}

	ret = send_request(req, &resp);

done:
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

static errf_t *
do_show_recovery(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;
	nvlist_t *cfgs = NULL;
	nvpair_t *pair = NULL;
	int c;
	boolean_t opt_p = B_FALSE;
	boolean_t opt_v = B_FALSE;

	while ((c = getopt(argc, argv, "pv")) != -1) {
		switch (c) {
		case 'p':
			opt_p = B_TRUE;
			break;
		case 'v':
			opt_v = B_TRUE;
			break;
		default:
			(void) fprintf(stderr, "Invalid flag -%c\n", optopt);
			usage();
		}
	}

	if ((ret = req_new(KBM_CMD_LIST_RECOVERY, &req)) != ERRF_OK)
		return (ret);

	if ((ret = send_request(req, &resp)) != ERRF_OK)
		goto done;

	if ((ret = envlist_lookup_nvlist(resp, KBM_NV_CONFIGS,
	    &cfgs)) != ERRF_OK) {
		goto done;
	}

	for (pair = nvlist_next_nvpair(cfgs, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(cfgs, pair)) {
		const char *name = nvpair_name(pair);
		nvlist_t *cfg = NULL;
		nvlist_t **cfgs = NULL;
		uint_t ncfgs = 0;
		uint8_t *hash = NULL;
		uint_t hashlen = 0;

		if (nvpair_type(pair) != DATA_TYPE_NVLIST) {
			ret = errf("InternalError", NULL,
			    "kbmd response was not an nvlist");
			goto done;
		}

		VERIFY0(nvpair_value_nvlist(pair, &cfg));

		if ((ret = envlist_lookup_uint8_array(cfg, KBM_NV_CONFIG_HASH,
		    &hash, &hashlen)) != ERRF_OK)
			goto done;

		char hashstr[hashlen * 2 + 1];
		tohex(hash, (size_t)hashlen, hashstr, hashlen * 2 + 1);

		if (opt_p) {
			(void) printf("%s:%s\n", name, hashstr);
			continue;
		}

		if ((ret = envlist_lookup_nvlist_array(cfg, KBM_NV_CONFIGS,
		    &cfgs, &ncfgs)) != ERRF_OK)
			goto done;

		(void) printf("%s config (%s):\n", name, hashstr);

		if ((ret = show_configs(cfgs, ncfgs, opt_v)) != ERRF_OK)
			goto done;
	}

done:
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

static errf_t *
do_activate_recovery(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = NULL;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;

	if ((dataset = argv[1]) == NULL) {
		return (errf("ArgumentError", NULL, "dataset name is missing"));
	}

	if ((ret = req_new(KBM_CMD_ACTIVATE_RECOVERY, &req)) != ERRF_OK)
		goto done;

	if ((ret = envlist_add_string(req, KBM_NV_DATASET, dataset)) != ERRF_OK)
		goto done;

	ret = send_request(req, &resp);

done:
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

static errf_t *
do_cancel_recovery(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = NULL;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;

	if ((dataset = argv[optind]) == NULL) {
		return (errf("ArgumentError", NULL, "dataset name is missing"));
	}

	if ((ret = req_new(KBM_CMD_CANCEL_RECOVERY, &req)) != ERRF_OK)
		goto done;

	if ((ret = envlist_add_string(req, KBM_NV_DATASET, dataset)) != ERRF_OK)
		goto done;

	ret = send_request(req, &resp);

done:
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

/*
 * Undocumented option for use by fs-joyent
 */
static errf_t *
do_set_syspool(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;

	if (argc < 2) {
		usage();
	}

	if ((ret = req_new(KBM_CMD_SET_SYSPOOL, &req)) != ERRF_OK ||
	    (ret = envlist_add_string(req, KBM_NV_SYSPOOL,
	    argv[1])) != ERRF_OK) {
		goto done;
	}

	ret = send_request(req, &resp);

done:
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

static errf_t *
do_set_systoken(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;
	uint8_t guid[GUID_LEN] = { 0 };

	if (argc < 2) {
		errx(EXIT_FAILURE, "No GUID supplied");
	}

	if ((ret = parse_guid(argv[1], guid)) != ERRF_OK)
		goto done;

	if ((ret = req_new(KBM_CMD_SET_SYSTOKEN, &req)) != ERRF_OK ||
	    (ret = envlist_add_uint8_array(req, KBM_NV_GUID, guid,
	    GUID_LEN)) != ERRF_OK) {
		goto done;
	}

	ret = send_request(req, &resp);

done:
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

static errf_t *
read_template_stdin(char **bufp)
{
	errf_t *ret = ERRF_OK;
	custr_t *buf = NULL;
	char *line = NULL;
	size_t linesz = 0;
	ssize_t n;

	if ((ret = ecustr_alloc(&buf)) != ERRF_OK)
		return (ret);

	(void) printf("Enter base64 encoded template:\n");

	while ((n = getline(&line, &linesz, stdin)) > 0) {
		char *start, *end;

		start = line;
		end = &line[n - 1];

		/* strip leading whitespace */
		while (*start != '\0' && isspace(*start))
			start++;
		if (*start == '\0')
			continue;

		/* strip trailing whitespace */
		while (end > start && isspace(*end)) {
			*end = '\0';
			end--;
		}

		/* ignore empty lines */
		if (end == start)
			continue;

		if ((ret = ecustr_append(buf, line)) != ERRF_OK)
			goto done;
	}

	if (ferror(stdin)) {
		ret = errfno("getline", errno, "error reading template");
		goto done;
	}

	if ((ret = zalloc(custr_len(buf) + 1, bufp)) != ERRF_OK)
		goto done;

	bcopy(custr_cstr(buf), *bufp, custr_len(buf));

done:
	free(line);
	custr_free(buf);
	return (ret);
}

static errf_t *
read_template_file(const char *filename, char **bufp)
{
	errf_t *ret = ERRF_OK;
	char *buf = NULL;
	FILE *f = NULL;
	struct stat st = { 0 };
	ssize_t n;

	if ((f = fopen(filename, "r")) == NULL)
		return (errfno("fopen", errno, "cannot open %s", filename));

	if (fstat(fileno(f), &st) < 0) {
		ret = errfno("fstat", errno, "cannot stat %s", filename);
		goto fail;
	}

	if ((ret = zalloc(st.st_size + 1, &buf)) != ERRF_OK)
		goto fail;

	n = fread(buf, 1, st.st_size, f);
	if (n < st.st_size && feof(f)) {
		ret = errf("IOError", NULL,
		    "short read while reading template file %s", filename);
		goto fail;
	}

	if (ferror(f)) {
		ret = errf("IOError", NULL,
		    "error reading template file %s", filename);
		goto fail;
	}

	buf[n] = '\0';

	if (fclose(f) < 0) {
		ret = errfno("fclose", errno, "error closing template file %s",
		    filename);
		goto failnoclose;
	}

	*bufp = buf;
	return (ERRF_OK);

fail:
	(void) fclose(f);

failnoclose:
	free(buf);
	*bufp = NULL;
	return (ret);
}

errf_t *
assert_door(void)
{
	if (door_fd != -1) {
		return (ERRF_OK);
	}

	if ((door_fd = open(KBMD_DOOR_PATH, O_RDONLY|O_CLOEXEC)) >= 0) {
		return (ERRF_OK);
	}

	return (errfno("open", errno, "Error opening kbmd door (%s)",
	    KBMD_DOOR_PATH));
}

errf_t *
check_error(nvlist_t *resp)
{
	errf_t *ef, *ret;
	boolean_t success;

	if (resp == NULL) {
		return (errf("InternalError", NULL,
		    "kbmd did not return any data"));
	}

	if ((ret = envlist_lookup_boolean_value(resp, KBM_NV_SUCCESS,
	    &success)) != ERRF_OK) {
		return (errf("InternalError", NULL,
		    "kbmd is missing request result"));
	}

	if (success) {
		return (ERRF_OK);
	}

	if ((ret = envlist_lookup_errf(resp, KBM_NV_ERRMSG, &ef)) != ERRF_OK) {
		return (errf("InternalError", ret,
		    "failed to retrieve error data from kbmd"));
	}

	return (errf("KbmdError", ef, "kbmd returned an error"));
}

errf_t *
req_new(kbm_cmd_t cmd, nvlist_t **nvlp)
{
	errf_t *ret;

	if ((ret = envlist_alloc(nvlp)) != ERRF_OK ||
	    (ret = envlist_add_int32(*nvlp, KBM_NV_CMD,
	    (int32_t)cmd)) != ERRF_OK)
		return (ret);

	return (ERRF_OK);
}

static errf_t *
edoor_call(int fd, door_arg_t *da)
{
	if (door_call(fd, da) < 0)
		return (errfno("door_call", errno, ""));
	return (ERRF_OK);
}

errf_t *
nv_door_call(int fd, nvlist_t *in, nvlist_t **out)
{
	door_arg_t da = { 0 };
	door_desc_t ddesc = { 0 };
	char *buf = NULL;
	size_t buflen = 0;
	errf_t *ret = ERRF_OK;

	if (show_door_nvlist) {
		(void) fprintf(stderr, "REQUEST:\n");
		nvlist_print(stderr, in);
	}

	if ((ret = envlist_pack(in, &buf, &buflen)) != ERRF_OK)
		return (ret);

	ddesc.d_attributes = DOOR_DESCRIPTOR;
	ddesc.d_data.d_desc.d_descriptor = fileno(stdout);

	da.data_ptr = buf;
	da.data_size = buflen;
	da.desc_ptr = &ddesc;
	da.desc_num = 1;

	if ((ret = edoor_call(fd, &da)) != ERRF_OK)
		goto done;

	if (da.data_ptr != NULL) {
		if ((ret = envlist_unpack(da.data_ptr, da.data_size,
		    out)) != ERRF_OK) {
			goto done;
		}
	} else {
		*out = NULL;
	}

	if (show_door_nvlist) {
		if (*out != NULL) {
			(void) fprintf(stderr, "RESPONSE:\n");
			nvlist_print(stderr, *out);
		} else {
			(void) fprintf(stderr, "<NO RESPONSE>\n");
		}
	}

done:
	if (da.rbuf != NULL) {
		/*
		 * This could contain key data, so zero it out just to be
		 * safe.
		 */
		explicit_bzero(da.rbuf, da.rsize);
		VERIFY0(munmap(da.rbuf, da.rsize));
	}
	umem_free(buf, buflen);
	return (ret);
}

/*
 * Wrapper around assert_door, nv_door_call(), and check_error() for commands
 * that do a single request/response over the kbmd door.
 */
errf_t *
send_request(nvlist_t *restrict req, nvlist_t **restrict respp)
{
	errf_t *ret = ERRF_OK;

	*respp = NULL;

	if ((ret = assert_door()) != ERRF_OK ||
	    (ret = nv_door_call(door_fd, req, respp)) != ERRF_OK) {
		return (ret);
	}

	ret = check_error(*respp);
	return (ret);
}

/*
 * Normally, 'zpool import' will mount any 'canmount=on' datasets. Encrypted
 * datasets end up not being mounted after their keys are loaded. We currently
 * emulate the 'canmount' behavior after the key is loaded (either via
 * unlock or post-recovery). Like the 'zfs mount -a' behavior, this is
 * best effort, and we silently ignore errors.
 */
void
mount_zpool(const char *pool, const char *mntopts)
{
	errf_t *ret = ERRF_OK;
	zpool_handle_t *zhp = NULL;

	(void) bunyan_debug(tlog, "Attempting to mount datasets in pool",
	    BUNYAN_T_STRING, "pool", pool,
	    BUNYAN_T_END);

	if ((ret = assert_libzfs()) != ERRF_OK) {
		errf_free(ret);
		return;
	}

	if ((zhp = zpool_open_canfail(g_zfs, pool)) == NULL) {
		goto done;
	}

	if (zpool_get_state(zhp) == POOL_STATE_UNAVAIL) {
		goto done;
	}

	(void) zpool_enable_datasets(zhp, mntopts, 0);

done:
	zpool_close(zhp);
}

errf_t *
assert_libzfs(void)
{
	if (g_zfs != NULL || (g_zfs = libzfs_init()) != NULL) {
		return (ERRF_OK);
	}

	return (errfno("libzfs_init", errno, "cannot initialize libzfs"));
}

static struct {
	const char *str;
	bunyan_level_t lvl;
} levels[] = {
	{ "trace", BUNYAN_L_TRACE },
	{ "debug", BUNYAN_L_DEBUG },
	{ "info", BUNYAN_L_INFO },
	{ "warn", BUNYAN_L_WARN },
	{ "error", BUNYAN_L_ERROR },
	{ "fatal", BUNYAN_L_FATAL }
};

errf_t *
parse_log_level(const char *lvl, bunyan_level_t *levelp)
{
	for (size_t i = 0; i < ARRAY_SIZE(levels); i++) {
		if (strcasecmp(lvl, levels[i].str) == 0) {
			*levelp = levels[i].lvl;
			return (ERRF_OK);
		}
	}

	return (errf("ParseError", NULL, "'%s' is not a valid log level", lvl));
}
