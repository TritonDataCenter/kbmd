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
 * Copyright 2019, Joyent, Inc.
 */

#include <bunyan.h>
#include <ctype.h>
#include <door.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <umem.h>
#include "kbmadm.h"
#include "pivy/errf.h"
#include "pivy/libssh/sshbuf.h"

#define	ZPOOL_CMD	"zpool"

char *guidstr;
char *recovery;
char *template_f;
uint8_t guid[GUID_LEN];

static errf_t *parse_guid(const char *, uint8_t guid[GUID_LEN]);
static errf_t *read_template_file(const char *, char **);
static errf_t *read_template_stdin(char **);
static errf_t *run_zpool_cmd(char **, const uint8_t *, size_t);
static errf_t *do_create_zpool(int, char **);
static errf_t *do_unlock(int, char **);
static errf_t *do_update_recovery(int, char **);
errf_t *do_recover(int, char **);

static struct {
	const char *name;
	errf_t *(*cmd)(int, char **);
} cmd_tbl[] = {
	{ "create-zpool", do_create_zpool },
	{ "recover", do_recover },
	{ "unlock", do_unlock },
	{ "update-recovery", do_update_recovery },
};

static void __NORETURN
usage(void)
{
	const char *name = getprogname();

	(void) fprintf(stderr,
	    "Usage: %1$s create-zpool <zpool create args>...\n"
	    "       %1$s recover\n"
	    "       %1$s unlock [dataset...]\n"
	    "       %1$s update-recovery [-d dataset] [-f template file]\n",
	    name);

	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	errf_t *ret = ERRF_OK;
	size_t i;
	int c;

	alloc_init();

	/*
	 * TODO: Add a flag that will control the log level output.  For
	 * most normal operation, we shouldn't expect to see much if any
	 * bunyan logging in kbmadm.  For development, testing, we'll be
	 * more verbose.
	 */
	if ((ret = init_log(BUNYAN_L_DEBUG)) != ERRF_OK) {
		errx(EXIT_FAILURE, "%s: %s in %s() at %s:%d",
		    errf_name(ret), errf_message(ret), errf_function(ret),
		    errf_file(ret), errf_line(ret));
	}

	/*
	 * We only have one thread, but some things (e.g. the spawning code)
	 * wants the per-thread logger.
	 */
	tlog = blog;

	/* XXX: For testing */
	while ((c = getopt(argc, argv, "g:t:r:")) != -1) {
		switch (c) {
		case 'g':
			guidstr = optarg;
			break;
		case 't':
			template_f = optarg;
			break;
		case 'r':
			recovery = optarg;
			break;
		case '?':
			return (1);
		}
	}

	if (recovery != NULL && guidstr == NULL) {
		err(EXIT_FAILURE, "-r also requires -g options");
	}

	if (guidstr != NULL) {
		if ((ret = parse_guid(guidstr, guid)) != ERRF_OK)
			errfx(EXIT_FAILURE, ret, "invalid GUID");
	}

	argc -= optind - 1;
	argv += optind - 1;
	/* XXX: End testing */

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
add_debug_args(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	char *buf = NULL;

	if (guidstr != NULL &&
	    (ret = envlist_add_uint8_array(req, KBM_NV_GUID, guid,
	    GUID_LEN)) != ERRF_OK)
		return (ret);

	if (recovery != NULL &&
	    (ret = add_b64(req, "recovery_token", recovery)) != ERRF_OK)
		return (ret);

	if (template_f == NULL)
		return (ERRF_OK);

	if ((ret = read_template_file(template_f, &buf)) != ERRF_OK)
		return (ret);

	ret = add_b64(req, KBM_NV_TEMPLATE, buf);

done:
	/*
	 * A recovery template is essentially public information, so
	 * freezero() is not needed here
	 */
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
	char **params = NULL;
	const char *dataset = NULL;
	uint_t keylen = 0, nparams = 0;
	int fd = -1;
	int c;
	strarray_t args = STRARRAY_INIT;

	/*
	 * When 'kbmadm create-zpool args...' is invoked, due to the
	 * complexity of interpreting the zpool creation arguments, we
	 * ideally want to just pass them through, with the necessary
	 * options for creating the ebox as a dataset property prepended
	 * to the argument list (i.e. -O rfd77:config=... -O encryption=on ...).
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
	 */

	/*
	 * A getopt(3C) call in main might have altered optind.  Reset to
	 * the initial value (1 in order to skip argv[0]).
	 */
	optind = 1; /* This might have been changed by a getopt(3C) main() */
	while ((c = getopt(argc, argv, ":fndBR:m:o:O:t:")) != -1)
		;

	if ((dataset = argv[optind]) == NULL) {
		return (errf("ArgumentError", NULL, "zpool name is missing"));
	}

	if ((ret = req_new(KBM_CMD_ZPOOL_CREATE, &req)) != ERRF_OK ||
	    (ret = add_debug_args(req)) != ERRF_OK ||
	    (ret = envlist_add_string(req, KBM_NV_DATASET,
	    dataset)) != ERRF_OK ||
	    (ret = open_door(&fd)) != ERRF_OK ||
	    (ret = nv_door_call(fd, req, &resp)) ||
	    (ret = check_error(resp)) != ERRF_OK)
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
	if (fd >= 0)
		(void) close(fd);
	nvlist_free(resp);
	nvlist_free(req);
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
	size_t written = 0;

	if ((ret = spawn(ZPOOL_CMD, argv, _environ, &pid, fds)) != ERRF_OK ||
	    (ret = interact(pid, fds, key, keylen, out, &status)) != ERRF_OK)
		return (ret);

	if (status != 0) {
		return (errf("CommandError", NULL, "zpool create returned %d",
		    status));
	}

	return (ERRF_OK);
}

static errf_t *
unlock_dataset(int fd, const char *dataset)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL, *resp = NULL;

	if ((ret = req_new(KBM_CMD_ZFS_UNLOCK, &req)) != ERRF_OK ||
	    (ret = envlist_add_string(req, KBM_NV_ZFS_DATASET,
	    dataset)) != ERRF_OK ||
	    (ret = nv_door_call(fd, req, &resp)) != ERRF_OK)
		return (ret);

	ret = check_error(resp);
	return (ret);
}

static errf_t *
do_unlock(int argc, char **argv)
{
	errf_t *ret;
	nvlist_t *req = NULL, *resp = NULL;
	int fd = -1;

	if ((ret = open_door(&fd)) != ERRF_OK)
		goto done;

	for (int i = 1; i < argc; i++) {
		ret = unlock_dataset(fd, argv[i]);
		if (ret != ERRF_OK)
			goto done;
	}

done:
	if (fd >= 0)
		(void) close(fd);
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

static errf_t *
do_update_recovery(int argc, char **argv)
{
	const char *dataset = "zones";
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL, *resp = NULL;
	char *tpl = NULL;
	int c, fd;

	while ((c = getopt(argc, argv, "d:f:")) != -1) {
		switch (c) {
		case 'd':
			dataset = optarg;
			break;
		case 'f':
			template_f = optarg;
			break;
		default:
			(void) fprintf(stderr, "Invalid flag -%c\n", optopt);
			usage();
		}
	}

	if (template_f != NULL) {
		if ((ret = read_template_file(template_f, &tpl)) != ERRF_OK)
			return (ret);
	} else {
		if ((ret = read_template_stdin(&tpl)) != ERRF_OK)
			return (ret);
		if (tpl == NULL || strlen(tpl) == 0) {
			ret = errf("ArgumentError", NULL,
			    "no template was specified");
			goto done;
		}
	}

	if ((ret = req_new(KBM_CMD_UPDATE_RECOVERY, &req)) != ERRF_OK ||
	    (ret = envlist_add_string(req, KBM_NV_DATASET,
	    dataset)) != ERRF_OK ||
	    (ret = add_b64(req, KBM_NV_TEMPLATE, tpl)) != ERRF_OK)
		goto done;

	if ((ret = open_door(&fd)) != ERRF_OK ||
	    (ret = nv_door_call(fd, req, &resp)) != ERRF_OK) {
		goto done;
	}

	ret = check_error(resp);

done:
	nvlist_free(req);
	nvlist_free(resp);
	free(tpl);
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
open_door(int *fdp)
{
	int fd;

	if ((fd = open(KBM_DOOR_PATH, O_RDONLY|O_CLOEXEC)) >= 0) {
		*fdp = fd;
		return (ERRF_OK);
	}

	if (errno != ENOENT)
		goto fail;

	if ((fd = open(KBM_ALT_DOOR_PATH, O_RDONLY|O_CLOEXEC)) >= 0) {
		*fdp = fd;
		return (ERRF_OK);
	}

fail:
	return (errfno("open", errno, "Error opening kbmd door"));
}

errf_t *
check_error(nvlist_t *resp)
{
	errf_t *ef, *ret;

	if (fnvlist_lookup_boolean_value(resp, KBM_NV_SUCCESS))
		return (ERRF_OK);

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
	char *buf = NULL;
	size_t buflen = 0;
	errf_t *ret = ERRF_OK;

	if ((ret = envlist_pack(in, &buf, &buflen)) != ERRF_OK)
		return (ret);

	da.data_ptr = buf;
	da.data_size = buflen;

	if ((ret = edoor_call(fd, &da)) != ERRF_OK)
		goto done;

	ret = envlist_unpack(da.rbuf, da.rsize, out);

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
