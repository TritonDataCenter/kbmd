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
#include "common.h"
#include "envlist.h"
#include "errf.h"
#include "kbm.h"
#include "kspawn.h"

#if 0
#define	ZPOOL_CMD	"zpool"
#else
#define	ZPOOL_CMD	"/root/bin/dummy-zpool"
#endif

static errf_t *req_new(kbm_cmd_t, nvlist_t **);
static errf_t *open_door(int *);
static errf_t *nv_door_call(int, nvlist_t *, nvlist_t **);
static errf_t *check_error(nvlist_t *);

static errf_t *run_zpool_cmd(char **, const uint8_t *, size_t);

static errf_t *do_create_zpool(int, char **);
static errf_t *do_recover(int, char **);
static errf_t *do_unlock(int, char **);

static struct {
	const char *name;
	errf_t *(*cmd)(int, char **);
} cmd_tbl[] = {
	{ "create-zpool", do_create_zpool },
	{ "recover", do_recover },
	{ "unlock", do_unlock }
};

int exitval = 0;

static void __NORETURN
usage(void)
{
	const char *name = getprogname();

	(void) fprintf(stderr,
	    "Usage: %1$s create-zpool <zpool create args>...\n"
	    "       %1$s recover\n"
	    "       %1$s unlock [dataset...]\n", name);

	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	errf_t *ret = ERRF_OK;
	size_t i;

	alloc_init();

	if (argc < 2)
		usage();

	for (i = 0; i < ARRAY_SIZE(cmd_tbl); i++) {
		if (strcmp(argv[1], cmd_tbl[i].name) == 0) {
			ret = cmd_tbl[i].cmd(argc - 2, argv + 2);
			break;
		}
	}

	if (i == ARRAY_SIZE(cmd_tbl)) {
		(void) fprintf(stderr, "Unrecognized command '%s'\n", argv[1]);
		usage();
	}

	if (ret == ERRF_OK)
		return (exitval);

	errfx(EXIT_FAILURE, ret, "%s command failed", cmd_tbl[i].name);
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

	if ((ret = strarray_append(args, "-O") != ERRF_OK) ||
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
do_create_zpool(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;
	uint8_t *key = NULL;
	char **params = NULL;
	uint_t keylen = 0, nparams = 0;
	int fd = -1;
	strarray_t args = STRARRAY_INIT;

	if ((ret = req_new(KBM_CMD_ZPOOL_CREATE, &req)) != ERRF_OK ||
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
	 * Append arguments from kbmd command line
	 */
	for (size_t i = 0; i < argc; i++) {
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
	errf_t *ret;
	custr_t *out[2] = { 0 };
	int fds[3] = { -1, STDOUT_FILENO, STDERR_FILENO };
	int status;
	pid_t pid;
	size_t written = 0;

	if ((ret = spawn(ZPOOL_CMD, argv, _environ, &pid, fds)) != ERRF_OK ||
	    (ret = interact(pid, fds, key, keylen, out, &status)) != ERRF_OK)
		return (ret);

	if (status != 0) {
		exitval++;
		return (errf("CommandError", NULL, "zpool create returned %d",
		    status));
	}

	return (ERRF_OK);
}

static errf_t *
do_recover(int argc, char **argv)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL, *resp = NULL;
	int fd = -1;

	if ((ret = req_new(KBM_CMD_RECOVER_START, &req)) != ERRF_OK ||
	    (ret = open_door(&fd)) != ERRF_OK ||
	    (ret = nv_door_call(fd, req, &resp)) != ERRF_OK ||
	    (ret = check_error(resp)) != ERRF_OK)
		goto done;

done:
	if (fd >= 0)
		(void) close(fd);
	nvlist_free(req);
	nvlist_free(resp);
	return (ret);
}

static errf_t *
unlock_dataset(int fd, const char *dataset)
{
	errf_t *ret;
	nvlist_t *req = NULL, *resp = NULL;

	if ((ret = req_new(KBMD_CMD_ZFS_UNLOCK, &req)) != ERRF_OK ||
	    (ret = envlist_add_string(req, KBMD_NV_ZFS_DATASET,
	    dataset)) != ERRF_OK ||
	    (ret = nv_door_call(fd, req, &resp)) != ERRF_OK)
		return (ret);

	if ((ret = check_error(resp)) != ERRF_OK) {
		errf_t *e = NULL;

		(void) fprintf(stderr, "Failed to unlock %s\n", dataset);
		for (e = ret; e != NULL; e = errf_cause(e)) {
			(void) fprintf(stderr, "  Caused by: %s: %s\n",
			     errf_name(e), errf_message(e));
			(void) fprintf(stderr, "    in %s() at %s:%d\n",
			    errf_function(e), errf_file(e), errf_line(e));
		}
		erfree(ret);
		exitval++;
	}

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

	for (int i = 1; i <= argc; i++) {
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

static errf_t *
check_error(nvlist_t *resp)
{
	if (fnvlist_lookup_boolean_value(resp, KBM_NV_SUCCESS))
		return (ERRF_OK);

	char *msg = fnvlist_lookup_string(resp, KBM_NV_ERRMSG);
	return (errf("InternalError", NULL, "kbmd returned an error: %s",
	    msg));
}

static errf_t *
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

static errf_t *
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

	if ((ret = edoor_call(fd, &da)) != ERRF_OK ||
	    (ret = envlist_unpack(da.rbuf, da.rsize, out)) != ERRF_OK)
		goto done;

done:
	/*
	 * This might contain key data, zero it out just to be safe.
	 */
	explicit_bzero(da.rbuf, da.rsize);
	VERIFY0(munmap(da.rbuf, da.rsize));
	umem_free(buf, buflen);
	return (ret);
}
