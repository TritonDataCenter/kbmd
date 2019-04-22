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
		return (0);

	errfx(EXIT_FAILURE, ret, "%s command failed", cmd_tbl[i].name);
}

static errf_t *
do_create_zpool(int argc, char **argv)
{
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;
	errf_t *ret = ERRF_OK;
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

	VERIFY0(nvlist_lookup_uint8_array(resp, KBM_NV_ZPOOL_KEY, &key,
	    &keylen));
	VERIFY0(nvlist_lookup_string_array(resp, KBM_NV_CREATE_ARGS, &params,
	    &nparams));

	if ((ret = strarray_append(&args, "zpool")) != ERRF_OK ||
	    (ret = strarray_append(&args, "create")) != ERRF_OK)
		goto done;

	for (size_t i = 0; i < nparams; i++) {
		if ((ret = strarray_append(&args, "%s", params[i])) != ERRF_OK)
			goto done;
	}
	for (size_t i = 0; i < argc; i++) {
		if ((ret = strarray_append(&args, "%s", argv[i])) != ERRF_OK)
			goto done;
	}

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
	pid_t pid;
	int fds[3] = { -1, STDOUT_FILENO, STDERR_FILENO };
	int status;
	size_t written = 0;

	if ((ret = spawn(ZPOOL_CMD, argv, _environ, &pid, fds)) != ERRF_OK)
		return (ret);

	/*
	 * Since the key is a raw binary value, we cannot use interact()
	 * to feed it into the spawned zpool create command and must
	 * do it ourselves.
	 */
	do {
		ssize_t n;

		n = write(fds[0], key + written, keylen - written);
		if (n > 0) {
			written += n;
		} else if (n < 0) {
			if (errno == EINTR)
				continue;
			return (errfno("write", errno, ""));
		} else {
			break;
		}

	} while (written < keylen);

	(void) close(fds[0]);

	return (exitval(pid, &status));
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
add_datasets(nvlist_t *req, char **argv, int argc)
{
	if (argc == 0)
		return (ERRF_OK);

	uint_t n = argc;
	return (envlist_add_string_array(req, KBM_NV_ZFS_DATASETS, argv, n));
}

static errf_t *
do_unlock(int argc, char **argv)
{
	errf_t *ret;
	nvlist_t *req = NULL, *resp = NULL;
	int fd = -1;

	if ((ret = req_new(KBM_CMD_ZFS_UNLOCK, &req)) != ERRF_OK ||
	    (ret = add_datasets(req, argv, argc)) != ERRF_OK ||
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
