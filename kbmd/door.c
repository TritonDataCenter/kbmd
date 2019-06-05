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
#include <door.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <stropts.h>
#include <sys/debug.h>
#include <thread.h>
#include <unistd.h>
#include <umem.h>
#include "ecustr.h"
#include "envlist.h"
#include "errf.h"
#include "kbm.h"
#include "kbmd.h"
#include "common.h"

#define	DOOR_RET_MAX 16384

struct retbuf {
	char		*rt_buf;
	size_t		rt_len;
	nv_alloc_t	rt_nvalloc;
};

int door_fd = -1;
static thread_key_t retkey = THR_ONCE_KEY;

/*
 * A packed nvlist suitable for use with door_return(3C).  Created during
 * kbmd startup (by kbmd_door_setup) as a return value of last resort that
 * should always be available to return.
 */
static char *generr;
static size_t generr_sz;

static void
session_log_start(door_cred_t *dc)
{
	bunyan_logger_t *child;

	VERIFY0(bunyan_child(blog, &child,
	    BUNYAN_T_UINT32, "req_pid", (uint32_t)dc->dc_pid,
	    BUNYAN_T_UINT32, "req_uid", (uint32_t)dc->dc_ruid,
	    BUNYAN_T_END));

	tlog = child;
}

static void
session_log_end(void)
{
	bunyan_fini(tlog);
	tlog = NULL;
}

static struct retbuf *
retbuf_alloc(void)
{
	struct retbuf *b;

	if ((b = umem_zalloc(sizeof (*b), UMEM_DEFAULT)) == NULL)
		return (NULL);

	if ((b->rt_buf = umem_zalloc(DOOR_RET_MAX, UMEM_DEFAULT)) == NULL) {
		umem_free(b, sizeof (*b));
		return (NULL);
	}

	b->rt_len = DOOR_RET_MAX;
	if (nv_alloc_init(&b->rt_nvalloc, nv_fixed_ops, b->rt_buf,
	    b->rt_len) != 0) {
		umem_free(b->rt_buf, b->rt_len);
		umem_free(b, sizeof (*b));
		return (NULL);
	}

	return (b);
}

static void
retbuf_free(void *p)
{
	if (p == NULL)
		return;

	struct retbuf *b = p;

	nv_alloc_fini(&b->rt_nvalloc);
	umem_free(b->rt_buf, b->rt_len);
	umem_free(b, sizeof (*b));
}

/*
 * Packs and returns the given nvlist to the door caller.
 * Note: the nvlist is freed by kbmd_ret_nvlist, and the request log instance
 * is freed.
 */
void __NORETURN
kbmd_ret_nvlist(nvlist_t *resp)
{
	struct retbuf *b = NULL;
	size_t nvlen;

	flockfile(stderr);
	fprintf(stderr, "Response:\n");
	nvlist_print(stderr, resp);
	fputc('\n', stderr);
	funlockfile(stderr);

	VERIFY0(nvlist_size(resp, &nvlen, NV_ENCODE_NATIVE));
	if (nvlen > DOOR_RET_MAX) {
		(void) bunyan_error(tlog,
		    "Tried to return more than DOOR_RET_MAX",
		    BUNYAN_T_UINT64, "retsize", nvlen,
		    BUNYAN_T_END);
		nvlist_free(resp);
		session_log_end();
		door_return(generr, generr_sz, NULL, 0);
	}

	VERIFY0(thr_keycreate_once(&retkey, retbuf_free));
	VERIFY0(thr_getspecific(retkey, (void **)&b));
	if (b == NULL) {
		if ((b = retbuf_alloc()) == NULL)
			door_return(generr, generr_sz, NULL, 0);
		VERIFY0(thr_setspecific(retkey, b));
	}

	bzero(b->rt_buf, b->rt_len);

	/* The nvlist_size() check above should guarantee this doesn't fail */
	VERIFY0(nvlist_xpack(resp, &b->rt_buf, &b->rt_len, NV_ENCODE_NATIVE,
	    &b->rt_nvalloc));

	if (fnvlist_lookup_boolean_value(resp, KBM_NV_SUCCESS)) {
		(void) bunyan_debug(tlog, "Returning success",
		    BUNYAN_T_END);
	} else {
		char *errmsg = fnvlist_lookup_string(resp, KBM_NV_ERRMSG);

		(void) bunyan_debug(tlog, "Returning error",
		    BUNYAN_T_STRING, "errmsg", errmsg,
		    BUNYAN_T_END);
	}

	nvlist_free(resp);
	session_log_end();
	door_return(b->rt_buf, nvlen, NULL, 0);
	/* NOTREACHED */
	abort();
}

void __NORETURN
kbmd_ret_error(errf_t *ef)
{
	nvlist_t *nvret = NULL;
	custr_t *cu = NULL;
	errf_t *ret = ERRF_OK;

	if ((ret = envlist_alloc(&nvret)) != ERRF_OK ||
	    (ret = ecustr_alloc(&cu)) != ERRF_OK)
		goto fail;

	if (nvlist_add_boolean_value(nvret, KBM_NV_SUCCESS, B_FALSE) != 0)
		goto fail;

	ret = ecustr_append_printf(cu, "%s: %s in %s() at %s:%d\n",
	    errf_name(ef), errf_message(ef), errf_function(ef), errf_file(ef),
	    errf_line(ef));
	if (ret != ERRF_OK)
		goto fail;

	for (errf_t *cause = errf_cause(ef); cause != NULL;
	    cause = errf_cause(cause)) {
		ret = ecustr_append_printf(cu,
		    "    Caused by %s: %s in %s() at %s:%d\n",
		    errf_name(cause), errf_message(cause), errf_function(cause),
		    errf_file(cause), errf_line(cause));

		/*
		 * If we fail, go with as much as we have as a last ditch
		 * effort to report something.
		 */
		if (ret != ERRF_OK)
			break;
	}

	if (nvlist_add_string(nvret, KBM_NV_ERRMSG, custr_cstr(cu)) < 0)
		goto fail;

	kbmd_ret_nvlist(nvret);

fail:
	erfree(ef);
	erfree(ret);
	nvlist_free(nvret);
	custr_free(cu);
	door_return(generr, generr_sz, NULL, 0);
	/* NOTREACHED */
	abort();
}

static void
kbmd_door_server(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc)
{
	door_cred_t dcred;
	nvlist_t *req;
	errf_t *ret = ERRF_OK;
	int rc, cmdval;

	rc = door_cred(&dcred);
	if (rc != 0) {
		(void) bunyan_error(blog,
		    "Unable to obtain caller credentials",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "errmsg", strerror(errno),
		    BUNYAN_T_END);
		door_return(generr, generr_sz, NULL, 0);
	}

	session_log_start(&dcred);

	ret = envlist_unpack(argp, arg_size, &req);
	if (ret != ERRF_OK) {
		(void) bunyan_info(tlog, "Unable to unpack request",
		    BUNYAN_T_INT32, "errno", errf_errno(ret),
		    BUNYAN_T_STRING, "errmsg", errf_message(ret),
		    BUNYAN_T_END);
		erfree(ret);
		door_return(generr, generr_sz, NULL, 0);
	}

	flockfile(stderr);
	fprintf(stderr, "Request:\n");
	nvlist_print(stderr, req);
	fputc('\n', stderr);
	funlockfile(stderr);

	ret = envlist_lookup_int32(req, KBM_NV_CMD, &cmdval);
	if (ret != ERRF_OK) {
		(void) bunyan_info(tlog, "Unable to obtain command",
		    BUNYAN_T_INT32, "errno", errf_errno(ret),
		    BUNYAN_T_STRING, "errmsg", errf_message(ret),
		    BUNYAN_T_END);
		nvlist_free(req);
		kbmd_ret_error(errf("InvalidCommand", ret,
		    "Unable to retrieve command value"));
	}

	switch ((kbm_cmd_t)cmdval) {
	case KBM_CMD_ZFS_UNLOCK:
		kbmd_zfs_unlock(req);
		break;
	case KBM_CMD_ZPOOL_CREATE:
		kbmd_zpool_create(req);
		break;
	case KBM_CMD_RECOVER_START:
		kbmd_recover_start(req, dcred.dc_pid);
		break;
	case KBM_CMD_RECOVER_RESP:
		kbmd_recover_resp(req, dcred.dc_pid);
		break;
	default:
		(void) bunyan_info(tlog, "Unrecognized command",
		    BUNYAN_T_INT32, "cmdval", (int32_t)cmdval,
		    BUNYAN_T_END);
		nvlist_free(req);

		kbmd_ret_error(errf("InvalidCommand", NULL,
		    "Invalid command value %d", cmdval));
		break;
	}
}

static void
create_generr(void)
{
	nvlist_t *nvl;

	VERIFY0(nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0));
	fnvlist_add_boolean_value(nvl, KBM_NV_SUCCESS, B_FALSE);
	fnvlist_add_string(nvl, KBM_NV_ERRMSG, "general error");
	VERIFY0(nvlist_pack(nvl, &generr, &generr_sz, NV_ENCODE_NATIVE, 0));
}

int
kbmd_door_setup(const char *path)
{
	int ret, fd;

	create_generr();

	/*
	 * XXX: We might want to manually control door server thread creation
	 * to control memory and resource usage for requests.  More likely to
	 * be of concern once we add per-zone token support.
	 */
	door_fd = door_create(kbmd_door_server, NULL, 0);
	if (door_fd == -1)
		return (errno);

	if ((fd = open(path, O_CREAT|O_RDWR, 0666)) == -1) {
		ret = errno;
		if (door_revoke(door_fd) != 0)
			err(EXIT_FAILURE, "failed to revoke door");
		return (ret);
	}

	if (fchown(fd, UID_KBMD, GID_KBMD) != 0) {
		ret = errno;
		if (door_revoke(door_fd) != 0)
			err(EXIT_FAILURE, "failed to revoke door");
		return (ret);
	}

	if (close(fd) != 0)
		err(EXIT_FAILURE, "failed to close door fd %d", fd);

	(void) fdetach(path);
	if (fattach(door_fd, path) != 0) {
		ret = errno;
		if (door_revoke(door_fd) != 0)
			err(EXIT_FAILURE, "failed to revoke door");
		return (ret);
	}

	return (0);
}
