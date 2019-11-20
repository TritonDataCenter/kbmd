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
#include <thread.h>
#include <unistd.h>
#include <umem.h>
#include "kbmd.h"

#define	DOOR_RET_MAX 16384

struct retbuf {
	char		*rt_buf;
	size_t		rt_len;
	nv_alloc_t	rt_nvalloc;
};

static int door_fd = -1;

/*
 * We allocate a per-door server thread buffer used to hold the packed
 * nvlist. TSD is used so that we can attach a cleanup function if the
 * thread is terminated. Unfortunately, there is no other way after a
 * door_return(3C) call for the thread to clean up after itself. The
 * alternative would be to put the contents on the stack, but that seems
 * rife with peril if our responses get too large.
 */
static thread_key_t retkey = THR_ONCE_KEY;

/*
 * A packed nvlist suitable for use with door_return(3C).  Created during
 * kbmd startup (by kbmd_door_setup -- before we start the door server) as a
 * return value of last resort that should always be available to return.
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

static void __NORETURN
kbmd_ret_generr(errf_t *restrict errval, nvlist_t *restrict resp)
{

	/*
	 * If we end up here, things are pretty dire, but we'll try to log
	 * what info we can.
	 */
	if (errval != ERRF_OK) {
		(void) bunyan_error(tlog,
		    "Returning general error",
		    BUNYAN_T_STRING, "err_name", errf_name(errval),
		    BUNYAN_T_STRING, "err_msg", errf_message(errval),
		    BUNYAN_T_STRING, "err_func", errf_function(errval),
		    BUNYAN_T_STRING, "err_file", errf_file(errval),
		    BUNYAN_T_UINT32, "err_line", errf_line(errval),
		    BUNYAN_T_END);
	} else {
		(void) bunyan_error(tlog, "Returning general error",
		    BUNYAN_T_END);
	}

	session_log_end();
	errf_free(errval);
	nvlist_free(resp);
	VERIFY0(door_return(generr, generr_sz, NULL, 0));

	/* NOTREACHED */
	abort();
}

/*
 * Packs and returns the given nvlist to the door caller.  resp may be NULL
 * if there is no data to return to the caller.
 * Note: the nvlist is freed by kbmd_ret_nvlist, and the request log instance
 * is freed.
 */
static void __NORETURN
kbmd_ret_nvlist(nvlist_t *resp)
{
	errf_t *ret = ERRF_OK;
	struct retbuf *b = NULL;
	size_t nvlen;
	boolean_t success;

	/*
	 * Even if there is no data to return, we want to indicate
	 * success to the client.
	 */
	if (resp == NULL && (ret = envlist_alloc(&resp)) != ERRF_OK)
		kbmd_ret_generr(ret, resp);

	if ((ret = envlist_lookup_boolean_value(resp, KBM_NV_SUCCESS,
	    &success)) != ERRF_OK) {
		errf_free(ret);
		if ((ret = envlist_add_boolean_value(resp, KBM_NV_SUCCESS,
		    B_TRUE)) != ERRF_OK) {
			errf_free(ret);
			(void) bunyan_error(tlog,
			    "Failed to set success in response",
			    BUNYAN_T_END);
			kbmd_ret_generr(ret, resp);
		}
	}

#ifdef DEBUG
	flockfile(stderr);
	fprintf(stderr, "Response:\n");
	nvlist_print(stderr, resp);
	fputc('\n', stderr);
	funlockfile(stderr);
#endif

	VERIFY0(nvlist_size(resp, &nvlen, NV_ENCODE_NATIVE));
	if (nvlen > DOOR_RET_MAX) {
		(void) bunyan_error(tlog,
		    "Tried to return more than DOOR_RET_MAX",
		    BUNYAN_T_UINT64, "retsize", nvlen,
		    BUNYAN_T_END);
		kbmd_ret_generr(ret, resp);
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

	/*
	 * If a failure, kbmd_ret_error has already logged the failure,
	 * so we only want to log success here.
	 */
	if (success)
		(void) bunyan_debug(tlog, "Returning success", BUNYAN_T_END);

	nvlist_free(resp);
	session_log_end();
	VERIFY0(door_return(b->rt_buf, nvlen, NULL, 0));

	/* NOTREACHED */
	abort();
}

static void __NORETURN
kbmd_ret_error(errf_t *ef)
{
	nvlist_t *nvret = NULL;

	/*
	 * This can be slightly confusing, but ef is the error we're trying
	 * to return. However, it's possible (though hopefully unlikely) we'll
	 * encounter an error while trying to construct the error reply. Most
	 * likely this would be an out of memory condition. 'ret' reflects
	 * out ability to create the error response for 'ef'.
	 */
	errf_t *ret = ERRF_OK;

	if ((ret = envlist_alloc(&nvret)) != ERRF_OK ||
	    (ret = envlist_add_boolean_value(nvret, KBM_NV_SUCCESS,
	    B_FALSE)) != ERRF_OK ||
	    (ret = envlist_add_errf(nvret, KBM_NV_ERRMSG, ef)) != ERRF_OK)
		kbmd_ret_generr(ret, nvret);

	/*
	 * We can't easily log the whole error chain, so we just log the
	 * topmost one -- however the client gets the entire error chain.
	 */
	(void) bunyan_debug(tlog, "Returning error",
	    BUNYAN_T_STRING, "err_name", errf_name(ef),
	    BUNYAN_T_STRING, "err_msg", errf_message(ef),
	    BUNYAN_T_STRING, "err_func", errf_function(ef),
	    BUNYAN_T_STRING, "err_file", errf_file(ef),
	    BUNYAN_T_UINT32, "err_line", errf_line(ef),
	    BUNYAN_T_END);

	errf_free(ef);
	kbmd_ret_nvlist(nvret);
}

/*
 * Return function used by the various commands. If no errors are present,
 * we return sucess with the given response (which may be NULL if there is
 * no data to return to the client). If any errors are present, we ignore
 * the contents of resp and send back the error. The assumption is that
 * if resp is non-NULL it at best contains a partially constructed response
 * that failed somewhere mid-way through handling the request. That is in
 * the case of an error, we don't send any additional data beyond the
 * data in errval.
 *
 * In all cases, both errval and resp are freed prior to calling door_return.
 */
void __NORETURN
kbmd_return(errf_t *restrict errval, nvlist_t *restrict resp)
{
	if (errval != ERRF_OK) {
		nvlist_free(resp);
		kbmd_ret_error(errval);
	}

	kbmd_ret_nvlist(resp);
}

static void
kbmd_door_server(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc)
{
	door_cred_t dcred = { 0 };
	nvlist_t *req = NULL;
	errf_t *ret = ERRF_OK;
	int rc;

	rc = door_cred(&dcred);
	if (rc != 0) {
		(void) bunyan_error(blog,
		    "Unable to obtain caller credentials",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "errmsg", strerror(errno),
		    BUNYAN_T_END);
		VERIFY0(door_return(generr, generr_sz, NULL, 0));
	}

	session_log_start(&dcred);

	ret = envlist_unpack(argp, arg_size, &req);
	if (ret != ERRF_OK) {
		(void) bunyan_info(tlog, "Unable to unpack request",
		    BUNYAN_T_INT32, "errno", errf_errno(ret),
		    BUNYAN_T_STRING, "errmsg", errf_message(ret),
		    BUNYAN_T_END);
		errf_free(ret);
		VERIFY0(door_return(generr, generr_sz, NULL, 0));
	}

	dispatch_request(req, dcred.dc_pid);
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
