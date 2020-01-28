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
#include <door.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <stropts.h>
#include <thread.h>
#include <unistd.h>
#include <umem.h>
#include <sys/sysmacros.h>
#include "kbmd.h"

/*
 * Arbitrary limit on the amount of data (as a packed nvlist) we expect to
 * return for any given request.  Used to size tdata_t->td_buf
 */
static size_t door_ret_max = 16384;

/*
 * Per-door thread data
 */
typedef struct tdata {
	ucred_t		*td_ucred;
	int		td_errfd;
	char		td_tty[_POSIX_PATH_MAX];
	bunyan_logger_t *td_log;
	size_t		td_buflen;
	char		td_buf[];
} tdata_t;

static int door_fd = -1;
static thread_key_t tdatakey = THR_ONCE_KEY;

/*
 * A packed nvlist suitable for use with door_return(3C).  Created during
 * kbmd startup (by kbmd_door_setup -- before we start the door server) as a
 * return value of last resort that should always be available to return.
 * Once created during setup, it is never altered and is treated as constant
 * data (i.e. no locking required to use either value).
 */
static char *generr;
static size_t generr_sz;

static boolean_t
tdata_init(tdata_t *td, door_desc_t *dp, uint_t n_desc)
{
	static const char *rem_keys[] = {
		"req_pid", "req_uid", "req_tty", "user",
	};

	struct passwd *pw = NULL;
	ucred_t *uc = NULL;

	bzero(td->td_buf, td->td_buflen);
	bzero(td->td_tty, sizeof (td->td_tty));
	td->td_errfd = -1;

	for (size_t i = 0; i < ARRAY_SIZE(rem_keys); i++) {
		(void) bunyan_key_remove(tlog, rem_keys[i]);
	}

	/*
	 * We're not anticipating the kernel calling us. If that changes,
	 * we should alter this check.
	 */
	if (door_ucred(&td->td_ucred) != 0) {
		(void) bunyan_error(tlog,
		    "Unable to obtain caller credentials",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "errmsg", strerror(errno),
		    BUNYAN_T_END);
		return (B_FALSE);
	}
	uc = td->td_ucred;

	pw = getpwuid(ucred_getruid(uc));
	if (pw != NULL) {
		if (bunyan_key_add(tlog,
		    BUNYAN_T_STRING, "user", pw->pw_name,
		    BUNYAN_T_END) != 0)
			return (B_FALSE);
	}

	/*
	 * We rely on bunyan overwriting an existing key with a new
	 * value for this.
	 */
	if (bunyan_key_add(tlog,
	    BUNYAN_T_UINT32, "req_pid", (uint32_t)ucred_getpid(uc),
	    BUNYAN_T_UINT32, "req_uid", (uint32_t)ucred_getruid(uc),
	    BUNYAN_T_END) != 0) {
		return (B_FALSE);
	}

	if (n_desc > 1) {
		pid_t pid = ucred_getpid(td->td_ucred);
		uid_t uid = ucred_getruid(td->td_ucred);

		(void) bunyan_error(tlog,
		    "Unexpected number of descrptors passed",
		    BUNYAN_T_UINT32, "n_desc", n_desc,
		    BUNYAN_T_UINT32, "req_pid", (uint32_t)pid,
		    BUNYAN_T_UINT32, "req_uid", (uint32_t)uid,
		    BUNYAN_T_END);

		return (B_FALSE);
	}

	if (n_desc == 0) {
		(void) strlcpy(td->td_tty, "<none>", sizeof (td->td_tty));
	} else {
		int rc;

		if ((dp->d_attributes & DOOR_DESCRIPTOR) == 0) {
			(void) bunyan_error(tlog,
			    "Passed unknown attribute in door_desc_t",
			    BUNYAN_T_INT32, "attr", dp->d_attributes,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		td->td_errfd = dp->d_data.d_desc.d_descriptor;
		rc = ttyname_r(td->td_errfd, td->td_tty, sizeof (td->td_tty));
		if (rc == 0) {
			(void) strlcpy(td->td_tty, "<none>",
			    sizeof (td->td_tty));
		}
	}

	if (bunyan_key_add(tlog,
	    BUNYAN_T_STRING, "req_tty", td->td_tty,
	    BUNYAN_T_END) != 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static tdata_t *
tdata_alloc(size_t buflen)
{
	tdata_t *td = NULL;
	size_t tdlen = sizeof (*td) + buflen;

	if ((td = umem_zalloc(tdlen, UMEM_DEFAULT)) == NULL)
		return (NULL);

	if (bunyan_child(blog, &td->td_log, BUNYAN_T_END) != 0) {
		umem_free(td, tdlen);
		return (NULL);
	}
	tlog = td->td_log;

	td->td_buflen = buflen;
	td->td_errfd = -1;
	return (td);
}

static void
tdata_free(void *p)
{
	if (p == NULL)
		return;

	tdata_t *td = p;
	size_t tdlen = 0;

	bunyan_fini(td->td_log);
	tlog = NULL;

	ucred_free(td->td_ucred);

	tdlen = sizeof (*td) + td->td_buflen;
	bzero(td, tdlen);
	umem_free(td, tdlen);
}

static tdata_t *
tdata_get(void)
{
	tdata_t *td = NULL;

	VERIFY0(thr_keycreate_once(&tdatakey, tdata_free));
	VERIFY0(thr_getspecific(tdatakey, (void **)&td));

	if (td != NULL)
		return (td);

	/*
	 * TODO: Eventually we should make the kbmd door have a private
	 * preallocated thread pool, with each thread's tdata being
	 * a required part of the thread creation.
	 */
	td = tdata_alloc(door_ret_max);
	VERIFY3P(td, !=, NULL);

	VERIFY0(thr_setspecific(tdatakey, td));
	return (td);
}

uid_t
req_uid(void)
{
	tdata_t *td = tdata_get();

	return (ucred_getruid(td->td_ucred));
}

pid_t
req_pid(void)
{
	tdata_t *td = tdata_get();

	return (ucred_getpid(td->td_ucred));
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
	tdata_t *td = tdata_get();
	char *buf = td->td_buf;
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
			(void) bunyan_error(tlog,
			    "Failed to set success in response",
			    BUNYAN_T_END);
			kbmd_ret_generr(ret, resp);
		}
	}

	VERIFY0(nvlist_size(resp, &nvlen, NV_ENCODE_NATIVE));
	if (nvlen > td->td_buflen) {
		(void) bunyan_error(tlog,
		    "Tried to return more data than allowed",
		    BUNYAN_T_UINT64, "retsize", nvlen,
		    BUNYAN_T_UINT64, "allowed", td->td_buflen,
		    BUNYAN_T_END);
		kbmd_ret_generr(ret, resp);
	}

	/* The nvlist_size() check above should guarantee this doesn't fail */
	VERIFY0(nvlist_pack(resp, &buf, &td->td_buflen, NV_ENCODE_NATIVE, 0));

	/*
	 * If a failure, kbmd_ret_error has already logged the failure,
	 * so we only want to log success here.
	 */
	if (success)
		(void) bunyan_debug(tlog, "Returning success", BUNYAN_T_END);

	nvlist_free(resp);
	VERIFY0(door_return(td->td_buf, nvlen, NULL, 0));

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
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL;
	tdata_t *td = tdata_get();

	/*
	 * If we make the kbmd door server use a private thread pool,
	 * each thread should gets its own preallocated tdata_t and
	 * we can remove this check.
	 *
	 * If these fail, we can't assume we have a bunyan logger to use.
	 * The best we can do is write out to stderr and hope the message
	 * gets captured in the service log for the operator.
	 */
	if (td == NULL) {
		(void) fprintf(stderr,
		    "%s: %d: Failed to get server thread data\n",
		    __func__, __LINE__);
		VERIFY0(door_return(generr, generr_sz, NULL, 0));
	}

	if (!tdata_init(td, dp, n_desc)) {
		(void) fprintf(stderr,
		    "%s: %d: Failed to init server thread data\n",
		    __func__, __LINE__);
		VERIFY0(door_return(generr, generr_sz, NULL, 0));
	}

	ret = envlist_unpack(argp, arg_size, &req);
	if (ret != ERRF_OK) {
		(void) bunyan_info(tlog, "Unable to unpack request",
		    BUNYAN_T_INT32, "errno", errf_errno(ret),
		    BUNYAN_T_STRING, "errmsg", errf_message(ret),
		    BUNYAN_T_END);
		errf_free(ret);
		VERIFY0(door_return(generr, generr_sz, NULL, 0));
	}

	dispatch_request(req);
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

	if ((fd = open(path, O_CREAT|O_RDWR, 0600)) == -1) {
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
