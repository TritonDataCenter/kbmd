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

#include <errno.h>
#include <fcntl.h>
#include <bunyan.h>
#include <libcustr.h>
#include <poll.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "pivy/errf.h"
#include "common.h"
#include "ecustr.h"
#include "kspawn.h"

/*
 * This is shared between kbmd and kbmadm, including piv.h would bring
 * in too many things, so we redefine the GUID length here.
 */
#define	GUID_LEN 16

#define	CHUNK 16

static errf_t *
strarray_cklen(strarray_t *sar)
{
	if (sar->sar_n + 2 < sar->sar_alloc)
		return (ERRF_OK);

	char **new;
	size_t newlen = sar->sar_alloc + CHUNK;

	new = recallocarray(sar->sar_strs, sar->sar_alloc, newlen,
	    sizeof (char *));
	if (new == NULL)
		return (errfno("recallocarray", errno, ""));

	sar->sar_strs = new;
	sar->sar_alloc = newlen;
	return (ERRF_OK);
}

errf_t *
strarray_append(strarray_t *restrict sar, const char *restrict fmt, ...)
{
	errf_t *ret;
	char *s = NULL;
	va_list ap;
	int n;

	if ((ret = strarray_cklen(sar)) != ERRF_OK)
		return (ret);

	va_start(ap, fmt);
	n = vasprintf(&s, fmt, ap);
	va_end(ap);

	if (n == -1)
		return (errfno("vasprintf", errno, ""));

	sar->sar_strs[sar->sar_n++] = s;
	sar->sar_strs[sar->sar_n] = NULL;

	return (ERRF_OK);
}

errf_t *
strarray_append_guid(strarray_t *restrict sar, const uint8_t guid[restrict])
{
	char str[GUID_LEN * 2 + 1] = { 0 };

	guidtohex(guid, str, sizeof (str));
	return (strarray_append(sar, "%s", str));
}

void
strarray_fini(strarray_t *sar)
{
	if (sar == NULL)
		return;

	if (sar->sar_strs == NULL) {
		ASSERT3U(sar->sar_n, ==, 0);
		return;
	}

	for (size_t i = 0; i < sar->sar_n; i++) {
		size_t len = strlen(sar->sar_strs[i]);
		freezero(sar->sar_strs[i], len);
		sar->sar_strs[i] = NULL;
	}

	free(sar->sar_strs);
	sar->sar_n = sar->sar_alloc = 0;
}

/*
 * Wrap a few functions with errf_t's
 */

static errf_t *
epipe(int fds[2])
{
	if (pipe(fds) == 0)
		return (ERRF_OK);
	return (errfno("pipe", errno, ""));
}

static errf_t *
kspawn_attr_init(posix_spawnattr_t *attrp)
{
	int rc;

	if ((rc = posix_spawnattr_init(attrp)) == 0)
		return (ERRF_OK);
	return (errfno("posix_spawnattr_init", rc, ""));
}

static errf_t *
kspawn_fact_init(posix_spawn_file_actions_t *fp)
{
	int rc;

	if ((rc = posix_spawn_file_actions_init(fp)) == 0)
		return (ERRF_OK);
	return (errfno("posix_spawn_file_actions_init", rc, ""));
}

static errf_t *
kspawn_fact_dup2(posix_spawn_file_actions_t *fp, int fd1, int fd2)
{
	int rc;

	if ((rc = posix_spawn_file_actions_adddup2(fp, fd1, fd2)) == 0)
		return (ERRF_OK);
	return (errfno("posix_spawn_file_actions_adddup2", rc, ""));
}

static errf_t *
kspawn_fact_closefrom(posix_spawn_file_actions_t *fp, int fd)
{
	int rc;

	if ((rc = posix_spawn_file_actions_addclosefrom_np(fp, fd)) == 0)
		return (ERRF_OK);
	return (errfno("posix_spawn_file_actions_addclosefrom_np", rc, ""));
}

static errf_t *
kspawnp(pid_t *restrict pidp, const char *restrict path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *restrict attrp,
    char *const argv[restrict], char *const envp[restrict])
{
	int rc;

	if ((rc = posix_spawnp(pidp, path, file_actions, attrp, argv,
	    envp)) == 0)
		return (ERRF_OK);
	return (errfno("posix_spawnp", rc, "error running %s", path));
}

/*
 * Run the given command with the given arguments and environment.
 * pidp is a pointer that is set to the pid of the spawned command on success
 * fds are the stdin, stdout, and stderr file descriptors.  They should either
 * be initialized with -1 or the fd that will be dup2(3C)'ed to the
 * corresponding standard fd (e.g. fd = { 42, -1, 6 } will cause the equivalent
 * of:
 *	dup2(42, 0);
 *	dup2(6, 2);
 * to occur in the spawned process.  Any fd values of -1 will be replaced
 * with the fd of a pipe suitable for interaction with the spawned process.
 * In the above example, stdin and stderr in the child process will be
 * set to use the given fds, while stdout will be connected to a pipe and
 * the fd of the other side of the pipe will be placed in fds[1] and can
 * be used to read from the spawned process.
 *
 * If the process is successfully spawned, 0 is returned, otherwise an
 * error is returned.
 */
errf_t *
spawn(const char *restrict cmd, char *const argv[restrict],
    char *const env[restrict], pid_t *restrict pidp, int fds[restrict])
{
	errf_t *ret = ERRF_OK;
	custr_t *cmdline = NULL;
	posix_spawn_file_actions_t fact = { 0 };
	posix_spawnattr_t attr = { 0 };
	pid_t pid;
	int pipe_fds[3][2] = { { -1, -1 }, { -1, -1 }, { -1, -1 } };

	*pidp = (pid_t)-1;

	if ((ret = ecustr_alloc(&cmdline)) != ERRF_OK) {
		return (ret);
	}

	/*
	 * This is for diagnostic purposes, so we're not bothering with
	 * correctly escaping the cmdline since we already have the
	 * values in an acceptable format for posix_spawn()
	 */

	for (size_t i = 0; argv[i] != NULL; i++) {
		if (i > 0 && (ret = ecustr_appendc(cmdline, ' ')) != ERRF_OK) {
			custr_free(cmdline);
			return (ret);
		}

		if ((ret = ecustr_append(cmdline, argv[i])) != ERRF_OK) {
			custr_free(cmdline);
			return (ret);
		}
	}

	if ((ret = kspawn_attr_init(&attr)) != ERRF_OK) {
		custr_free(cmdline);
		return (ret);
	}

	if ((ret = kspawn_fact_init(&fact)) != ERRF_OK) {
		custr_free(cmdline);
		VERIFY0(posix_spawnattr_destroy(&attr));
		return (ret);
	}

	/* This can only fail due to programming error */
	VERIFY0(posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_NOSIGCHLD_NP | POSIX_SPAWN_WAITPID_NP));

	for (size_t i = 0; i < 3; i++) {
		if (fds[i] == i)
			continue;

		if (fds[i] >= 0) {
			if ((ret = kspawn_fact_dup2(&fact, fds[i],
			    i)) != ERRF_OK) {
				goto fail;
			}
			continue;
		}

		if ((ret = epipe(pipe_fds[i])) != ERRF_OK ||
		    (ret = kspawn_fact_dup2(&fact, pipe_fds[i][1],
		    i)) != ERRF_OK)
			goto fail;
	}

	if ((ret = kspawn_fact_closefrom(&fact,
	    STDERR_FILENO + 1)) != ERRF_OK)
		goto fail;

	if ((ret = kspawnp(&pid, cmd, &fact, &attr, argv, env)) != ERRF_OK)
		goto fail;

	(void) bunyan_debug(tlog, "Spawned process",
	    BUNYAN_T_STRING, "command", cmd,
	    BUNYAN_T_STRING, "cmdline", custr_cstr(cmdline),
	    BUNYAN_T_INT32, "pid", (int32_t)pid,
	    BUNYAN_T_END);

	VERIFY0(posix_spawn_file_actions_destroy(&fact));
	VERIFY0(posix_spawnattr_destroy(&attr));

	for (size_t i = 0; i < 3; i++) {
		if (pipe_fds[i][1] < 0) {
			VERIFY3S(fds[i], >=, 0);
			continue;
		}

		(void) close(pipe_fds[i][1]);
		fds[i] = pipe_fds[i][0];
	}

	*pidp = pid;
	return (ret);

fail:
	for (size_t i = 0; i < 3; i++) {
		if (pipe_fds[i][0] >= 0)
			(void) close(pipe_fds[i][0]);
		if (pipe_fds[i][1] >= 0)
			(void) close(pipe_fds[i][1]);
	}

	VERIFY0(posix_spawn_file_actions_destroy(&fact));
	VERIFY0(posix_spawnattr_destroy(&attr));
	custr_free(cmdline);
	return (ret);
}

errf_t *
exitval(pid_t pid, int *valp)
{
	int status;

	for (;;) {
		pid_t ret = waitpid(pid, &status, 0);

		if (ret == pid) {
			*valp = WEXITSTATUS(status);

			(void) bunyan_debug(tlog, "Process exited",
			    BUNYAN_T_INT32, "pid", (int32_t)pid,
			    BUNYAN_T_INT32, "exitval", (int32_t)*valp,
			    BUNYAN_T_END);

			return (ERRF_OK);
		}

		if (ret != (pid_t)-1)
			panic("Unexpected waitpid() return value: %s", ret);

		if (errno == EINTR)
			continue;

		return (errfno("waitpid", errno, ""));
	}

	/*NOTREACHED*/
	return (ERRF_OK);
}

#define	READBUF_SZ 256
static errf_t *
read_fd(int fd, custr_t *restrict cu, size_t *restrict np, boolean_t esc_nl)
{
	errf_t *ret = ERRF_OK;
	char buf[READBUF_SZ] = { 0 };
	ssize_t n;

	n = read(fd, buf, sizeof (buf) - 1);

	if (n == -1) {
		ret = errfno("read", errno, "");
		explicit_bzero(buf, sizeof (buf));
		return (errf("ReadError", ret, ""));
	}

	for (size_t i = 0; i < n; i++) {
		char c = buf[i];

		if (c == '\n' && esc_nl) {
			ret = ecustr_append(cu, "\\n");
		} else {
			ret = ecustr_appendc(cu, c);
		}

		if (ret != ERRF_OK) {
			ret = errf("ReadError", ret, "");
			break;
		}
	}

	explicit_bzero(buf, sizeof (buf));
	*np = (ret == ERRF_OK) ? n : 0;
	return (ret);
}

static errf_t *
write_fd(int fd, const void *data, size_t datalen, size_t offset,
    size_t *restrict np)
{
	const uint8_t *p = data;
	ssize_t n;

	if (offset >= datalen) {
		*np = 0;
		return (ERRF_OK);
	}

	n = write(fd, p + offset, datalen - offset);
	if (n < 0) {
		int errsave = errno;
		return (errf("WriteError", errfno("write", errsave, ""), ""));
	}

	*np = n;
	return (ERRF_OK);
}

errf_t *
interact(pid_t pid, int fds[restrict], const void *input, size_t inputlen,
    custr_t *output[restrict], int *restrict exitvalp, boolean_t esc_stderr)
{
	bunyan_logger_t *ilog = NULL;
	struct pollfd pfds[3]= { 0 };
	nfds_t nfds = 3;
	size_t written = 0;
	int rc = 0;

	if (input != NULL) {
		pfds[0].fd = fds[0];
		pfds[0].events = POLLOUT;
	} else {
		pfds[0].fd = -1;
	}

	for (size_t i = 1; i < 3; i++) {
		if (output[i - 1] != NULL) {
			pfds[i].fd = fds[i];
			pfds[i].events = POLLIN;
		} else {
			pfds[i].fd = -1;
		}
	}

	if (bunyan_child(tlog, &ilog,
	    BUNYAN_T_INT32, "pid", (int32_t)pid, BUNYAN_T_END) != 0) {
		return (errfno("bunyan_child", errno,
		    "creating interact() logger"));
	}

	(void) bunyan_trace(ilog, "Interacting with process", BUNYAN_T_END);

	while (pfds[0].fd >= 0 || pfds[1].fd >= 0 || pfds[2].fd >= 0) {
		errf_t *ret = ERRF_OK;
		size_t n;

		rc = poll(pfds, nfds, -1);
		if (rc < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;

			return (errf("IOError", errfno("poll", errno, ""), ""));
		}

		if (rc == 0)
			continue;

		/*
		 * Since newer standards allow read(2) and write(2) to
		 * return 0 outside of an EOF condition (even with non-blocking
		 * fds), we always use the POLLHUP event instead. Note:
		 * per poll(2), POLLHUP is always set in revents, regardless
		 * if we requested it when calling poll(2).
		 */

		if (pfds[0].revents & POLLHUP) {
			(void) bunyan_trace(ilog, "Output descriptor closed",
			    BUNYAN_T_INT32, "fd", pfds[0].fd,
			    BUNYAN_T_END);

			(void) close(pfds[0].fd);
			pfds[0].fd = -1;
			pfds[0].events = 0;
			pfds[0].revents = 0;
			fds[0] = -1;
		}

		if (pfds[0].revents & POLLOUT) {
			ret = write_fd(pfds[0].fd, input, inputlen,
			    written, &n);
			written += n;

			if (written == inputlen || ret != ERRF_OK) {
				if (ret == ERRF_OK) {
					(void) bunyan_trace(ilog,
					    "finished writing output",
					    BUNYAN_T_INT32, "fd", pfds[0].fd,
					    BUNYAN_T_END);
				}

				(void) close(pfds[0].fd);
				pfds[0].fd = -1;
				pfds[0].events = 0;
				pfds[0].revents = 0;
				fds[0] = -1;
				if (ret != ERRF_OK)
					return (errf("IOError", ret, ""));
			}

			(void) bunyan_trace(ilog, "wrote data",
			    BUNYAN_T_INT32, "fd", pfds[0].fd,
			    BUNYAN_T_UINT64, "amt_written", (uint64_t)n,
			    BUNYAN_T_END);
		}

		for (size_t i = 1; i < 3; i++) {
			if (!(pfds[i].revents & (POLLIN|POLLHUP))) {
				continue;
			}

			boolean_t esc_nl = B_FALSE;

			if (i == STDERR_FILENO && esc_stderr) {
				esc_nl = B_TRUE;
			}

			if ((ret = read_fd(pfds[i].fd, output[i - 1], &n,
			    esc_nl)) != ERRF_OK) {
				return (errf("IOError", ret, ""));
			}

			(void) bunyan_trace(ilog, "read data",
			    BUNYAN_T_INT32, "fd", pfds[i].fd,
			    BUNYAN_T_UINT64, "amt_read", (uint64_t)n,
			    BUNYAN_T_END);

			/*
			 * poll(2) states that while POLLOUT and POLLHUP
			 * will never be set at the same time in revents
			 * (they are mutually exclusive), it is possible
			 * that POLLHUP and POLLIN could both be set in
			 * revents. Therefore, we always process any pending
			 * reads, then close the fd if required.
			 */
			if (pfds[i].revents & POLLHUP) {
				(void) bunyan_trace(ilog,
				    "finished reading data on fd",
				    BUNYAN_T_INT32, "fd", pfds[i].fd,
				    BUNYAN_T_END);

				(void) close(pfds[i].fd);
				pfds[i].fd = -1;
				pfds[i].events = 0;
				pfds[i].revents = 0;
				fds[i] = -1;
			}
		}
	}

	bunyan_fini(ilog);

	return (exitval(pid, exitvalp));
}

/*
 * If any fds are left open by spawn, close them
 */
void
close_fds(int fds[3])
{
	for (size_t i = 0; i < 3; i++) {
		if (fds[i] == -1)
			continue;
		VERIFY0(close(fds[i]));
	}
}
