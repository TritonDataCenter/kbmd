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
 * Copyright 2024 MNX Cloud, Inc.
 */

#include <sys/corectl.h>
#include <sys/list.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uuid.h>
#include <sys/wait.h>
#include <bunyan.h>
#include <door.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <paths.h>
#include <port.h>
#include <signal.h>
#include <smbios.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <synch.h>
#include <umem.h>
#include <unistd.h>
#include "kbmd.h"

/* sys_pool and sys_uuid are write-only -- once set, they're never changed */
char *sys_pool;
uuid_t sys_uuid;

SCARDCONTEXT piv_ctx;

mutex_t guid_lock = ERRORCHECKMUTEX;
uint8_t sys_guid[GUID_LEN];

const uint8_t zero_guid[GUID_LEN];

volatile boolean_t kbmd_quit = B_FALSE;

static int kbmd_daemonize(int);
static void kbmd_fd_setup(void);
static int kbmd_dir_setup(void);
static void kbmd_log_setup(int, bunyan_level_t);
static void kbmd_cleanup(int);
static int kbmd_sys_uuid(uuid_t);

int
main(int argc, char *argv[])
{
	const char *doorpath = KBMD_DOOR_PATH;
	int dirfd, dfd, errval, c;
	sigset_t set;
	struct sigaction act;
	boolean_t opt_d = B_FALSE;

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
		case 'd':
			opt_d = B_TRUE;
			break;
		}
	}

	alloc_init();
	kbmd_fd_setup();
	dirfd = kbmd_dir_setup();
	if (opt_d) {
		dfd = open(_PATH_DEVNULL, O_WRONLY);
		if (dfd == -1)
			err(EXIT_FAILURE, "/dev/null");
	} else {
		dfd = kbmd_daemonize(dirfd);
		/*
		 * Now in the child (non -d)
		 */
	}

	/*
	 * Initialize a sentinel errf_t to allow iterator callbacks to
	 * signal iteration should (non-fatally) stop iterating.
	 */
	foreach_stop = errf("StopIteration", NULL, "iteration stopped");
	VERIFY3P(foreach_stop, !=, ERRF_NOMEM);

	/*
	 * At this point, finish up signal intialization and finally go ahead,
	 * notify the parent that we're okay, and enter the sigsuspend loop.
	 */
	bzero(&act, sizeof (struct sigaction));
	act.sa_handler = kbmd_cleanup;
	if (sigfillset(&act.sa_mask) != 0)
		kbmd_dfatal(dfd, "failed to fill sigaction mask");
	act.sa_flags = 0;
	if (sigaction(SIGHUP, &act, NULL) != 0)
		kbmd_dfatal(dfd, "failed to register HUP handler");
	if (sigdelset(&set, SIGHUP) != 0)
		kbmd_dfatal(dfd, "failed to remove HUP from mask");
	if (sigaction(SIGQUIT, &act, NULL) != 0)
		kbmd_dfatal(dfd, "failed to register QUIT handler");
	if (sigdelset(&set, SIGQUIT) != 0)
		kbmd_dfatal(dfd, "failed to remove QUIT from mask");
	if (sigaction(SIGINT, &act, NULL) != 0)
		kbmd_dfatal(dfd, "failed to register INT handler");
	if (sigdelset(&set, SIGINT) != 0)
		kbmd_dfatal(dfd, "failed to remove INT from mask");
	if (sigaction(SIGTERM, &act, NULL) != 0)
		kbmd_dfatal(dfd, "failed to register TERM handler");
	if (sigdelset(&set, SIGTERM) != 0)
		kbmd_dfatal(dfd, "failed to remove TERM from mask");

#ifdef DEBUG
	kbmd_log_setup(dfd, BUNYAN_L_TRACE);
#else
	kbmd_log_setup(dfd, BUNYAN_L_DEBUG);
#endif

	(void) bunyan_debug(tlog, "Starting up", BUNYAN_T_END);

	if (getenv("KBMD_APDU_DEBUG") != NULL) {
		piv_full_apdu_debug = B_TRUE;

		(void) bunyan_warn(tlog,
		    "APDU debugging enabled, sensitive data may be logged!",
		    BUNYAN_T_END);
	}

	(void) kbmd_sys_uuid(sys_uuid);

	errval = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &piv_ctx);
	if (errval != 0) {
		kbmd_dfatal(dfd, "could not initialize libpcsc: %s",
		    pcsc_stringify_error(errval));
	}

	kbmd_event_init(dfd);
	kbmd_recover_init(dfd);
	load_plugin();

	(void) bunyan_trace(tlog, "Creating door server", BUNYAN_T_END);

	errval = kbmd_door_setup(doorpath);
	if (errval != 0)
		kbmd_dfatal(dfd, "unable to create door");

	errval = 0;
	(void) write(dfd, &errval, sizeof (errval));
	(void) close(dfd);

	for (;;) {
		if (sigsuspend(&set) == -1)
			if (errno == EFAULT)
				abort();
		if (kbmd_quit == B_TRUE)
			break;
	}

	(void) bunyan_info(tlog, "Exiting...", BUNYAN_T_END);

	kbmd_event_fini();
	return (0);
}

/*
 * We borrow fmd's daemonization style. Basically, the parent waits for the
 * child to successfully set up a door and recover all of the old configurations
 * before we say that we're good to go.
 */
static int
kbmd_daemonize(int dirfd)
{
	char path[PATH_MAX];
	struct rlimit rlim;
	sigset_t set, oset;
	int estatus, pfds[2];
	pid_t child;

	/*
	 * Set a per-process core path to be inside of /etc/svc/volatile/kbmd.
	 * Make sure that we aren't limited in our dump size.
	 */
	VERIFY3S(snprintf(path, sizeof (path),
	    "%s/core.%s.%%p", KBMD_RUNDIR, getprogname()), >, 0);
	(void) core_set_process_path(path, strlen(path) + 1, getpid());

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		warn("unable to set core file size to unlimited");

	/*
	 * Claim as many file descriptors as the system will let us.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
	}

	/*
	 * chdir /etc/svc/volatile/kbmd
	 */
	if (fchdir(dirfd) != 0)
		err(EXIT_FAILURE, "failed to chdir to %s", KBMD_RUNDIR);


	/*
	 * At this point block all signals going in so we don't have the parent
	 * mistakingly exit when the child is running, but never block SIGABRT.
	 */
	VERIFY0(sigfillset(&set));
	VERIFY0(sigdelset(&set, SIGABRT));
	VERIFY0(sigprocmask(SIG_BLOCK, &set, &oset));

	/*
	 * Do the fork+setsid dance.
	 */
	if (pipe(pfds) != 0)
		err(EXIT_FAILURE, "failed to create pipe for daemonizing");

	if ((child = fork()) == -1)
		err(EXIT_FAILURE, "failed to fork for daemonizing");

	if (child != 0) {
		/* We'll be exiting shortly, so allow for silent failure */
		(void) close(pfds[1]);
		if (read(pfds[0], &estatus, sizeof (estatus)) ==
		    sizeof (estatus))
			_exit(estatus);

		if (waitpid(child, &estatus, 0) == child && WIFEXITED(estatus))
			_exit(WEXITSTATUS(estatus));

		_exit(EXIT_FAILURE);
	}

	VERIFY0(setgroups(0, NULL));
	if (setgid(GID_KBMD) == -1 || seteuid(UID_KBMD) == -1)
		abort();

	VERIFY0(close(pfds[0]));
	if (setsid() == -1)
		abort();
	VERIFY0(sigprocmask(SIG_SETMASK, &oset, NULL));
	(void) umask(0022);

	return (pfds[1]);
}

static void
kbmd_fd_setup(void)
{
	int dupfd;

	closefrom(STDERR_FILENO + 1);
	if ((dupfd = open(_PATH_DEVNULL, O_RDONLY)) < 0)
		err(EXIT_FAILURE, "unable to open %s", _PATH_DEVNULL);
	if (dup2(dupfd, STDIN_FILENO) < 0)
		err(EXIT_FAILURE, "failed to dup out stdin");
}

static int
kbmd_dir_setup(void)
{
	int fd;

	if (mkdir(KBMD_RUNDIR, 0700) != 0) {
		if (errno != EEXIST)
			err(EXIT_FAILURE, "failed to create %s", KBMD_RUNDIR);
	}

	fd = open(KBMD_RUNDIR, O_RDONLY);
	if (fd < 0)
		err(EXIT_FAILURE, "failed to open %s", KBMD_RUNDIR);

	/*
	 * XXX: Once we can determine the necessary privileges for
	 * accessing pivtokens, we can have this all run as non-root.
	 */
	if (fchown(fd, UID_KBMD, GID_KBMD) != 0)
		err(EXIT_FAILURE, "failed to chown %s", KBMD_RUNDIR);

	if (fchmod(fd, 0700) != 0)
		err(EXIT_FAILURE, "failed to chmod %s", KBMD_RUNDIR);

	return (fd);
}

static void
kbmd_log_setup(int dfd, bunyan_level_t level)
{
	errf_t *ret;

	if ((ret = init_log(level)) == ERRF_OK) {
		tlog = blog;
		return;
	}

	kbmd_dfatal(dfd, "%s: %s in %s() at %s:%d",
	    errf_name(ret), errf_message(ret), errf_function(ret),
	    errf_file(ret), errf_line(ret));

	tlog = blog;
}

void
kbmd_dfatal(int dfd, const char *fmt, ...)
{
	int status = EXIT_FAILURE;
	va_list ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);

	/* Take a single shot at this */
	(void) write(dfd, &status, sizeof (status));
	exit(status);
}

static void
kbmd_cleanup(int arg __unused)
{
	kbmd_quit = B_TRUE;
}

static int
kbmd_sys_uuid(uuid_t uuid)
{
	smbios_hdl_t *shp;
	smbios_system_t s;
	int errval = 0;

	shp = smbios_open(NULL, SMB_VERSION, 0, &errval);
	if (shp == NULL) {
		(void) bunyan_warn(blog, "failed to load SMBIOS",
		    BUNYAN_T_STRING, "errmsg", smbios_errmsg(errval),
		    BUNYAN_T_END);
		return (-1);
	}

	if (smbios_info_system(shp, &s) == -1) {
		(void) bunyan_warn(blog, "failed to read SMBIOS uuid",
		    BUNYAN_T_END);
		return (-1);
	}

	if (s.smbs_uuidlen != sizeof (uuid_t)) {
		(void) bunyan_warn(blog, "SMBIOS uuid length mismatch",
		    BUNYAN_T_UINT32, "uuidlen", (uint32_t)s.smbs_uuidlen,
		    BUNYAN_T_UINT32, "expected_len", (uint32_t)sizeof (uuid_t),
		    BUNYAN_T_END);
		smbios_close(shp);
		return (-1);
	}

	bcopy(s.smbs_uuid, uuid, sizeof (uuid_t));
	smbios_close(shp);

	return (0);
}
