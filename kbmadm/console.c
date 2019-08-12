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
 * Copyright 2019 Joyent, Inc.
 */

#include <bunyan.h>
#include <errno.h>
#include <libcustr.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmsg_impl.h>
#include <sys/vt.h>
#include <sys/kd.h>
#include "common.h"

#define	DEFAULT_CONSOLE "/dev/console"

/*
 * These come from the 'sane' table entres from
 * usr/src/cmd/ttymon/sttytable.c
 */
#define	IFLAG_SET	(BRKINT|IGNPAR|ISTRIP|ICRNL|ISON|IMAXBEL)
#define	IFLAG_CLEAR	(IGNBRK|PARMRK|INPCK|INLCR|IUCLC|IXOFF|IXANY)
#define	LFLAG_SET	(ISIG|ICANON|IEXTEN|ECHO|ECHOK|ECHOE|ECHOKE|ECHOCTL)
#define	LFLAG_CLEAR	(XCASE|ECHONL|NOFLSH|STFLUSH|STWRAP|STAPPL)
#define	OFLAG_SET	(OPOST|ONLCR)
#define	OFLAG_CLEAR	(OLUCU|OCRNL|ONOCR|ONLRET|OFILL|OFDEL|NLDLY|CRDLY| \
    TABDLY|BSDLY|VTDLY|FFDLY)

static void
tty_sane(int fd)
{
	struct termio tinfo = { 0 };

	if (ioctl(fd, TCGETA, &tinfo) < 0) {
		return;
	}

	tinfo.c_iflag &= ~IFLAG_CLEAR;
	tinfo.c_iflag |= IFLAG_SET;

	tinfo.c_lflag &= ~LFLAG_CLEAR;
	tinfo.c_lflag |= LFLAG_SET;

	tinfo.c_oflag &= ~OFLAG_CLEAR;
	tinfo.c_oflag |= OFLAG_SET;

	tinfo.c_cc[VERASE] = CERASE;
	tinfo.c_cc[VKILL] = CKILL;
	tinfo.c_cc[VQUIT] = CQUIT;
	tinfo.c_cc[VINTR] = CINTR;
	tinfo.c_cc[VEOF] = CEOF;
	tinfo.c_cc[VEOL] = CNUL;

	(void) ioctl(fd, TCSETAF, &tinfo);
}

/*
 * Stops the progress bar and resets the console mode to text.
 * This is best effort, so we ignore errors.
 */
static void
set_textmode(void)
{
	int fd = -1;

	if ((fd = open("/dev/fb", O_RDONLY)) < 0) {
		return;
	}

	(void) ioctl(fd, KDSETMODE, KD_RESETTEXT);
	(void) close(fd);
}

static errf_t *
find_console(char *consoles, dev_t cdev, custr_t *cstr)
{
	errf_t *ret = ERRF_OK;
	char *s = consoles;
	char *p = NULL;

	/* large enough for 0x<long hex> */
	char devbuf[20] = { 0 };
	(void) snprintf(devbuf, sizeof (devbuf), "0x%lx", cdev);

	(void) bunyan_trace(tlog, "find_console: enter",
	    BUNYAN_T_STRING, "consoles", consoles,
	    BUNYAN_T_STRING, "dev", devbuf,
	    BUNYAN_T_END);

	custr_reset(cstr);

	for (p = strsep(&s, " "); p != NULL; p = strsep(&s, " ")) {
		struct stat sb = { 0 };

		(void) bunyan_debug(tlog, "Trying console",
		    BUNYAN_T_STRING, "console", p,
		    BUNYAN_T_END);

		if (stat(p, &sb) < 0) {
			return (errfno("stat", errno, "stat(%s) failed", p));
		}

		if (st.st_rdev == cdev) {
			(void) bunyan_debug(tlog, "Found console",
			    BUNYAN_T_STRING, "console", p,
			    BUNYAN_T_STRING, "dev", devbuf,
			    BUNYAN_T_END);

			return (ecustr_append(cstr, p));
		}
	}

	return (ERRF_OK);
}

errf_t *
get_console(custr_t **cusp)
{
	errf_t *ret = ERRF_OK;
	custr_t *cus = NULL;
	char *consolestr = NULL;
	dev_t cttyd = NODEV;
	int fd = -1;
       	int bufsize = 0;

	*cusp = NULL;

	if ((ret = ecustr_alloc(&cus)) != ERRF_OK) {
		goto done;
	}

	if ((fd = open(SYSMSG, 0)) < 0) {
		ret = errfno("open", errno, "could not open %s", SYSMSG);
		goto done;
	}

	/*
	 * sulogin.c obscures this a bit, but if the CIOCTTYCONSOLE fails,
	 * the only choice is to use DEFAULT_CONSOLE as the console.
	 */
	if (ioctl(fd, CIOCTTYCONSOLE, &cttyd) != 0) {
		(void) bunyan_debug(tlog,
		    "CIOCTTYCONSOLE ioctl failed, using default console",
		    BUNYAN_T_END);

		ret = ecustr_append(cus, DEFAULT_CONSOLE);
		goto done;
	}

	if ((bufsize = ioctl(fd, CIOCGETCONSOLE, NULL)) < 0) {
		ret = errfno("ioctl", errno,
		    "CIOCGETCONSOLE ioctl on %s failed", SYSMSG);
		goto done;
	}

	if (bufsize == 0) {
		ret = ecustr_append(cus, DEFAULT_CONSOLE);
		goto done;
	}

	/*
	 * If this triggers, something is very wrong with our kernel.
	 */
	VERIFY3S(bufsize, <, INT_MAX);

	if ((ret = zalloc(++bufsize, &consolestr)) != ERRF_OK) {
		goto done;
	}

	if (ioctl(fd, CIOCGETCONSOLE, consolestr) < 0) {
		ret = errfno("ioctl", errno,
		    "CIOCGETCONSOLE ioctl on %s failed", SYSMSG);
		goto done;
	}

	VERIFY3U(strlcat(consolestr, " ", bufsize), <=, (size_t)bufsize);
	VERIFY3U(strlcat(consolestr, DEFAULT_CONSOLE, bufsize), <=,
	    (size_t)bufsize);

	if ((ret = find_console(consolestr, cttyd, cus)) != ERRF_OK) {
		goto done;
	}

	if (custr_len(cus) == 0) {
		ret = ecustr_append(cus, DEFAULT_CONSOLE);
	}

done:
	free(consolestr);

	if (fd >= 0) {
		(void) close(fd);
	}

	if (ret == ERRF_OK) {
		*cusp = cus;
	} else {
		custr_free(cus);
	}

	return (ret);
}
