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

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/types.h>
#include <umem.h>
#include <unistd.h>
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "errf.h"

char panicstr[256];

/*
 * Debug builds are automatically wired up for umem debugging.
 */
#ifdef  DEBUG
const char *
_umem_debug_init(void)
{
	/*
	 * Per umem_debug(3MALLOC), "default" is equivalent to
	 * audit,contents,guards
	 */
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}
#else
const char *
_umem_debug_init(void)
{
	return ("guards");
}
#endif  /* DEBUG */

static __NORETURN int
nomem(void)
{
	panic("out of memory");
}

void __NORETURN
panic(const char *msg, ...)
{
	int n;
	va_list ap;

	va_start(ap, msg);
	n = vsnprintf(panicstr, sizeof (panicstr), msg, ap);
	va_end(ap);

	(void) write(STDERR_FILENO, "PANIC: ", 7);
	(void) write(STDERR_FILENO, panicstr, n);
	if (n > 0 && panicstr[n - 1] != '\n')
		(void) write(STDERR_FILENO, "\n", 1);
	(void) fsync(STDERR_FILENO);
	abort();
}

void
alloc_init(void)
{
	ecustr_init();
	envlist_init();
	umem_nofail_callback(nomem);
}
