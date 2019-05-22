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

void
guidstr(const uint8_t *restrict guid, char *restrict str)
{
	static const char hexdigits[] = "0123456789ABCDEF";
	size_t i, j;

	for (i = j = 0; i < GUID_LEN; i++) {
		uint8_t v = guid[i];
		str[j++] = hexdigits[v >> 4];
		str[j++] = hexdigits[v & 0x0f];
	}
	str[j] = '\0';
}

errf_t *
ecalloc(size_t n, size_t sz, void *p)
{
	void **pp = p;

	if ((*pp = calloc(n, sz)) == NULL)
		return (errfno("calloc", NULL, ""));
	return (ERRF_OK);
}
