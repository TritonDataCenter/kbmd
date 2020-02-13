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

#ifndef _COMMON_H
#define	_COMMON_H

#include <bunyan.h>
#include <synch.h>

#include "pivy/piv.h" /* for GUID_LEN */

#ifdef __cplusplus
extern "C" {
#endif

#define	GUID_STR_LEN (GUID_LEN * 2 + 1)

extern bunyan_logger_t *blog;
extern __thread bunyan_logger_t *tlog;

struct errf *init_log(bunyan_level_t);

void panic(const char *, ...) __NORETURN;
void alloc_init(void);
void tohex(const uint8_t *restrict, size_t, char *restrict, size_t);
void guidtohex(const uint8_t *restrict, char *restrict, size_t);

struct errf *ecalloc(size_t, size_t, void *);

static inline struct errf *
zalloc(size_t sz, void *p)
{
	return (ecalloc(1, sz, p));
}


struct errf *eparse_ulong(const char *, ulong_t *);

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_H */
