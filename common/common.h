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

#ifndef _COMMON_H
#define	_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef GUID_LEN
#define	GUID_LEN 16
#endif

#define	GUID_STR_LEN (GUID_LEN * 2 + 1)

void panic(const char *, ...) __NORETURN;
void alloc_init(void);
void guidstr(const uint8_t *restrict, char *restrict);

struct errf *ecalloc(size_t, size_t, void *);
static inline struct errf *
zalloc(size_t sz, void *p)
{
	return (ecalloc(1, sz, p));
}

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_H */
