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

#ifndef _ECUSTR_H
#define	_ECUSTR_H

#include <libcustr.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

struct errf;

void ecustr_init(void);
struct errf *ecustr_alloc(custr_t **);
struct errf *ecustr_append(custr_t *, const char *);
struct errf *ecustr_appendc(custr_t *, char);
struct errf *ecustr_append_printf(custr_t *, const char *, ...);
struct errf *ecustr_append_vprintf(custr_t *, const char *, va_list);
struct errf *ecustr_append_b64(custr_t *, const uint8_t *, size_t);
struct errf *ecustr_fromb64(custr_t *, uint8_t **, size_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ECUSTR_H */
