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

#ifndef _KSPAWN_H
#define	_KSPAWN_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct errf;
struct custr;

/*
 * A helpful builder for char *[] arrays such as an argv or environ
 */
typedef struct strarray {
	char **sar_strs;
	size_t sar_n;
	size_t sar_alloc;
} strarray_t;

#define	STRARRAY_INIT { 0 }

extern char **_environ;

struct errf *strarray_append(strarray_t *restrict, const char *restrict, ...);
struct errf *strarray_append_guid(strarray_t *restrict,
    const uint8_t [restrict]);
void strarray_fini(strarray_t *);

struct errf *spawn(const char *restrict, char *const[restrict],
    char *const[restrict], pid_t *restrict, int [restrict]);
struct errf *interact(pid_t, int [restrict], const void *, size_t,
    struct custr *[restrict], int *restrict, boolean_t);
struct errf *exitval(pid_t, int *);

#ifdef __cplusplus
}
#endif

#endif /* _KSPAWN_H */
