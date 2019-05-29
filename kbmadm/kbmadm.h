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

#ifndef _KBMADM_H
#define	_KBMADM_H

#include "../common/kbm.h"

#ifdef __cplusplus
extern "C" {
#endif

struct errf;
struct nvlist;

struct errf *req_new(kbm_cmd_t, struct nvlist **);
struct errf *open_door(int *);
struct errf *nv_door_call(int, struct nvlist *, struct nvlist **);
struct errf *check_error(struct nvlist *);

#ifdef __cplusplus
}
#endif

#endif /* _KBMADM_H */
