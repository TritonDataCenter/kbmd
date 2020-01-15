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

#ifndef _KBMADM_H
#define	_KBMADM_H

#include <inttypes.h>
#include <sys/debug.h>
#include "kbm.h"
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "kspawn.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Is a dataset name the pool name?
 */
#define	IS_ZPOOL(_name) (strchr(_name, '/') == NULL)

struct errf;
struct nvlist;
struct libzfs_handle;

extern struct libzfs_handle *g_zfs;

struct errf *req_new(kbm_cmd_t, struct nvlist **);
struct errf *assert_door(void);
struct errf *nv_door_call(int, struct nvlist *, struct nvlist **);
struct errf *check_error(struct nvlist *);
struct errf *assert_libzfs(void);
struct errf *send_request(struct nvlist * restrict, struct nvlist ** restrict);

struct errf *recover(const char *, uint32_t);
struct errf *show_configs(nvlist_t **, uint_t, boolean_t);

void mount_zpool(const char *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _KBMADM_H */
