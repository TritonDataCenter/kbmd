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
#include <libnvpair.h>
#include <libzfs.h>
#include "kbm.h"
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "kspawn.h"
#include "pivy/errf.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Is a dataset name the pool name?
 */
#define	IS_ZPOOL(_name) (strchr(_name, '/') == NULL)

extern libzfs_handle_t *g_zfs;

errf_t *req_new(kbm_cmd_t, nvlist_t **);
errf_t *assert_door(void);
errf_t *nv_door_call(int, nvlist_t *, nvlist_t **);
errf_t *check_error(nvlist_t *);
errf_t *assert_libzfs(void);
errf_t *send_request(nvlist_t * restrict, nvlist_t ** restrict);

errf_t *recover(const char *, uint32_t);
errf_t *show_configs(nvlist_t **, uint_t, boolean_t);

void mount_zpool(const char *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _KBMADM_H */
