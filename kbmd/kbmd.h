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

#ifndef _KBMD_H
#define	_KBMD_H

#include <errno.h>
#include <inttypes.h>
#include <thread.h>
#include <synch.h>
#include <sys/uuid.h>
#include <wintypes.h>
#include <winscard.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * XXX: Once we have a better idea of the permissions needed for the ccid
 * driver, we can perhaps set these to something other than root.
 */
#define	UID_KBMD	0
#define	GID_KBMD	0

#define	BOX_PROP	"rfd77:config"

struct custr;
struct ebox;
struct errf;
struct nvlist;
struct piv_token;
struct zfs_handle;

extern int door_fd;
extern struct bunyan_logger *blog;
extern __thread struct bunyan_logger *tlog;
extern uuid_t sys_uuid;
extern char *zones_dataset;

extern mutex_t g_zfs_lock;
extern struct libzfs_handle *g_zfs;

extern mutex_t piv_lock;
extern SCARDCONTEXT piv_ctx;

const char *get_dc(void);
const char *get_domain(void);

void kbmd_dfatal(int, const char *, ...) __NORETURN;
int kbmd_door_setup(const char *);

void kbmd_ret_nvlist(struct nvlist *) __NORETURN;
void kbmd_ret_error(struct errf *) __NORETURN;

void kbmd_zfs_unlock(struct nvlist *);
void kbmd_zpool_create(struct nvlist *);
void kbmd_recover_init(void);
void kbmd_recover_start(struct nvlist *, pid_t);
void kbmd_recover_resp(struct nvlist *, pid_t);

struct errf *kbmd_assert_pin(struct piv_token *);
struct errf *kbmd_get_ebox(const char *restrict, struct ebox **restrict);
struct errf *kbmd_put_ebox(struct ebox *);
struct errf *kbmd_unlock_ebox(struct ebox *);
struct errf *ebox_to_str(struct ebox *restrct, char **restrict);

struct errf *kbmd_scan_pools(void);

struct errf *kbmd_get_pin(const uint8_t [restrict], struct custr **restrict);
struct errf *kbmd_register_pivtoken(struct piv_token *restrict,
    const char *restrict, struct custr **restrict);
struct errf *kbmd_replace_pivtoken(uint8_t [restrict],
    struct piv_token *restrict, const char *restrict, const char *restrict,
    struct custr **restrict);
struct errf *kbmd_setup_token(struct piv_token **, uint8_t **, size_t *);

void kbmd_event_init(int);
void kbmd_event_fini(void);
struct errf *kbmd_watch_pid(pid_t, void (*)(pid_t, void *), void *);
struct errf *kbmd_unwatch_pid(pid_t);

#ifdef __cplusplus
}
#endif

#endif /* _KBMD_H */
