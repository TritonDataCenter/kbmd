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

#include "common/kbm.h"
#include "pivy/ebox.h"
#include "pivy/errf.h"
#include "pivy/piv.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XXX: Once we have a better idea of the permissions needed for the ccid
 * driver, we can perhaps set these to something other than root.
 */
#define	UID_KBMD	0
#define	GID_KBMD	0

#define	BOX_PROP	"rfd77:ebox"
#define	BOX_NEWPROP	"rfd77:newebox"

#define	CONSOLIDATE_MIN		(6U * 60U * 60U)
#define	CONSOLIDATE_SPLAY	CONSOLIDATE_MIN

/* These come from NIST 800-73-4 */
#define	PIN_MIN_LENGTH	6
#define	PIN_MAX_LENGTH	8

struct custr;
struct ebox;
struct ebox_tpl;
struct ebox_tpl_config;
struct nvlist;
struct piv_slot;
struct piv_token;
struct sshkey;
struct zfs_handle;

/*
 * The only field of kbmd_token_t that is guaranteed to be non-NULL is
 * kt_piv.  The remaining fields may be NULL depending on the context.
 */
typedef struct kbmd_token {
	struct piv_token	*kt_piv;
	char			kt_pin[PIN_MAX_LENGTH + 1];
	uint8_t			*kt_rtoken;	/* The recovery token */
	size_t			kt_rtoklen;	/* Recovery token len */
} kbmd_token_t;

extern int door_fd;
extern uuid_t sys_uuid;
extern char *zones_dataset;

extern mutex_t g_zfs_lock;
extern struct libzfs_handle *g_zfs;

/*
 * piv_lock protects piv_ctx, kpiv, and sys_box
 */
extern mutex_t piv_lock;
extern SCARDCONTEXT piv_ctx;
extern kbmd_token_t *kpiv;
extern struct ebox *sys_box;
#define	IS_SYSTEM_TOKEN(_tok) ((kpiv != NULL) && ((_tok) == kpiv->kt_piv))

const char *get_dc(void);
const char *get_domain(void);

void kbmd_dfatal(int, const char *, ...) __NORETURN;
int kbmd_door_setup(const char *);

void kbmd_ret_nvlist(struct nvlist *) __NORETURN;
void kbmd_ret_error(errf_t *) __NORETURN;

void kbmd_zfs_unlock(struct nvlist *);
void kbmd_zpool_create(struct nvlist *);
void kbmd_recover_init(void);
void kbmd_recover_start(struct nvlist *, pid_t);
void kbmd_recover_resp(struct nvlist *, pid_t);
void kbmd_update_recovery(struct nvlist *);

errf_t *get_template(struct piv_token *, struct ebox_tpl **);
errf_t *get_request_template(struct nvlist *restrict,
    struct ebox_tpl **restrict);
errf_t *add_supplied_template(struct nvlist *, struct ebox_tpl *,
    boolean_t);
errf_t *create_piv_tpl_config(kbmd_token_t *,
    struct ebox_tpl_config **restrict);

errf_t *kbmd_get_ebox(const char *restrict, struct ebox **restrict);
errf_t *kbmd_put_ebox(struct ebox *);
errf_t *ebox_to_str(struct ebox *restrct, char **restrict);
errf_t *kbmd_ageout_zfs_ebox(const char *);

errf_t *kbmd_scan_pools(void);

void kbmd_event_init(int);
void kbmd_event_fini(void);
errf_t *kbmd_watch_pid(pid_t, void (*)(pid_t, void *), void *);
errf_t *kbmd_unwatch_pid(pid_t);

/* piv.c */
errf_t *kbmd_find_byguid(const uint8_t *, size_t, kbmd_token_t **);
errf_t *kbmd_find_byslot(enum piv_slotid, const struct sshkey *,
    kbmd_token_t **);
errf_t *kbmd_get_slot(kbmd_token_t *restrict, enum piv_slotid slotid,
    struct piv_slot **restrict);
errf_t *kbmd_assert_pin(kbmd_token_t *);
errf_t *kbmd_verify_pin(kbmd_token_t *);
errf_t *kbmd_assert_token(const uint8_t *, size_t, kbmd_token_t **);
errf_t *kbmd_auth_pivtoken(kbmd_token_t *restrict, struct sshkey *restrict);
errf_t *kbmd_setup_token(kbmd_token_t **);
void kbmd_set_token(kbmd_token_t *);
void kbmd_token_free(kbmd_token_t *);

const char *piv_pin_str(enum piv_pin pin_type);

/* plugin.c */
errf_t *kbmd_get_pin(const uint8_t guid[restrict], struct custr **restrict);
errf_t *kbmd_register_pivtoken(struct piv_token *restrict, const char *restrict,
    struct custr **restrict);
errf_t *kbmd_replace_pivtoken(uint8_t [restrict], struct piv_token *restrict,
    const char *restrict, const char *restrict, struct custr **restrict);
errf_t *kbmd_new_recovery_token(kbmd_token_t *restrict,
    uint8_t **restrict, size_t *restrict);

/* box.c */
errf_t *kbmd_ebox_clone(struct ebox *restrict, struct ebox **restrict,
    struct ebox_tpl *restrict, kbmd_token_t *restrict);
errf_t *kbmd_unlock_ebox(struct ebox *restrict, struct kbmd_token **restrict);
errf_t *kbmd_rotate_zfs_ebox(const char *);

#define	FOREACH_STOP ((errf_t *)(uintptr_t)-1)

typedef errf_t *(ebox_tpl_cb_t)(const struct ebox_tpl *,
    struct ebox_tpl_config *, void *);

errf_t *ebox_tpl_foreach_cfg(const struct ebox_tpl *, ebox_tpl_cb_t, void *);

#ifdef __cplusplus
}
#endif

#endif /* _KBMD_H */
