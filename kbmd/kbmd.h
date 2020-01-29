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

#ifndef _KBMD_H
#define	_KBMD_H

#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <thread.h>
#include <synch.h>
#include <sys/debug.h>
#include <sys/uuid.h>
#include <wintypes.h>
#include <winscard.h>

#include "common/kbm.h"
#include "pivy/errf.h"
#include "pivy/ebox.h"
#include "pivy/piv.h"

#ifdef __cplusplus
extern "C" {
#endif


#define	KBMD_PG				"kbmd"
#define	KBMD_PROP_INC			"kbmd-plugin-dir"
#define	DEFAULT_FMRI			"svc:/system/kbmd:default"
#define	PLUGIN_PATH_ENV			"KBM_PLUGIN_DIR"

/*
 * XXX: Once we have a better idea of the permissions needed for the ccid
 * driver, we can perhaps set these to something other than root.
 */
#define	UID_KBMD	0
#define	GID_KBMD	0

#define	BOX_PROP	"com.joyent.kbm:ebox"
#define	STAGEBOX_PROP	"com.joyent.kbm:stagedebox"

/* These come from NIST 800-73-4 */
#define	PIN_MIN_LENGTH	6
#define	PIN_MAX_LENGTH	8

/*
 * Is a dataset name the pool name?
 *
 * XXX: Might need to expand this to check for other special characters
 * (e.g. '@' or '%').
 */
#define	IS_ZPOOL(_name) (strchr(_name, '/') == NULL)

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
	recovery_token_t	kt_rtoken;
} kbmd_token_t;

extern uuid_t sys_uuid;

extern mutex_t g_zfs_lock;
extern struct libzfs_handle *g_zfs;

/*
 * piv_lock protects piv_ctx, sys_piv, and sys_pool
 */
extern mutex_t piv_lock;
extern SCARDCONTEXT piv_ctx;
extern kbmd_token_t *sys_piv;
extern char *sys_pool;

extern struct ebox *sys_box;

extern struct errf *foreach_stop;

void kbmd_dfatal(int, const char *, ...) __NORETURN;
int kbmd_door_setup(const char *);

void kbmd_return(errf_t *restrict, struct nvlist *restrict) __NORETURN;
pid_t req_pid(void);

void dispatch_request(struct nvlist *);
errf_t *kbmd_zpool_create(const char *, const uint8_t *,
    const struct ebox_tpl *, const recovery_token_t *, nvlist_t *);
void kbmd_recover_init(int);
void kbmd_recover_start(struct nvlist *);
void kbmd_recover_resp(struct nvlist *);
void kbmd_list_recovery(struct nvlist *);

errf_t *
template_hash(const struct ebox_tpl *, uint8_t **, size_t *);

errf_t *ezfs_open(struct libzfs_handle *, const char *, int,
    struct zfs_handle **);

errf_t *get_dataset_status(const char *, boolean_t *, boolean_t *);
errf_t *create_template(kbmd_token_t *restrict, const struct ebox_tpl *,
    struct ebox_tpl **restrict);

errf_t *kbmd_get_ebox(const char *restrict, boolean_t, struct ebox **restrict);
errf_t *kbmd_put_ebox(struct ebox *, boolean_t);
errf_t *ebox_to_str(struct ebox *restrct, char **restrict);

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
errf_t *kbmd_auth_pivtoken(kbmd_token_t *restrict, struct sshkey *restrict);
errf_t *kbmd_setup_token(kbmd_token_t **restrict);
void kbmd_set_token(kbmd_token_t *);
void kbmd_token_free(kbmd_token_t *);
errf_t *set_piv_rtoken(kbmd_token_t *, const recovery_token_t *);

/* plugin.c */
errf_t *kbmd_get_pin(const uint8_t guid[restrict], struct custr **restrict);
errf_t *register_pivtoken(kbmd_token_t *restrict,
    struct ebox_tpl **restrict);
errf_t *replace_pivtoken(const uint8_t [], const recovery_token_t *,
    kbmd_token_t *restrict , struct ebox_tpl **restrict);
errf_t *new_recovery_token(kbmd_token_t *restrict);
errf_t *post_recovery_config_update(void);
void load_plugin(void);

/* box.c */
errf_t *kbmd_unlock_ebox(struct ebox *restrict, struct kbmd_token **restrict);
errf_t *kbmd_create_ebox(kbmd_token_t *restrict, const struct ebox_tpl *,
    const char *, uint8_t **restrict, size_t *restrict, struct ebox **restrict);

#define	FOREACH_STOP foreach_stop

typedef errf_t *(ebox_tpl_cb_t)(struct ebox_tpl_config *, void *);
typedef errf_t *(ebox_tpl_part_cb_t)(struct ebox_tpl_part *, void *);

errf_t *ebox_tpl_foreach_cfg(struct ebox_tpl *, ebox_tpl_cb_t, void *);
errf_t *ebox_tpl_foreach_part(struct ebox_tpl_config *, ebox_tpl_part_cb_t,
    void *);

errf_t *add_recovery(const char *, const struct ebox_tpl *, boolean_t,
    const recovery_token_t *);
errf_t *activate_recovery(const char *);
errf_t *remove_recovery(const char *);

/* zfs_unlock.c */
errf_t *load_key(const char *, const uint8_t *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _KBMD_H */
