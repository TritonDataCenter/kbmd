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

#ifndef _KBM_H
#define	_KBM_H

#ifdef __cplusplus
extern "C" {
#endif

#define	KBM_DOOR_PATH		"/var/run/kbm_door"
#define	KBM_ALT_DOOR_PATH	"/etc/svc/volatile/.kbm_door"

/* nvlist keys shared between kbmd and kbmadm */
#define	KBM_NV_CMD		"command"	/* int32_t */
#define	KBM_NV_SUCCESS		"success"	/* boolean value */
#define	KBM_NV_ERRMSG		"errmsg"	/* string */
#define	KBM_NV_CREATE_ARGS	"args"		/* string array */
#define	KBM_NV_ZPOOL_KEY	"zpool-key"	/* byte array */
#define	KBM_NV_ZFS_DATASETS	"datasets"	/* string array */
#define	KBM_NV_RECOVER_ID	"recover-id"	/* uint64_t */

typedef enum kbm_cmd {
	KBM_CMD_ZFS_UNLOCK,
	KBM_CMD_ZPOOL_CREATE,
	KBM_CMD_RECOVER_START,
	KBM_CMD_RECOVER_RESP,
} kbm_cmd_t;

#ifdef __cplusplus
}
#endif

#endif /* _KBM_H */
