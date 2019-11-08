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

#ifndef _KBM_H
#define	_KBM_H

#include "common/common.h"
#include "common/kspawn.h"
#include "common/ecustr.h"
#include "common/envlist.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The size (in bytes) of a raw (not base64 encoded) recovery token. It is
 * based on the size allowed in an ebox which itself is limited by the
 * size of data that the Shamir secret sharing code allows.
 */
#define	RECOVERY_TOKEN_LEN	32U

/*
 * For most daemons, we'd set their equivalent of KBMD_RUNDIR to /var/run/xxx.
 * However, kbmd starts early enough in the boot process that /var/run isn't
 * mounted yet.  Similar to dladm and ipadm (and likely for similar reasons),
 * we use /etc/svc/volatile instead.
 */
#define	KBMD_RUNDIR		"/etc/svc/volatile/kbmd"
#define	KBMD_DOOR_PATH		KBMD_RUNDIR "/kbmd_door"

/* nvlist keys shared between kbmd and kbmadm */
#define	KBM_NV_CMD		"command"	/* int32_t */
#define	KBM_NV_SUCCESS		"success"	/* boolean value */
#define	KBM_NV_ERRMSG		"errmsg"	/* string */
#define	KBM_NV_CREATE_ARGS	"args"		/* string array */
#define	KBM_NV_DATASET		"dataset"	/* string */
#define	KBM_NV_ZPOOL_KEY	"zpool-key"	/* byte array */
#define	KBM_NV_ZFS_DATASET	"dataset"	/* string */
#define	KBM_NV_RECOVER_ID	"recover-id"	/* uint32_t */

#define	KBM_NV_ACTION		"action"	/* int32_t */
#define	KBM_NV_PROMPT		"prompt"	/* string */
#define	KBM_NV_CONFIGS		"configs"	/* nvlist */
#define	KBM_NV_PARTS		"parts"		/* nvlist array */
#define	KBM_NV_ANSWER		"answer"	/* string */
#define	KBM_NV_REMAINING	"remaining"	/* uint32_t */

#define	KBM_NV_CONFIG_HASH	"config hash"	/* uint8 array */
#define	KBM_NV_CONFIG_NUM	"config num"	/* uint32_t */
#define	KBM_NV_DESC		"desc"		/* string */
#define	KBM_NV_GUID		"guid"		/* uint8_t array */
#define	KBM_NV_NAME		"name"		/* string */
#define	KBM_NV_CHALLENGE	"challenge"	/* string */
#define	KBM_NV_WORDS		"words"		/* string array */
#define	KBM_NV_SLOT		"slot"		/* int32_t */
#define	KBM_NV_PUBKEY		"pubkey"	/* string */
#define	KBM_NV_N		"n"		/* uint32_t */

#define	KBM_NV_RESP_QUIT	"quit"		/* boolean */
#define	KBM_NV_RECOVERY_COMPLETE	"recovery-complete"	/* boolean */

#define	KBM_NV_TEMPLATE		"template"	/* uint8_t array */
#define	KBM_NV_SYSPOOL		"syspool"	/* string */
#define	KBM_NV_RTOKEN		"rtoken"	/* uint8_t array */
#define	KBM_NV_STAGE		"stage"		/* boolean value */

/*
 * A request looks similar to the following:
 *	command=nnn
 *	<command specific parameters>
 *
 * A failed response from kbmadm will look like:
 *	success=B_FALSE
 *	errmsg=....
 *
 * A successful response from kbmadm will look like:
 *	success=B_TRUE
 *	<returned data>
 *
 * For ZFS unlock:
 *    Request:
 *	command=KBM_CMD_ZFS_UNLOCK
 *	dataset=XXX (optional, otherwise all datasets w/ boxes are unlocked)
 *
 *    Response (success):
 *	success=B_TRUE
 *
 * For zpool create:
 *    Request:
 *	command=KBM_CMD_ZPOOL_CREATE
 *
 *    Response (success):
 *	success=B_TRUE
 *	args=[(option=XXX,value=xxx)...] (e.g.
 *		(option=rfd77:config,value=xxx),
 *		(option=encryption,value=on)...)
 *	zpool-key=<raw encryption key for zpool>
 *
 * For recovery:
 *    Request:
 *	command=KBM_CMD_RECOVER_START
 *
 *    Response (success):
 *	success=B_TRUE
 *	recover-id=xxxxxx
 *	prompt=xxx
 *	action=KBM_ACT_CONFIG
 *	configs=[{
 *	}]
 *
 *	or
 *
 *	success=B_TRUE
 *	recover-id=xxxxxx
 *	prompt=xxx
 *	action=KBM_ACT_RECOVER
 *	parts=[
 *	    {
 *	        guid=xxx
 *	        name=xxx (optional)
 *	        challenge=xxx
 *	        words=xxx
 *	    }, ...
 *	]
 *	remaining=nnn
 *
 *    Request:
 *	command=KBM_CMD_RECOVER_RESP
 *	recover-id=xxxxx
 *	answer=xxxx
 *
 *    ....
 *
 *    Response:
 *	success=B_TRUE
 *	recovery-complete
 */

typedef enum kbm_cmd {
	KBM_CMD_ZFS_UNLOCK,
	KBM_CMD_ZPOOL_CREATE,
	KBM_CMD_RECOVER_START,
	KBM_CMD_RECOVER_RESP,
	KBM_CMD_ADD_RECOVERY,
	KBM_CMD_LIST_RECOVERY,
	KBM_CMD_ACTIVATE_RECOVERY,
	KBM_CMD_CANCEL_RECOVERY,
	KBM_CMD_SET_SYSPOOL,
	KBM_CMD_SET_SYSTOKEN,
	KBM_CMD_REPLACE_PIVTOKEN,
} kbm_cmd_t;

typedef enum kbm_act {
	KBM_ACT_CONFIG,
	KBM_ACT_CHALLENGE
} kbm_act_t;

#ifdef __cplusplus
}
#endif

#endif /* _KBM_H */
