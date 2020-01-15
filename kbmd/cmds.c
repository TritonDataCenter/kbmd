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

#include <bunyan.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <libzfs_core.h>
#include <strings.h>
#include <synch.h>
#include "pivy/libssh/sshbuf.h"
#include "kbmd.h"

#ifdef DEBUG
#include <stdio.h>
#endif

static errf_t *get_dataset(nvlist_t *, const char **);
static const char *kbm_cmd_str(kbm_cmd_t);

/*
 * As a general note, all of the cmd_xxx functions defer freeing their
 * request nvlist_t until immediately before they return, even though
 * in many cases, it could be done sooner in the functions. This is deliberate
 * so that the contents of the original nvlist are available for debugging
 * purposes through the (almost) entire life of the function.
 */

errf_t *
set_systoken(const uint8_t *guid, size_t guidlen)
{
	errf_t *ret = ERRF_OK;
	kbmd_token_t *kt = NULL;
	char gstr[GUID_STR_LEN] = { 0 };

	if (guidlen != GUID_LEN) {
		return (errf("ParameterError", NULL,
		    "GUID length (%u) is incorrect", guidlen));
	}

	guidtohex(guid, gstr, sizeof (gstr));

	(void) bunyan_info(tlog, "Setting system token",
	    BUNYAN_T_STRING, "guid", gstr,
	    BUNYAN_T_END);

	mutex_enter(&piv_lock);
	if (sys_piv != NULL) {
		const uint8_t *sys_guid = piv_token_guid(sys_piv->kt_piv);

		if (bcmp(sys_guid, guid, GUID_LEN) == 0) {
			mutex_exit(&piv_lock);
			return (ERRF_OK);
		}
	}

	if ((ret = kbmd_find_byguid(guid, GUID_LEN, &kt)) != ERRF_OK) {
		mutex_exit(&piv_lock);
		return (ret);
	}

	(void) bunyan_info(tlog, "Setting system token",
	    BUNYAN_T_STRING, "guid", piv_token_guid_hex(kt->kt_piv),
	    BUNYAN_T_END);

	kbmd_set_token(kt);
	mutex_exit(&piv_lock);
	return (ERRF_OK);
}

static void
kbmd_set_systoken(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	uint8_t *guid = NULL;
	uint_t guidlen = 0;

	if ((ret = envlist_lookup_uint8_array(req, KBM_NV_GUID, &guid,
	    &guidlen)) != ERRF_OK) {
		ret = errf("ParameterError", NULL, "no GUID was specified");
		goto done;
	}

	ret = set_systoken(guid, (size_t)guidlen);

done:
	nvlist_free(req);
	kbmd_return(ret, NULL);
}

static errf_t *
set_guid_part(struct ebox_tpl_part *tpart, void *arg)
{
	uint8_t *guid = arg;

	bcopy(ebox_tpl_part_guid(tpart), guid, GUID_LEN);
	return (FOREACH_STOP);
}

static errf_t *
set_guid(struct ebox_tpl_config *tcfg, void *arg)
{
	if (ebox_tpl_config_type(tcfg) != EBOX_PRIMARY)
		return  (ERRF_OK);

	return (ebox_tpl_foreach_part(tcfg, set_guid_part, arg));
}

static errf_t *
do_set_syspool(const char *zpool)
{
	char *str = NULL;

	VERIFY(MUTEX_HELD(&piv_lock));

	if (strcmp(zpool, sys_pool) == 0) {
		(void) bunyan_debug(tlog,
		    "Tried to set syspool to existing value, no action taken",
		    BUNYAN_T_STRING, "syspool", sys_pool,
		    BUNYAN_T_END);
		return (ERRF_OK);
	}

	if ((str = strdup(zpool)) == NULL) {
		return (errfno("strdup", errno, "failed to set syspool"));
	}

	(void) bunyan_info(tlog, "Setting system zpool",
	    BUNYAN_T_STRING, "syspool", zpool,
	    BUNYAN_T_STRING, "oldvalue",
	    (sys_pool == NULL) ? "(not set)" : sys_pool,
	    BUNYAN_T_END);

	free(sys_pool);
	sys_pool = str;
	return (ERRF_OK);
}

static errf_t *
do_set_sysbox(const char *zpool)
{
	errf_t *ret = ERRF_OK;
	struct ebox *ebox = NULL;

	VERIFY(MUTEX_HELD(&piv_lock));

	if (sys_box != NULL) {
		const char *box_name = ebox_private(sys_box);

		if (strcmp(box_name, zpool) == 0)
			return (ERRF_OK);
	}

	if ((ret = kbmd_get_ebox(zpool, B_FALSE, &ebox)) != ERRF_OK) {
		return (ret);
	}

	ebox_free(sys_box);
	sys_box = ebox;

	(void) bunyan_trace(tlog, "Set system ebox",
	    BUNYAN_T_STRING, "dataset", zpool,
	    BUNYAN_T_END);

	return (ERRF_OK);
}

static errf_t *
set_syspool(const char *zpool)
{
	errf_t *ret = ERRF_OK;
	zpool_handle_t *zhp = NULL;
	boolean_t exists = B_FALSE;
	uint8_t guid[GUID_LEN] = { 0 };

	(void) bunyan_info(tlog, "Setting system zpool",
	    BUNYAN_T_STRING, "syspool", zpool,
	    BUNYAN_T_END);

	if (!IS_ZPOOL(zpool)) {
		return (errf("ParameterError", NULL, "'%s' is not a zpool",
		    zpool));
	}

	mutex_enter(&piv_lock);
	mutex_enter(&g_zfs_lock);

	if ((zhp = zpool_open_canfail(g_zfs, zpool)) == NULL) {
		mutex_exit(&g_zfs_lock);
		return (errf("zpool_open_canfail", NULL,
		    "could not determine existence of '%s'", zpool));
	}

	exists = (zhp != NULL) ? B_TRUE : B_FALSE;
	zpool_close(zhp);
	mutex_exit(&g_zfs_lock);

	if (exists && (ret = do_set_sysbox(zpool)) != ERRF_OK) {
		mutex_exit(&piv_lock);
		return (ret);
	}

	if (!exists) {
		return (errf("NotFoundError", NULL, "zpool '%s' not found",
		    zpool));
	}

	if ((ret = do_set_syspool(zpool)) != ERRF_OK) {
		mutex_exit(&piv_lock);
		return (ret);
	}

	ret = ebox_tpl_foreach_cfg(ebox_tpl(sys_box), set_guid, guid);
	mutex_exit(&piv_lock);

	if (ret != ERRF_OK) {
		return (ret);
	}

	ret = set_systoken(guid, sizeof (guid));

	return (ret);
}

static void
kbmd_set_syspool(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	char *zpool = NULL;

	if ((ret = envlist_lookup_string(req, KBM_NV_SYSPOOL,
	    &zpool)) != ERRF_OK) {
		ret = errf("ParameterError", NULL, "no zpool was specified");
		goto done;
	}

	ret = set_syspool(zpool);

done:
	nvlist_free(req);
	kbmd_return(ret, NULL);
}

errf_t *
load_key(const char *dataset, const uint8_t *key, size_t keylen)
{
	errf_t *ret = ERRF_OK;
	int rc;

	/*
	 * lzc_load_key() returns EEXIST if the key is already loaded.
	 * Don't treat EEXIST as a failure.
	 */
	if ((rc = lzc_load_key(dataset, B_FALSE, (uint8_t *)key,
	    keylen)) != 0 && rc != EEXIST) {
		ret = errfno("lzc_load_key", rc,
		    "failed to load key for %s dataset", dataset);
	}

	return (ret);
}

errf_t *
get_dataset_status(const char *dataset, boolean_t *restrict encryptedp,
    boolean_t *restrict lockedp)
{
	errf_t *ret = ERRF_OK;
	zfs_handle_t *zhp = NULL;
	int encryption, keystatus;

	mutex_enter(&g_zfs_lock);
	if ((ret = ezfs_open(g_zfs, dataset,
	    ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME, &zhp)) != ERRF_OK) {
		mutex_exit(&g_zfs_lock);
		ret = errf("ZfsError", ret,
		    "unable to open dataset %s to check encryption status",
		    dataset);
		return (ret);
	}

	/*
	 * If the dataset is not encrypted, we treat it as if the
	 * key was loaded (unlocked).
	 *
	 * NOTE: This might not do the right thing for a child inheriting
	 * the encryption status of its parent, however we shouldn't be
	 * using this on such datasets.
	 */
	encryption = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);
	(void) bunyan_trace(tlog, "Checking encryption status for dataset",
	    BUNYAN_T_STRING, "dataset", dataset,
	    BUNYAN_T_INT32, "encryption", encryption,
	    BUNYAN_T_END);

	if (encryption == ZIO_CRYPT_OFF) {
		*encryptedp = B_FALSE;
		*lockedp = B_FALSE;
		goto done;
	}
	*encryptedp = B_TRUE;

	keystatus = zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS);
	(void) bunyan_trace(tlog, "Checking dataset keystatus",
	    BUNYAN_T_STRING, "dataset", dataset,
	    BUNYAN_T_INT32, "keystatus", keystatus,
	    BUNYAN_T_END);

	if (keystatus == ZFS_KEYSTATUS_AVAILABLE) {
		*lockedp = B_FALSE;
	} else {
		*lockedp = B_TRUE;
	}

done:
	zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	return (ret);
}

errf_t *
unlock_dataset(const char *dataset)
{
	errf_t *ret = ERRF_OK;
	struct ebox *ebox = NULL;
	kbmd_token_t *kt = NULL;
	const uint8_t *key = NULL;
	size_t keylen = 0;
	boolean_t is_encrypted, is_locked;

	(void) bunyan_info(tlog, "Request to unlock dataset",
	    BUNYAN_T_STRING, "dataset", dataset,
	    BUNYAN_T_END);

	mutex_enter(&piv_lock);

	if ((ret = get_dataset_status(dataset, &is_encrypted,
	    &is_locked)) != ERRF_OK) {
		goto done;
	}

	if (!is_encrypted) {
		ret = errf("ArgumentError", NULL,
		    "dataset %s does not appear to be encrypted", dataset);
		goto done;
	}

	if (!is_locked) {
		ret = errf("AlreadyUnlocked", NULL,
		    "dataset %s's key is already loaded", dataset);
		goto done;
	}

	if ((ret = kbmd_get_ebox(dataset, B_FALSE, &ebox)) != ERRF_OK ||
	    (ret = kbmd_unlock_ebox(ebox, &kt)) != ERRF_OK) {
		goto done;
	}

	key = ebox_key(ebox, &keylen);
	if ((ret = load_key(dataset, key, keylen)) != ERRF_OK) {
		goto done;
	}

done:
	mutex_exit(&piv_lock);
	return (ret);
}

void
kbmd_zfs_unlock(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = NULL;

	if ((ret = get_dataset(req, &dataset)) != ERRF_OK)
		goto done;

	ret = unlock_dataset(dataset);

done:
	nvlist_free(req);
	kbmd_return(ret, NULL);
}

static errf_t *
get_request_template(nvlist_t *restrict nvl, struct ebox_tpl **restrict tplp)
{
	errf_t *ret = ERRF_OK;
	struct sshbuf *buf = NULL;
	uint8_t *bytes = NULL;
	uint_t nbytes = 0;

	if ((ret = envlist_lookup_uint8_array(nvl, KBM_NV_TEMPLATE, &bytes,
	    &nbytes)) != ERRF_OK)
		return (ret);

	if ((buf = sshbuf_from(bytes, nbytes)) == NULL) {
		return (errfno("sshbuf_from", errno,
		    "cannot allocate ebox template"));
	}

	ret = sshbuf_get_ebox_tpl(buf, tplp);
	sshbuf_free(buf);
	return (ret);
}

static errf_t *
get_nvrtoken(nvlist_t *nvl, const char *name, recovery_token_t *rtok)
{
	errf_t *ret = ERRF_OK;
	uint8_t *val = NULL;
	uint_t len = 0;

	if ((ret = envlist_lookup_uint8_array(nvl, name, &val,
	    &len)) != ERRF_OK) {
		return (ret);
	}

	rtok->rt_val = val;
	rtok->rt_len = len;
	return (ret);
}

static void
cmd_zpool_create(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = NULL;
	struct ebox_tpl *rcfg = NULL;
	uint8_t *guid = NULL;
	uint_t guidlen = 0;
	recovery_token_t rtoken = { 0 };
	nvlist_t *resp = NULL;

	if ((ret = get_dataset(req, &dataset)) != ERRF_OK)
		goto done;

	if ((ret = envlist_lookup_uint8_array(req, KBM_NV_GUID, &guid,
	    &guidlen)) != ERRF_OK) {
		if (!errf_caused_by(ret, "ENOENT"))
			goto done;
		errf_free(ret);
		ret = ERRF_OK;
	}
	if (guid != NULL && guidlen != GUID_LEN) {
		ret = errf("InvalidGUID", NULL, "Bad guid length (%u)",
		    guidlen);
		goto done;
	}

	if ((ret = get_request_template(req, &rcfg)) != ERRF_OK) {
		if (!errf_caused_by(ret, "ENOENT"))
			goto done;
		errf_free(ret);
		ret = ERRF_OK;
	}

	if ((ret = get_nvrtoken(req, KBM_NV_RTOKEN, &rtoken)) != ERRF_OK) {
		if (!errf_caused_by(ret, "ENOENT"))
			goto done;
		errf_free(ret);
		ret = ERRF_OK;
	}

	if ((ret = envlist_alloc(&resp)) != ERRF_OK)
		goto done;

	ret = kbmd_zpool_create(dataset, guid, rcfg, &rtoken, resp);

done:
	explicit_bzero(rtoken.rt_val, rtoken.rt_len);
	nvlist_free(req);
	kbmd_return(ret, resp);
}

static void
cmd_add_recovery(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = NULL;
	struct ebox_tpl *tpl = NULL;
	recovery_token_t rtoken = { 0 };
	boolean_t stage = B_FALSE;

	if ((ret = get_dataset(req, &dataset)) != ERRF_OK)
		goto done;

	if ((ret = get_request_template(req, &tpl)) != ERRF_OK)
		goto done;

	if ((ret = envlist_lookup_boolean_value(req, KBM_NV_STAGE,
	    &stage)) != ERRF_OK)
		goto done;

	if ((ret = get_nvrtoken(req, KBM_NV_RTOKEN, &rtoken)) != ERRF_OK) {
		if (!errf_caused_by(ret, "ENOENT")) {
			goto done;
		}
		errf_free(ret);
		ret = ERRF_OK;
	}

	ret = add_recovery(dataset, tpl, stage, &rtoken);

done:
	explicit_bzero(rtoken.rt_val, rtoken.rt_len);
	nvlist_free(req);
	ebox_tpl_free(tpl);
	kbmd_return(ret, NULL);
}

static void
cmd_activate_recovery(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = NULL;

	if ((ret = get_dataset(req, &dataset)) != ERRF_OK)
		goto done;

	ret = activate_recovery(dataset);

done:
	nvlist_free(req);
	kbmd_return(ret, NULL);
}

static void
cmd_remove_recovery(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = NULL;

	if ((ret = get_dataset(req, &dataset)) != ERRF_OK)
		goto done;

	ret = remove_recovery(dataset);

done:
	nvlist_free(req);
	kbmd_return(ret, NULL);
}

static void
cmd_replace_pivtoken(nvlist_t *req)
{
	nvlist_free(req);
	kbmd_return(ERRF_OK, NULL);
}

void
dispatch_request(nvlist_t *req)
{

	errf_t *ret = ERRF_OK;
	int cmdval;

#ifdef DEBUG
	/*
	 * XXX: These will probably be removed before integration
	 */
	flockfile(stderr);
	(void) fprintf(stderr, "Request\n");
	nvlist_print(stderr, req);
	(void) fputc('\n', stderr);
	funlockfile(stderr);
#endif

	ret = envlist_lookup_int32(req, KBM_NV_CMD, &cmdval);
	if (ret != ERRF_OK) {
		(void) bunyan_info(tlog, "Unable to obtain command",
		    BUNYAN_T_INT32, "errno", errf_errno(ret),
		    BUNYAN_T_STRING, "errmsg", errf_message(ret),
		    BUNYAN_T_END);

		ret = errf("InvalidCommand", ret,
		    "Unable to retrieve command value");

		goto fail;
	}

	(void) bunyan_info(tlog, "Received request",
	    BUNYAN_T_STRING, "request", kbm_cmd_str(cmdval),
	    BUNYAN_T_INT32, "reqval", cmdval,
	    BUNYAN_T_END);

	switch ((kbm_cmd_t)cmdval) {
	case KBM_CMD_ZFS_UNLOCK:
		kbmd_zfs_unlock(req);
		break;
	case KBM_CMD_ZPOOL_CREATE:
		cmd_zpool_create(req);
		break;
	case KBM_CMD_RECOVER_START:
		kbmd_recover_start(req);
		break;
	case KBM_CMD_RECOVER_RESP:
		kbmd_recover_resp(req);
		break;
	case KBM_CMD_ADD_RECOVERY:
		cmd_add_recovery(req);
		break;
	case KBM_CMD_LIST_RECOVERY:
		kbmd_list_recovery(req);
		break;
	case KBM_CMD_ACTIVATE_RECOVERY:
		cmd_activate_recovery(req);
		break;
	case KBM_CMD_CANCEL_RECOVERY:
		cmd_remove_recovery(req);
		break;
	case KBM_CMD_SET_SYSTOKEN:
		kbmd_set_systoken(req);
		break;
	case KBM_CMD_SET_SYSPOOL:
		kbmd_set_syspool(req);
		break;
	case KBM_CMD_REPLACE_PIVTOKEN:
		cmd_replace_pivtoken(req);
		break;
	default:
		(void) bunyan_info(tlog, "Unknown command value in request",
		    BUNYAN_T_INT32, "cmdval", cmdval,
		    BUNYAN_T_END);

		ret = errf("InvalidCommand", NULL, "Invalid command value %d",
		    cmdval);
		break;
	}

fail:
	nvlist_free(req);
	kbmd_return(ret, NULL);
}

static errf_t *
get_dataset(nvlist_t *req, const char **dsp)
{
	errf_t *ret = ERRF_OK;
	char *dataset = NULL;

	ret = envlist_lookup_string(req, KBM_NV_ZFS_DATASET, &dataset);
	if (ret != ERRF_OK) {
		int cmdval;

		/*
		 * If we get here, we should have already verified we have
		 * a valid command.
		 */
		VERIFY0(nvlist_lookup_int32(req, KBM_NV_CMD, &cmdval));

		(void) bunyan_warn(tlog,
		    "Failed to lookup dataset name for command",
		    BUNYAN_T_STRING, "cmd", kbm_cmd_str((kbm_cmd_t)cmdval),
		    BUNYAN_T_END);
		return (errf("ArgumentError", ret, "dataset name is missing"));
	}

	*dsp = dataset;
	return (ERRF_OK);
}

static const char *
kbm_cmd_str(kbm_cmd_t cmd)
{
#define	STR(_x) case _x: return (#_x)
	switch (cmd) {
	STR(KBM_CMD_ZFS_UNLOCK);
	STR(KBM_CMD_ZPOOL_CREATE);
	STR(KBM_CMD_RECOVER_START);
	STR(KBM_CMD_RECOVER_RESP);
	STR(KBM_CMD_ADD_RECOVERY);
	STR(KBM_CMD_LIST_RECOVERY);
	STR(KBM_CMD_ACTIVATE_RECOVERY);
	STR(KBM_CMD_CANCEL_RECOVERY);
	STR(KBM_CMD_SET_SYSTOKEN);
	STR(KBM_CMD_SET_SYSPOOL);
	STR(KBM_CMD_REPLACE_PIVTOKEN);
	default:
		return ("<unknown>");
	}
}
