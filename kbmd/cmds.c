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

#include <bunyan.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <libzfs_core.h>
#include <strings.h>
#include <synch.h>
#include "pivy/libssh/sshbuf.h"
#include "kbmd.h"

static const char *kbm_cmd_str(kbm_cmd_t);

static errf_t *
set_systoken(const uint8_t *guid, size_t guidlen)
{
	char gstr[GUID_STR_LEN] = { 0 };

	if (guidlen != GUID_LEN) {
		return (errf("ParameterError", NULL,
		    "GUID length (%u) is incorrect", guidlen));
	}

	guidtohex(guid, gstr, sizeof (gstr));

	(void) bunyan_info(tlog, "Setting system token",
	    BUNYAN_T_STRING, "guid", gstr,
	    BUNYAN_T_END);

	mutex_enter(&guid_lock);
	bcopy(guid, sys_guid, GUID_LEN);
	mutex_exit(&guid_lock);

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
set_syspool(const char *zpool)
{
	/*
	 * Since we want this to be set only once, we treat 'sys_pool' as
	 * a write once variable. To accomplish this, we serialize execution
	 * of set_syspool() using sys_syspool_lock, so that once set,
	 * sys_pool cannot be altered.
	 */
	static mutex_t set_syspool_lock = ERRORCHECKMUTEX;

	errf_t *ret = ERRF_OK;
	zpool_handle_t *zhp = NULL;
	struct ebox *sys_ebox = NULL;
	uint8_t guid[GUID_LEN] = { 0 };

	mutex_enter(&set_syspool_lock);

	(void) bunyan_info(tlog, "Setting system zpool",
	    BUNYAN_T_STRING, "syspool", zpool,
	    BUNYAN_T_END);

	if (sys_pool != NULL) {
		ret = errf("AlreadySetError", NULL,
		    "syspool is already set to '%s'", sys_pool);
		goto done;
	}

	if (!IS_ZPOOL(zpool)) {
		ret = errf("ParameterError", NULL, "'%s' is not a zpool",
		    zpool);
		goto done;
	}

	if ((zhp = zpool_open_canfail(get_libzfs(), zpool)) == NULL) {
		ret = errf("NotFoundError", NULL, "unable to open zpool %s: %s",
		    libzfs_error_description(get_libzfs()));
		goto done;
	}

	zpool_close(zhp);

	/*
	 * Load the ebox for this zpool, and set 'guid' to GUID of the
	 * template part of the EBOX_PRIMARY template config in 'sys_ebox'.
	 * In other words, set 'guid' to the GUID of the PIV token that
	 * unlocks the ebox for the system zpool.
	 */
	if ((ret = kbmd_get_ebox(zpool, B_FALSE, &sys_ebox)) != ERRF_OK) {
		goto done;
	}
	ret = ebox_tpl_foreach_cfg(ebox_tpl(sys_ebox), set_guid, guid);
	/* It should never return an error */
	VERIFY3P(ret, ==, ERRF_OK);

	if ((sys_pool = strdup(zpool)) == NULL) {
		ret = errfno("strdup", errno, "failed to set system pool");
		goto done;
	}

	ret = set_systoken(guid, sizeof (guid));

done:
	mutex_exit(&set_syspool_lock);
	ebox_free(sys_ebox);
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

	if ((ret = ezfs_open(dataset, ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME,
	    &zhp)) != ERRF_OK) {
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
	return (ret);
}

static errf_t *
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
	if (key == NULL) {
		ret = errf("EboxError", NULL,
		    "ebox for %s does not contain a key!", dataset);
		goto done;
	}

	ret = load_key(dataset, key, keylen);

done:
	ebox_free(ebox);
	kbmd_token_free(kt);
	return (ret);
}

static void
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

void
dispatch_request(nvlist_t *req)
{

	errf_t *ret = ERRF_OK;
	int cmdval;

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

	(void) bunyan_key_add(tlog,
	    BUNYAN_T_STRING, "request", kbm_cmd_str(cmdval),
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
	default:
		(void) bunyan_error(tlog, "Unknown command value in request",
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

errf_t *
get_dataset(nvlist_t *req, const char **dsp)
{
	errf_t *ret = ERRF_OK;
	char *dataset = NULL;

	*dsp = NULL;

	ret = envlist_lookup_string(req, KBM_NV_ZFS_DATASET, &dataset);
	if (ret == ERRF_OK) {
		*dsp = dataset;
		return (ERRF_OK);
	}

	if (errf_caused_by(ret, "ENOENT")) {
		if (sys_pool != NULL) {
			*dsp = sys_pool;
			errf_free(ret);
			return (ERRF_OK);
		}

		return (errf("ParameterError", ret,
		    "No dataset given and system pool not set")); 
	}

	/*
	 * dispatch_cmd() already sets the request as part of tlog,
	 * so we don't need to include it again.
	 */
	(void) bunyan_warn(tlog,
	    "Failed to lookup dataset name for request",
	    BUNYAN_T_END);

	return (ret);
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
	default:
		return ("<unknown>");
	}
}
