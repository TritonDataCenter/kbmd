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

#include <bunyan.h>
#include <err.h>
#include <stddef.h>
#include <strings.h>
#include <sys/list.h>
#include <libzfs.h>
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/errf.h"
#include "pivy/libssh/sshbuf.h"
#include "pivy/libssh/ssherr.h"
#include "pivy/piv.h"

#include <stdio.h>

static errf_t *
ezfs_open(libzfs_handle_t *hdl, const char *path, int types,
    zfs_handle_t **zhpp)
{
	if ((*zhpp = zfs_open(hdl, path, types)) == NULL) {
		return (errf("ZFSError", NULL, "unable to open %s: %s",
		    path, libzfs_error_description(hdl)));
	}
	return (ERRF_OK);
}

static errf_t *
ezfs_prop_set_list(zfs_handle_t *zhp, nvlist_t *prop)
{
	if (zfs_prop_set_list(zhp, prop) != 0) {
		return (errf("ZFSError", NULL,
		    "zfs_prop_set_list on %s failed: %s",
		    zfs_get_name(zhp),
		    libzfs_error_description(zfs_get_handle(zhp))));
	}
	return (ERRF_OK);
}

static errf_t *
str_to_ebox(const char *restrict dsname, const char *restrict str,
    struct ebox **restrict eboxp)
{
	errf_t *ret = ERRF_OK;
	struct sshbuf *boxbuf = NULL;
	struct ebox *ebox = NULL;
	int rc;

	if ((boxbuf = sshbuf_new()) == NULL) {
		ret = errf("ConversionError", errfno("sshbuf_new", errno, ""),
		    "unable to parse ebox contents of %s", dsname);
		goto done;
	}

	if ((rc = sshbuf_b64tod(boxbuf, str)) != SSH_ERR_SUCCESS) {
		ret = errf("ConversionError", ssherrf("sshbuf_b64tod", rc),
		    "unable to base64 decode ebox contents for %s", dsname);
		goto done;
	}

	if ((ret = sshbuf_get_ebox(boxbuf, &ebox)) != ERRF_OK) {
		ret = errf("ConversionError", ret,
		    "unable to parse the ebox contents for %s", dsname);
		goto done;
	}

	*eboxp = ebox;

done:
	sshbuf_free(boxbuf);
	return (ret);
}

errf_t *
ebox_to_str(struct ebox *restrict ebox, char **restrict strp)
{
	const char *dsname = ebox_private(ebox);
	errf_t *ret = ERRF_OK;
	struct sshbuf *boxbuf = NULL;
	char *str = NULL;
	int rc;

	VERIFY3P(dsname, !=, NULL);

	if ((boxbuf = sshbuf_new()) == NULL) {
		ret = errf("ConversionError", errfno("sshbuf_new", errno, ""),
		    "unable to serialize ebox for %s", dsname);
		goto done;
	}

	if ((ret = sshbuf_put_ebox(boxbuf, ebox)) != ERRF_OK) {
		ret = errf("ConversionError", ret,
		    "unable to serialize ebox for %s", dsname);
		goto done;
	}

	if ((str = sshbuf_dtob64(boxbuf)) == NULL) {
		ret = errf("sshbuf_dtob64", NULL,
		    "unable to convert ebox for %s to base 64", dsname);
		goto done;
	}

	*strp = str;

done:
	sshbuf_free(boxbuf);
	return (ret);
}

static errf_t *
set_box_dataset(struct ebox *restrict ebox, const char *dsname)
{
	size_t len = strlen(dsname) + 1;
	char *str = ebox_alloc_private(ebox, len);

	if (str == NULL) {
		return (errfno("ebox_alloc_private", errno,
		    "Unable to set dataset name %s on ebox", dsname));
	}

	bcopy(dsname, str, len);
	return (ERRF_OK);
}

static errf_t *
get_ebox_string(zfs_handle_t *restrict zhp, char **restrict sp)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *uprops = NULL;
	nvlist_t *val = NULL;

	uprops = zfs_get_user_props(zhp);
	if ((ret = envlist_lookup_nvlist(uprops, BOX_PROP, &val)) != ERRF_OK) {
		if (!errf_caused_by(ret, "ENOENT"))
			return (ret);
		return (errf("NotFoundError", ret,
		    "dataset %s does not contain an ebox property (%s)",
		    zfs_get_name(zhp), BOX_PROP));
	}

	return (envlist_lookup_string(val, "value", sp));
}

static errf_t *
get_ebox_common(zfs_handle_t *restrict zhp, struct ebox **restrict eboxp)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = zfs_get_name(zhp);
	char *str = NULL;
	struct ebox *ebox = NULL;

	if ((ret = get_ebox_string(zhp, &str)) != ERRF_OK ||
	    (ret = str_to_ebox(dataset, str, &ebox)) != ERRF_OK ||
	    (ret = set_box_dataset(ebox, dataset)) != ERRF_OK)
		return (ret);

	*eboxp = ebox;
	return (ERRF_OK);
}

errf_t *
kbmd_get_ebox(const char *dataset, struct ebox **eboxp)
{
	zfs_handle_t *zhp = NULL;
	errf_t *ret = ERRF_OK;

	mutex_enter(&g_zfs_lock);

	if ((ret = ezfs_open(g_zfs, dataset,
	    ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME, &zhp)) != ERRF_OK) {
		ret = errf("EBoxError", ret,
		    "unable to load ebox for %s", dataset);
		goto done;
	}

	ret = get_ebox_common(zhp, eboxp);

done:
	if (zhp != NULL)
		zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	return (ret);
}

static errf_t *
put_ebox_common(zfs_handle_t *restrict zhp, struct ebox *restrict ebox)
{
	errf_t *ret = ERRF_OK;
	char *str = NULL;
	nvlist_t *prop = NULL;

	if ((ret = envlist_alloc(&prop)) != ERRF_OK ||
	    (ret = ebox_to_str(ebox, &str)) != ERRF_OK ||
	    (ret = envlist_add_string(prop, BOX_PROP, str)) != ERRF_OK) {
		ret = errf("EBoxError", ret, "unable serialize ebox for %s",
		    zfs_get_name(zhp));
	    goto done;
	}

	if ((ret = ezfs_prop_set_list(zhp, prop)) != ERRF_OK) {
		ret = errf("EBoxError", ret, "unable to save ebox for %s",
		    zfs_get_name(zhp));
	}

done:
	nvlist_free(prop);
	free(str);
	return (ret);
}

errf_t *
kbmd_put_ebox(struct ebox *ebox)
{
	errf_t *ret = ERRF_OK;
	const char *dsname = ebox_private(ebox);
	zfs_handle_t *zhp = NULL;

	VERIFY3P(dsname, !=, NULL);

	mutex_enter(&g_zfs_lock);

	if ((ret = ezfs_open(g_zfs, dsname,
	    ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME, &zhp)) != ERRF_OK) {
		ret = errf("EBoxError", ret,
		    "unable to save ebox for %s", dsname);
		goto done;
	}

	ret = put_ebox_common(zhp, ebox);

done:
	if (zhp != NULL)
		zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	return (ret);
}

/*
 * For operations requiring a pin, if the token has not already been
 * authenticated, retrieve the pin and authenticate.
 */
errf_t *
kbmd_assert_pin(struct piv_token *pk)
{
	errf_t *ret = ERRF_OK;
	custr_t *pin = NULL;
	enum piv_pin pin_auth;

	/*
	 * There's no way to assert this, but it's also assumed that
	 * piv_select(pk) has been performed prior to the call to
	 * kbmd_assert_pin().
	 */
	ASSERT(piv_token_in_txn(pk));

	pin_auth = piv_token_default_auth(pk);

	(void) bunyan_debug(tlog, "Checking pin status of PIV",
	    BUNYAN_T_STRING, "token", piv_token_guid_hex(pk),
	    BUNYAN_T_STRING, "default_auth", piv_pin_str(pin_auth),
	    BUNYAN_T_END);

#if 0
	/*
	 * Determine if we're already authed, if so just return ok.
	 */
	if ((ret = piv_verify_pin(pk, pin_auth, NULL, NULL,
	    B_TRUE)) == ERRF_OK) {
		(void) bunyan_debug(tlog,
		    "PIV already authenticated, pin re-entry not needed",
		    BUNYAN_T_STRING, "token", piv_token_guid_hex(pk),
		    BUNYAN_T_STRING, "default_auth", piv_pin_str(pin_auth),
		    BUNYAN_T_END);
		return (ERRF_OK);
	}
#endif

	/*
	 * If it's the system pin, and we already have the cached pin,
	 * try that.
	 */
	if (IS_SYSTEM_TOKEN(pk) && kpiv->kt_pin != NULL) {
		ASSERT(MUTEX_HELD(&piv_lock));

		if ((ret = piv_verify_pin(pk, pin_auth, kpiv->kt_pin, NULL,
		    B_TRUE)) == ERRF_OK)
			return (ret);
	}

	/*
	 * Otherwise, retrieve the pin and unlock.
	 */
	if ((ret = kbmd_get_pin(piv_token_guid(pk), &pin)) != ERRF_OK)
		return (ret);

	/*
	 * The error message on failure includes the retry count, so we
	 * don't need to retrieve it again for error reporting.
	 */
	ret = piv_verify_pin(pk, pin_auth, custr_cstr(pin), NULL, B_TRUE);

	if (IS_SYSTEM_TOKEN(pk) && ret == ERRF_OK) {
		/*
		 * If we get here, we're updating the system PIV token and
		 * we either didn't cache the pin, or the cached value was
		 * wrong.  Either way update the pin.
		 */
		VERIFY3U(custr_len(pin), <, sizeof (kpiv->kt_pin));
		explicit_bzero(kpiv->kt_pin, sizeof (kpiv->kt_pin));
		bcopy(custr_cstr(pin), kpiv->kt_pin, custr_len(pin));
	}

	custr_free(pin);
	return (ret);
}

errf_t *
auth_card(struct piv_token *restrict token, struct sshkey *restrict cak)
{
	struct piv_slot *cakslot;
	errf_t *ret = ERRF_OK;

	ASSERT(piv_token_in_txn(token));

	if (cak == NULL)
		return (ERRF_OK);

	if ((cakslot = piv_get_slot(token, PIV_SLOT_CARD_AUTH)) == NULL) {
		if ((ret = piv_read_cert(token,
		    PIV_SLOT_CARD_AUTH)) != ERRF_OK) {
			return (errf("CardAuthenticationError", ret,
			    "Failed to validate Card Authentication "
			    "Key (CAK)"));
		}

		cakslot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
	}

	if (cakslot == NULL) {
		return (errf("CardAuthenticationError", NULL,
		    "Falied to validate Card Authentication Key (CAK)"));
	}

	return (piv_auth_key(token, cakslot, cak));
}

static errf_t *
local_unlock(struct piv_ecdh_box *box, struct sshkey *cak, const char *name)
{
	struct piv_token *tokens = NULL, *token = NULL;
	struct piv_slot *slot;
	errf_t *ret = ERRF_OK;

	(void) bunyan_debug(tlog, "Trying part",
	    BUNYAN_T_STRING, "partname", name,
	    BUNYAN_T_END);

	if (!piv_box_has_guidslot(box)) {
		return (errf("NoGUIDSlot", NULL, "box does not have GUID "
		    "and slot information, can't unlock with local hardware"));
	}

	mutex_enter(&piv_lock);

	/*
	 * The following code might seem a bit redundant -- we could just
	 * call piv_enumerate() to obtain a list of all present tokens and
	 * pass the results to piv_box_find_token() to locate the
	 * toke needed to unlock the box.  However, piv_enumerate() loads a
	 * lot of information (discovery object, history keys, etc.) for
	 * each token found -- all through a relatively slow communication
	 * channel
	 *
	 * In the common case, we know the GUID of the token we need.  As
	 * an optimization, we first try piv_find() which only loads the
	 * information for the matching token (if found).  If we cannot
	 * locate the required token by its GUID, only then do we use
	 * piv_enumerate() to load all of the present tokens.
	 * piv_box_find_token() will then search the list of tokens
	 * passed to it for a matching token.  In the common case the list
	 * will  be a single entry list with the token we alraedy know has
	 * a matching GUID.  In the fallback case, it will be a list of all
	 * tokens present on the system.  When piv_box_find_token() cannot
	 * find the token by GUID, it will then search the passed-in list of
	 * piv tokens for one with a matching 9D key.  If a matching token is
	 * found, piv_box_find_token() then loads the correct slot needed to
	 * unlock the given box.
	 */
	if ((ret = piv_find(piv_ctx, piv_box_guid(box), GUID_LEN,
	    &tokens)) != ERRF_OK) {
		if (!errf_caused_by(ret, "NotFoundError")) {
			ret = errf("LocalUnlockError", ret,
			    "failed to find token for box %s", name);
			goto done;
		}
		erfree(ret);
		if ((ret = piv_enumerate(piv_ctx, &tokens)) != ERRF_OK) {
			ret = errf("LocalUnlockError", ret,
			    "failed to find token for box %s", name);
			goto done;
		}
	}

	if ((ret = piv_box_find_token(tokens, box, &token, &slot)) != ERRF_OK) {
		ret = errf("LocalUnlockError", ret,
		    "failed to find token for box %s", name);
		goto done;
	}

	(void) bunyan_debug(tlog, "Found token",
	    BUNYAN_T_STRING, "guid", piv_token_guid_hex(token),
	    BUNYAN_T_END);

	if ((ret = piv_txn_begin(token)) != ERRF_OK ||
	    (ret = piv_select(token)) != ERRF_OK ||
	    (ret = auth_card(token, cak)) != ERRF_OK ||
	    (ret = kbmd_assert_pin(token)) != ERRF_OK) {
		ret = errf("LocalUnlockError", ret,
		    "failed to unlock piv token for box %s", name);
		goto done;
	}

	/*
	 * On failure, we'll end up printing out the errf_t chain
	 * when we return, so don't worry about that here.
	 */
	if ((ret = piv_box_open(token, slot, box)) == ERRF_OK)
		(void) bunyan_debug(tlog, "Unlock successful", BUNYAN_T_END);

done:
	if (token != NULL && piv_token_in_txn(token))
		piv_txn_end(token);

	piv_release(tokens);
	mutex_exit(&piv_lock);
	return (ret);
}

errf_t *
kbmd_unlock_ebox(struct ebox *ebox)
{
	struct ebox_config *config = NULL;
	struct ebox_part *part = NULL;
	struct ebox_tpl_part *tpart = NULL;
	struct ebox_tpl_config *tconfig = NULL;
	errf_t *ret = ERRF_OK;

	while ((config = ebox_next_config(ebox, config)) != NULL) {
		tconfig = ebox_config_tpl(config);
		if (ebox_tpl_config_type(tconfig) != EBOX_PRIMARY)
			continue;

		part = ebox_config_next_part(config, NULL);
		tpart = ebox_part_tpl(part);
		ret = local_unlock(ebox_part_box(part),
		    ebox_tpl_part_cak(tpart), ebox_tpl_part_name(tpart));
		if (ret != ERRF_OK && !errf_caused_by(ret, "NotFoundError")) {
			return (errf("UnlockError", ret,
			    "Failed to unlock ebox for %s dataset",
			    ebox_private(ebox)));
		}
		if (ret != ERRF_OK) {
			erfree(ret);
			continue;
		}

		return (ebox_unlock(ebox, config));
	}

	return (errf("NeedRecovery", ret,
	    "Cannot unlock box for %s; recovery is required",
	    ebox_private(ebox)));
}
