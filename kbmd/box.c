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
#include <libzfs.h>
#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/libssh/sshbuf.h"
#include "pivy/libssh/ssherr.h"

#include <stdio.h>

struct ebox *sys_box;

static errf_t *
ezfs_open(libzfs_handle_t *hdl, const char *path, int types,
    zfs_handle_t **zhpp)
{
	if ((*zhpp = zfs_open(hdl, path, types)) != NULL)
		return (ERRF_OK);

	return (errf("ZFSError", NULL, "unable to open %s: %s", path,
	    libzfs_error_description(hdl)));
}

static errf_t *
ezfs_prop_set_list(zfs_handle_t *zhp, nvlist_t *prop)
{
	if (zfs_prop_set_list(zhp, prop) == 0)
		return (ERRF_OK);

	return (errf("ZFSError", NULL, "zfs_prop_set_list on %s failed: %s",
	    zfs_get_name(zhp),
	    libzfs_error_description(zfs_get_handle(zhp))));
}

static errf_t *
ezfs_prop_inherit(zfs_handle_t *zhp, const char *propname)
{
	if (zfs_prop_inherit(zhp, propname, B_FALSE) == 0)
		return (ERRF_OK);

	return (errf("ZFSError", NULL,
	    "zfs_prop_inherit(%s) on %s failed: %s",
	    propname, zfs_get_name(zhp),
	    libzfs_error_description(zfs_get_handle(zhp))));
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

errf_t *
set_box_name(struct ebox *restrict ebox, const char *name)
{
	size_t len = strlen(name) + 1;
	char *str = ebox_alloc_private(ebox, len);

	if (str == NULL) {
		return (errfno("ebox_alloc_private", errno,
		    "Unable to set name '%s' on ebox", name));
	}

	bcopy(name, str, len);
	return (ERRF_OK);
}

/*
 * With libzfs, each property is stored as its own nvlist, with the 'value'
 * name containing the value of the property.
 */
static errf_t *
get_property_str(nvlist_t *restrict proplist, const char *propname,
    char **restrict sp)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *val = NULL;

	if ((ret = envlist_lookup_nvlist(proplist, propname, &val)) != ERRF_OK)
		return (ret);

	return (envlist_lookup_string(val, "value", sp));
}

static errf_t *
get_ebox_string(zfs_handle_t *restrict zhp, char **restrict sp)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *uprops = NULL;

	uprops = zfs_get_user_props(zhp);

	if ((ret = get_property_str(uprops, BOX_NEWPROP, sp)) == ERRF_OK ||
	    !errf_caused_by(ret, "ENOENT"))
		return (ret);

	if ((ret = get_property_str(uprops, BOX_PROP, sp)) == ERRF_OK ||
	    !errf_caused_by(ret, "ENOENT"))
		return (ret);

	return (errf("NotFoundError", ret,
	    "dataset %s does not contain an ebox", zfs_get_name(zhp)));
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
	    (ret = set_box_name(ebox, dataset)) != ERRF_OK)
		return (ret);

	*eboxp = ebox;
	return (ERRF_OK);
}

errf_t *
kbmd_get_ebox(const char *dataset, struct ebox **eboxp)
{
	zfs_handle_t *zhp = NULL;
	errf_t *ret = ERRF_OK;

	if (sys_box != NULL && strcmp(ebox_private(sys_box), dataset) == 0) {
		*eboxp = sys_box;
		return (ERRF_OK);
	}

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
put_ebox_common(zfs_handle_t *restrict zhp, const char *propname,
    struct ebox *restrict ebox)
{
	errf_t *ret = ERRF_OK;
	char *str = NULL;
	nvlist_t *prop = NULL;

	if ((ret = envlist_alloc(&prop)) != ERRF_OK ||
	    (ret = ebox_to_str(ebox, &str)) != ERRF_OK ||
	    (ret = envlist_add_string(prop, propname, str)) != ERRF_OK) {
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

	ret = put_ebox_common(zhp, BOX_PROP, ebox);

done:
	if (zhp != NULL)
		zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	return (ret);
}


errf_t *
ebox_tpl_foreach_cfg(struct ebox_tpl *tpl, ebox_tpl_cb_t cb, void *arg)
{
	errf_t *ret = ERRF_OK;
	struct ebox_tpl_config *cfg = NULL, *next = NULL;

	for (cfg = ebox_tpl_next_config(tpl, NULL); cfg != NULL; cfg = next) {
		next = ebox_tpl_next_config(tpl, cfg);
		if ((ret = cb(tpl, cfg, arg)) != ERRF_OK)
			return (ret);
	}

	return (ERRF_OK);
}

/*
 * Creates the ebox template config for the given PIV token
 */
errf_t *
create_piv_tpl_config(kbmd_token_t *restrict kt,
    struct ebox_tpl_config **restrict cfgp)
{
	errf_t *ret = ERRF_OK;
	struct piv_token *pk = kt->kt_piv;
	struct piv_slot *slot = NULL;
	struct piv_slot *auth_slot = NULL;
	struct ebox_tpl_config *cfg = NULL;
	struct ebox_tpl_part *part = NULL;

	VERIFY(piv_token_in_txn(pk));

	if ((ret = kbmd_get_slot(kt, PIV_SLOT_KEY_MGMT, &slot)) != ERRF_OK) {
		return (errf("TemplateError", ret,
		    "cannot read PIV %02X token slot", PIV_SLOT_KEY_MGMT));
	}

	if ((ret = kbmd_get_slot(kt, PIV_SLOT_CARD_AUTH,
	    &auth_slot)) != ERRF_OK) {
		return (errf("TemplateError", ret,
		    "cannot read PIV %02X token slot", PIV_SLOT_CARD_AUTH));
	}

	if ((cfg = ebox_tpl_config_alloc(EBOX_PRIMARY)) == NULL) {
		ret = errfno("ebox_tpl_config_alloc", errno,
		    "cannot create primary ebox config template");
		ret = errf("TemplateError", ret, "");
		goto fail;
	}

	if ((part = ebox_tpl_part_alloc(piv_token_guid(pk), GUID_LEN,
	    PIV_SLOT_KEY_MGMT, piv_slot_pubkey(slot))) == NULL) {
		ret = errfno("ebox_tpl_part_alloc", errno,
		    "cannot create primary ebox config template part");
		ret = errf("TemplateError", ret, "");
		goto fail;
	}

	ebox_tpl_part_set_cak(part, piv_slot_pubkey(auth_slot));

	/*
	 * XXX: We can set a name for this part.  Is there any useful/
	 * meaningful value that could be used?
	 */

	ebox_tpl_config_add_part(cfg, part);
	*cfgp = cfg;
	return (ERRF_OK);

fail:
	ebox_tpl_part_free(part);
	ebox_tpl_config_free(cfg);
	*cfgp = NULL;
	return (ret);
}

/*
 * Place the key from src ebox (unlocked prior to calling) into a
 * new ebox w/ a new template
 */
errf_t *
kbmd_ebox_clone(struct ebox *restrict src, struct ebox **restrict dstp,
    struct ebox_tpl *restrict tpl, kbmd_token_t *restrict kt)
{
	errf_t *ret = ERRF_OK;
	struct ebox *ebox = NULL;
	const char *name = NULL;
	const uint8_t *key = NULL;
       	uint8_t *rtoken = NULL;
	size_t keylen = 0, rtokenlen = 0;

	VERIFY(MUTEX_HELD(&piv_lock));

	VERIFY3P(key = ebox_key(src, &keylen), !=, NULL);
	name = ebox_private(src);

	if ((ret = kbmd_new_recovery_token(kt, &rtoken, &rtokenlen)) != ERRF_OK)
		return (ret);

	if ((ret = ebox_create(tpl, key, keylen, rtoken, rtokenlen,
	    &ebox)) != ERRF_OK)
		return (ret);

	if ((ret = set_box_name(ebox, name)) != ERRF_OK) {
		ebox_free(ebox);
		return (ret);
	}

	*dstp = ebox;
	return (ERRF_OK);
}

static errf_t *
find_part_pivtoken(struct ebox_part *part, kbmd_token_t **ktp)
{
	errf_t *ret = ERRF_OK;
	struct piv_ecdh_box *box = ebox_part_box(part);
	const uint8_t *guid = piv_box_guid(box);
	const struct sshkey *pubkey = piv_box_pubkey(box);
	struct ebox_tpl_part *tpart = ebox_part_tpl(part);
	enum piv_slotid slotid = piv_box_slot(box);

	(void) bunyan_debug(tlog, "Searching for pivtoken for ebox part",
	    BUNYAN_T_STRING, "box_part_name", ebox_tpl_part_name(tpart),
	    BUNYAN_T_STRING, "box_guid", piv_box_guid_hex(box),
	    BUNYAN_T_END);

	if (!piv_box_has_guidslot(box)) {
		return (errf("NoGUIDSlot", NULL, "box does not have GUID "
		    "and slot information, can't unlock with local hardware"));
	}

	if ((ret = kbmd_find_byguid(guid, GUID_LEN, ktp)) != ERRF_OK ||
	    (ret = kbmd_find_byslot(slotid, pubkey, ktp)) != ERRF_OK) {
		return (errf("NotFoundError", ret,
		    "Unable to find PIV token for piv box"));
	}

	return (ERRF_OK);
}

errf_t *
kbmd_unlock_ebox(struct ebox *restrict ebox, kbmd_token_t **restrict ktp)
{
	errf_t *ret = ERRF_OK;
	struct ebox_config *config = NULL;
	struct ebox_part *part = NULL;
	kbmd_token_t *kt = NULL;
	const char *boxname;

	VERIFY(MUTEX_HELD(&piv_lock));

	*ktp = NULL;
	if ((boxname = ebox_private(ebox)) == NULL)
		boxname = "(not set)";

	(void) bunyan_debug(tlog, "Attempting to unlock ebox",
	    BUNYAN_T_STRING, "eboxname", boxname,
	    BUNYAN_T_END);

	while ((config = ebox_next_config(ebox, config)) != NULL) {
		struct ebox_tpl_config *tconfig = NULL;
		struct ebox_tpl_part *tpart = NULL;
		const char *tname = NULL;
		struct sshkey *cak = NULL;
		struct piv_slot *slot = NULL;
		struct piv_ecdh_box *dhbox = NULL;

		tconfig = ebox_config_tpl(config);
		if (ebox_tpl_config_type(tconfig) != EBOX_PRIMARY)
			continue;

		part = ebox_config_next_part(config, NULL);
		tpart = ebox_part_tpl(part);
		if (tpart != NULL) {
			tname = ebox_tpl_part_name(tpart);
		}

		if (tname == NULL) {
			tname = "(not set)";
		}

		dhbox = ebox_part_box(part);

		if (!piv_box_has_guidslot(dhbox)) {
			(void) bunyan_debug(tlog,
			    "Ebox config part does not have GUID; skipping",
			    BUNYAN_T_STRING, "partname", tname,
			    BUNYAN_T_END);
			continue;
		}

		(void) bunyan_debug(tlog, "Trying part",
		    BUNYAN_T_STRING, "partname", tname,
		    BUNYAN_T_END);

		if (kt != NULL &&
		    bcmp(piv_token_guid(kt->kt_piv), piv_box_guid(dhbox),
		    GUID_LEN) != 0) {
			if (kt != kpiv)
				kbmd_token_free(kt);
			kt = NULL;

			(void) bunyan_key_remove(tlog, "piv_guid");
		}

		if (kt == NULL &&
		    (ret = find_part_pivtoken(part, &kt)) != ERRF_OK) {
			if (kt != kpiv)
				kbmd_token_free(kt);

			if (errf_caused_by(ret, "NotFoundError")) {
				errf_free(ret);

				(void) bunyan_debug(tlog,
				    "PIV token not present for part; trying "
				    "next part",
				    BUNYAN_T_STRING, "partname", tname,
				    BUNYAN_T_END);
				continue;
			}

			(void) bunyan_debug(tlog,
			    "Fatal failure finding PIV token for part",
			    BUNYAN_T_STRING, "partname", tname,
			    BUNYAN_T_END);

			return (ret);
		}
		VERIFY3P(kt, !=, NULL);
		VERIFY3P(kt->kt_piv, !=, NULL);

		(void) bunyan_key_add(tlog,
		    "piv_guid", BUNYAN_T_STRING,
		    piv_token_guid_hex(kt->kt_piv));

		(void) bunyan_debug(tlog, "Found PIV token for part",
		    BUNYAN_T_STRING, "partname", tname,
		    BUNYAN_T_END);

		cak = ebox_tpl_part_cak(tpart);

		(void) bunyan_debug(tlog, "Attempt to unlock PIV token",
		    BUNYAN_T_END);

		/*
		 * kbmd_assert_pin() may need to call a plugin to obtain
		 * the PIN.  Because the plugin itself may need to use
		 * the PIV token (e.g. using the CAK to authenticate a
		 * KBMAPI request), we must do this prior to starting
		 * the PIV transaction.
		 */
		if ((ret = kbmd_assert_pin(kt)) != ERRF_OK) {
			(void) bunyan_info(tlog,
			    "Failed to obtain PIV token pin",
			    BUNYAN_T_END);

			(void) bunyan_key_remove(tlog, "piv_guid");
			continue;
		}

		if ((ret = piv_txn_begin(kt->kt_piv)) != ERRF_OK ||
		    (ret = piv_select(kt->kt_piv)) != ERRF_OK ||
		    (ret = kbmd_auth_pivtoken(kt, cak)) != ERRF_OK ||
		    (ret = kbmd_verify_pin(kt)) != ERRF_OK) {
			piv_txn_end(kt->kt_piv);

			(void) bunyan_debug(tlog, "Unlock failed",
			    BUNYAN_T_END);

			(void) bunyan_key_remove(tlog, "piv_guid");
			continue;
		}

		if ((ret = kbmd_get_slot(kt, piv_box_slot(dhbox),
		    &slot)) != ERRF_OK) {
			piv_txn_end(kt->kt_piv);

			char slotstr[3] = { 0 };
			(void) snprintf(slotstr, sizeof (slotstr), "%02X",
			    piv_box_slot(dhbox));
			(void) bunyan_debug(tlog, "Failed to read slot",
			    BUNYAN_T_STRING, "slot", slotstr,
			    BUNYAN_T_END);

			goto done;
		}

		if ((ret = piv_box_open(kt->kt_piv, slot, dhbox)) != ERRF_OK) {
			piv_txn_end(kt->kt_piv);

			(void) bunyan_debug(tlog, "Failed to unlock part",
			    BUNYAN_T_STRING, "partname", tname,
			    BUNYAN_T_STRING, "error", errf_name(ret),
			    BUNYAN_T_STRING, "errmsg", errf_message(ret),
			    BUNYAN_T_STRING, "errfunc", errf_function(ret),
			    BUNYAN_T_END);

			errf_free(ret);
			continue;
		}

		(void) bunyan_debug(tlog, "Part unlocked",
		    BUNYAN_T_STRING, "partname", tname,
		    BUNYAN_T_END);

		piv_txn_end(kt->kt_piv);

		/*
		 * If we successfully unlocked a part, but are still unable
		 * to unlock the ebox that contains the part, we don't want
		 * to try again.
		 */
		if ((ret = ebox_unlock(ebox, config)) == ERRF_OK) {
			(void) bunyan_debug(tlog, "ebox unlocked",
			    BUNYAN_T_STRING, "eboxname", boxname,
			    BUNYAN_T_END);

			*ktp = kt;
		}
		return (ret);
	}

	ret = errf("NeedRecovery", ret,
	    "Cannot unlock box for %s; recovery is required", boxname);

done:
	if (kt != kpiv)
		kbmd_token_free(kt);

	return (ret);
}

/*
 * If both a 'new' and 'old' zfs ebox exist, remove the 'old' config, leaving
 * the 'new' config.  Unlike the soft token eboxes, we don't (won't) have
 * a separate recovery ebox, so we just age out the old config.
 *
 * XXX: Better name?
 */
errf_t *
kbmd_rotate_zfs_ebox(const char *dataset)
{
	errf_t *ret = ERRF_OK;
	zfs_handle_t *zhp = NULL;
	nvlist_t *uprops = NULL;
	nvlist_t *newprops = NULL;
	char *old = NULL, *new = NULL;

	mutex_enter(&g_zfs_lock);

	if ((ret = ezfs_open(g_zfs, dataset,
	    ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME, &zhp)) != ERRF_OK) {
		ret = errf("EBoxError", ret,
		    "unable to consolidate ebox for %s", dataset);
		goto done;
	}

	uprops = zfs_get_user_props(zhp);

	if ((ret = get_property_str(uprops, BOX_NEWPROP, &new)) != ERRF_OK)
		goto done;

	/*
	 * If there is a 'new' ebox, we always want to try to move it to
	 * the 'old' property.  If the 'old' ebox doesn't exist, that's ok,
	 * but some other problem suggests a bigger problem and we abort.
	 */
	if ((ret = get_property_str(uprops, BOX_PROP, &old)) != ERRF_OK &&
	    !errf_caused_by(ret, "ENOENT"))
		goto done;

	/*
	 * Currently, there is no way to do this atomically, so we remove the
	 * old property first, then set the old to the new, then remove the
	 * new so any failure still leaves a valid box.  If zfs channel
	 * programs ever support setting properties, we should consider
	 * altering this to do the change using a channel program so everything
	 * happens in a single TXG.
	 */
	if ((ret = ezfs_prop_inherit(zhp, BOX_PROP)) != ERRF_OK)
		goto done;

	if ((ret = envlist_alloc(&newprops)) != ERRF_OK ||
	    (ret = envlist_add_string(newprops, BOX_PROP, new)) != ERRF_OK ||
	    (ret = ezfs_prop_set_list(zhp, newprops)) != ERRF_OK)
		goto done;

	ret = ezfs_prop_inherit(zhp, BOX_NEWPROP);

done:
	if(zhp != NULL)
		zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	nvlist_free(newprops);
	return (ret);
}

static errf_t *
move_recovery(struct ebox_tpl *tpl, struct ebox_tpl_config *cfg,
    void *arg)
{
	struct ebox_tpl *dst_tpl = arg;

	if (ebox_tpl_config_type(cfg) == EBOX_RECOVERY) {
		(void) bunyan_debug(tlog, "Adding recovery template",
		    BUNYAN_T_END);

		ebox_tpl_remove_config(tpl, cfg);
		ebox_tpl_add_config(dst_tpl, cfg);
	}
	return (ERRF_OK);
}

/*
 * For testing -- if kbmadm includes a template, merge in all the EBOX_RECOVERY
 * configs into tpl
 */
errf_t *
add_supplied_template(nvlist_t *restrict nvl, struct ebox_tpl *restrict tpl,
    boolean_t required)
{
	errf_t *ret = ERRF_OK;
	struct ebox_tpl *reqtpl = NULL;
	struct ebox_tpl_config *cfg = NULL, *nextcfg = NULL;

	/*
	 * This function is just for testing, if we fail, we just act
	 * like the template isn't there.
	 */
	if ((ret = get_request_template(nvl, &reqtpl)) != ERRF_OK) {
		if (required)
			return (ret);
		errf_free(ret);
		return (ERRF_OK);
	}

	ebox_tpl_foreach_cfg(reqtpl, move_recovery, tpl);
	ebox_tpl_free(reqtpl);
	return (ERRF_OK);
}
