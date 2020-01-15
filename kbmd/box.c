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
#include <err.h>
#include <stddef.h>
#include <strings.h>
#include <libzfs.h>
#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/libssh/sshbuf.h"
#include "pivy/libssh/ssherr.h"

#include <stdio.h>

#define	EBOX_KEY_LEN 32

extern const char activate_prog_start;
extern const char add_prog_start;

static const char *add_prog = &add_prog_start;
static const char *activate_prog = &activate_prog_start;

struct ebox *sys_box;

errf_t *
ezfs_open(libzfs_handle_t *hdl, const char *path, int types,
    zfs_handle_t **zhpp)
{
	VERIFY(MUTEX_HELD(&g_zfs_lock));

	if ((*zhpp = zfs_open(hdl, path, types)) != NULL)
		return (ERRF_OK);

	return (errf("ZFSError", NULL, "unable to open %s: %s", path,
	    libzfs_error_description(hdl)));
}

static errf_t *
ezfs_prop_set_list(zfs_handle_t *zhp, nvlist_t *prop)
{
	VERIFY(MUTEX_HELD(&g_zfs_lock));

	if (zfs_prop_set_list(zhp, prop) == 0)
		return (ERRF_OK);

	return (errf("ZFSError", NULL, "zfs_prop_set_list on %s failed: %s",
	    zfs_get_name(zhp),
	    libzfs_error_description(zfs_get_handle(zhp))));
}

static errf_t *
ezfs_prop_inherit(zfs_handle_t *zhp, const char *propname)
{
	VERIFY(MUTEX_HELD(&g_zfs_lock));

	if (zfs_prop_inherit(zhp, propname, B_FALSE) == 0)
		return (ERRF_OK);

	return (errf("ZFSError", NULL,
	    "zfs_prop_inherit(%s) on %s failed: %s",
	    propname, zfs_get_name(zhp),
	    libzfs_error_description(zfs_get_handle(zhp))));
}

/*
 * These match the ZCP default values from sys/zfs.h, and should be
 * sufficient for our purposes.
 */
#define	INSTRLIMIT (10 * 1000 * 1000)
#define	MEMLIMIT (10 * 1024 * 1024)

static errf_t *
run_channel_program(const char *pool, const char *prog, nvlist_t *args,
    nvlist_t **result)
{
	errf_t *ret = ERRF_OK;
	int rc;

	(void) bunyan_trace(tlog, "Running channel program",
	    BUNYAN_T_STRING, "pool", pool,
	    BUNYAN_T_END);

	if ((rc = lzc_channel_program(pool, prog, INSTRLIMIT, MEMLIMIT, args,
	    result)) != 0) {
		char *errmsg = NULL;

		ret = errfno("lzc_channel_program", rc,
		    "error running zfs channel program");

		(void) nvlist_lookup_string(*result, "error", &errmsg);

		(void) bunyan_error(tlog, "Channel program failed",
		    BUNYAN_T_STRING, "pool", pool,
		    BUNYAN_T_INT32, "errno", rc,
		    (errmsg != NULL) ? BUNYAN_T_STRING : BUNYAN_T_END,
		    "errmsg", errmsg,
		    BUNYAN_T_END);
	}

#ifdef DEBUG
	/* XXX: Just for testing */
	flockfile(stderr);
	(void) fprintf(stderr, "Channel program results:\n");
	nvlist_print(stderr, *result);
	funlockfile(stderr);
#endif

	return (ret);
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
get_ebox_string(zfs_handle_t *restrict zhp, boolean_t staged,
    char **restrict sp)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *uprops = NULL;
	const char *propstr = staged ? STAGEBOX_PROP : BOX_PROP;

	uprops = zfs_get_user_props(zhp);

	if ((ret = get_property_str(uprops, propstr, sp)) == ERRF_OK ||
	    !errf_caused_by(ret, "ENOENT"))
		return (ret);

	return (errf("NotFoundError", ret,
	    "dataset %s does not contain an ebox", zfs_get_name(zhp)));
}

errf_t *
get_ebox_common(zfs_handle_t *restrict zhp, boolean_t staged,
    struct ebox **restrict eboxp)
{
	errf_t *ret = ERRF_OK;
	const char *dataset = zfs_get_name(zhp);
	char *str = NULL;
	struct ebox *ebox = NULL;

	VERIFY(MUTEX_HELD(&g_zfs_lock));

	if ((ret = get_ebox_string(zhp, staged, &str)) != ERRF_OK ||
	    (ret = str_to_ebox(dataset, str, &ebox)) != ERRF_OK ||
	    (ret = set_box_name(ebox, dataset)) != ERRF_OK)
		return (ret);

	*eboxp = ebox;
	return (ERRF_OK);
}

errf_t *
kbmd_get_ebox(const char *dataset, boolean_t stage, struct ebox **eboxp)
{
	zfs_handle_t *zhp = NULL;
	errf_t *ret = ERRF_OK;

	*eboxp = NULL;

	(void) bunyan_trace(tlog, "kbmd_get_ebox: enter",
	    BUNYAN_T_STRING, "dataset", dataset,
	    BUNYAN_T_STRING, "stage", stage ? "true" : "false",
	    BUNYAN_T_END);

	VERIFY(MUTEX_HELD(&piv_lock));

	if (!stage && sys_box != NULL &&
	    strcmp(ebox_private(sys_box), dataset) == 0) {
		(void) bunyan_trace(tlog, "using system ebox",
		    BUNYAN_T_END);

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

	ret = get_ebox_common(zhp, stage, eboxp);

done:
	if (zhp != NULL)
		zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	return (ret);
}

static errf_t *
put_ebox_common(zfs_handle_t *restrict zhp, boolean_t stage,
    struct ebox *restrict ebox)
{
	errf_t *ret = ERRF_OK;
	char *str = NULL;
	nvlist_t *prop = NULL;
	const char *propname = stage ? STAGEBOX_PROP : BOX_PROP;

	if ((ret = envlist_alloc(&prop)) != ERRF_OK ||
	    (ret = ebox_to_str(ebox, &str)) != ERRF_OK ||
	    (ret = envlist_add_string(prop, propname, str)) != ERRF_OK) {
		ret = errf("EBoxError", ret, "unable serialize ebox for %s",
		    zfs_get_name(zhp));
	    goto done;
	}

	if ((ret = ezfs_prop_set_list(zhp, prop)) != ERRF_OK) {
		ret = errf("EBoxError", ret,
		    "unable to save ebox for %s", zfs_get_name(zhp));
	}

done:
	nvlist_free(prop);
	free(str);
	return (ret);
}

errf_t *
kbmd_put_ebox(struct ebox *ebox, boolean_t stage)
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

	ret = put_ebox_common(zhp, stage, ebox);

done:
	if (zhp != NULL)
		zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	return (ret);
}

/*
 * These allow for iterating ebox configs and config parts, while allowing
 * for removal of the given config or part during iteration without
 * invalidating the iteration.
 */
errf_t *
ebox_tpl_foreach_part(struct ebox_tpl_config *tcfg, ebox_tpl_part_cb_t cb,
    void *arg)
{
	errf_t *ret = ERRF_OK;
	struct ebox_tpl_part *tpart = NULL, *next = NULL;

	for (tpart = ebox_tpl_config_next_part(tcfg, NULL); tpart != NULL;
	    tpart = next) {
		next = ebox_tpl_config_next_part(tcfg, tpart);
		if ((ret = cb(tpart, arg)) != ERRF_OK) {
			return ((ret == FOREACH_STOP) ? ERRF_OK : ret);
		}
	}

	return (ERRF_OK);
}

errf_t *
ebox_tpl_foreach_cfg(struct ebox_tpl *tpl, ebox_tpl_cb_t cb, void *arg)
{
	errf_t *ret = ERRF_OK;
	struct ebox_tpl_config *cfg = NULL, *next = NULL;

	for (cfg = ebox_tpl_next_config(tpl, NULL); cfg != NULL; cfg = next) {
		next = ebox_tpl_next_config(tpl, cfg);
		if ((ret = cb(cfg, arg)) != ERRF_OK) {
			return ((ret == FOREACH_STOP) ? ERRF_OK : ret);
		}
	}

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

	VERIFY(MUTEX_HELD(&piv_lock));

	(void) bunyan_debug(tlog, "Searching for pivtoken for ebox part",
	    BUNYAN_T_STRING, "box_part_name", ebox_tpl_part_name(tpart),
	    BUNYAN_T_STRING, "box_guid", piv_box_guid_hex(box),
	    BUNYAN_T_END);

	if (!piv_box_has_guidslot(box)) {
		return (errf("NoGUIDSlot", NULL, "box does not have GUID "
		    "and slot information, can't unlock with local hardware"));
	}

	/*
	 * If a system token is set, try that one first
	 */
	if (sys_piv != NULL &&
	    bcmp(piv_token_guid(sys_piv->kt_piv), guid, GUID_LEN) == 0) {
		*ktp = sys_piv;
		return (ERRF_OK);
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
		char gstr[GUID_STR_LEN];

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
		guidtohex(ebox_tpl_part_guid(tpart), gstr, sizeof (gstr));

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
		    BUNYAN_T_STRING, "guid", gstr,
		    BUNYAN_T_END);

		if (kt != NULL &&
		    bcmp(piv_token_guid(kt->kt_piv), piv_box_guid(dhbox),
		    GUID_LEN) != 0) {
			if (kt != sys_piv)
				kbmd_token_free(kt);
			kt = NULL;

			(void) bunyan_key_remove(tlog, "piv_guid");
		}

		if (kt == NULL &&
		    (ret = find_part_pivtoken(part, &kt)) != ERRF_OK) {
			if (kt != sys_piv)
				kbmd_token_free(kt);

			if (errf_caused_by(ret, "NotFoundError")) {
				errf_free(ret);
				ret = ERRF_OK;

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

			goto done;
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

done:
	ret = errf("RecoveryNeeded", ret,
	    "Cannot unlock box for %s; recovery is required", boxname);

	if (kt != sys_piv)
		kbmd_token_free(kt);

	return (ret);
}

/*
 * Creates the ebox template config for the given PIV token
 */
static errf_t *
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
	 * There isn't a meaningful name we can give to this part, so
	 * we leave the name blank.
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

static errf_t *
strip_non_recovery(struct ebox_tpl_config *tcfg, void *arg)
{
	struct ebox_tpl *tpl = arg;

	if (ebox_tpl_config_type(tcfg) != EBOX_RECOVERY)
		ebox_tpl_remove_config(tpl, tcfg);
	return (ERRF_OK);
}

/*
 * Allocate a new ebox template, optionally including any existing
 * recovery configurations from rcfg (if rcfg is not NULL and contains
 * any recovery configs).
 */
static errf_t *
prepare_tpl(const struct ebox_tpl *rcfg, struct ebox_tpl **tplp)
{
	if (rcfg == NULL) {
		*tplp = ebox_tpl_alloc();
		if (*tplp == NULL) {
			return (errf("TemplateError", NULL,
			    "failed to create a new ebox template"));
		}
		return (ERRF_OK);
	}

	*tplp = ebox_tpl_clone((struct ebox_tpl *)rcfg);
	if (*tplp == NULL) {
		return (errf("TemplateError", NULL,
		    "failed to clone recovery config"));
	}

	VERIFY0(ebox_tpl_foreach_cfg(*tplp, strip_non_recovery, *tplp));

	return (ERRF_OK);
}

/*
 * Create an ebox template for the PIV token kt containing the
 * given recovery config rcfg.
 */
errf_t *
create_template(kbmd_token_t *restrict kt, const struct ebox_tpl *rcfg,
    struct ebox_tpl **restrict tplp)
{
	errf_t *ret = ERRF_OK;
	struct ebox_tpl *tpl = NULL;
	struct ebox_tpl_config *cfg =  NULL;

	VERIFY(piv_token_in_txn(kt->kt_piv));
	*tplp = NULL;

	/*
	 * Create a new template with any recovery configs from rcfg
	 * (if present).
	 */
	if ((ret = prepare_tpl(rcfg, &tpl)) != ERRF_OK) {
		return (ret);
	}

	/* Add the EBOX_PRIMARY config for the PIV token kt */
	if ((ret = create_piv_tpl_config(kt, &cfg)) != ERRF_OK) {
		ret = errf("TemplateError", ret, "cannot create ebox template");
		ebox_tpl_free(tpl);
		return (ret);
	}
	ebox_tpl_add_config(tpl, cfg);

	*tplp = tpl;
	return (ERRF_OK);
}

errf_t *
kbmd_create_ebox(kbmd_token_t *restrict kt, const struct ebox_tpl *rcfg,
    const char *name, uint8_t **restrict keyp, size_t *restrict keylenp,
    struct ebox **restrict eboxp)
{
	errf_t *ret = ERRF_OK;
	struct ebox_tpl *tpl = NULL;
	struct ebox *ebox = NULL;
	uint8_t *rtoken = NULL;
	size_t rtokenlen = 0;
	uint8_t key[EBOX_KEY_LEN] = { 0 };

	*eboxp = NULL;

	if ((ret = zalloc(EBOX_KEY_LEN, keyp)) != ERRF_OK) {
		return (ret);
	}
	*keylenp = EBOX_KEY_LEN;

	VERIFY(MUTEX_HELD(&piv_lock));
	VERIFY3P(kt->kt_rtoken.rt_val, !=, NULL);
	VERIFY3U(kt->kt_rtoken.rt_len, >=, RECOVERY_TOKEN_MINLEN);
	VERIFY3U(kt->kt_rtoken.rt_len, <=, RECOVERY_TOKEN_MAXLEN);

	if ((ret = piv_txn_begin(kt->kt_piv)) != ERRF_OK ||
	    (ret = piv_select(kt->kt_piv)) != ERRF_OK ||
	    (ret = create_template(kt, rcfg, &tpl)) != ERRF_OK) {
		goto done;
	}

	arc4random_buf(key, sizeof (key));
	if ((ret = ebox_create(tpl, key, sizeof (key), kt->kt_rtoken.rt_val,
	    kt->kt_rtoken.rt_len, &ebox)) != ERRF_OK) {
		goto done;
	}

	ret = set_box_name(ebox, name);
	bcopy(key, *keyp, EBOX_KEY_LEN);

done:
	if (piv_token_in_txn(kt->kt_piv))
		piv_txn_end(kt->kt_piv);

	explicit_bzero(key, sizeof (key));
	freezero(rtoken, rtokenlen);

	*eboxp = ebox;

	if (ret != ERRF_OK) {
		freezero(*keyp, *keylenp);
		*keyp =  NULL;
		*keylenp =  0;
	}

	return (ERRF_OK);
}

static errf_t *
add_hexkey(nvlist_t *nvl, const char *name, const uint8_t *key, size_t keylen)
{
	errf_t *ret = ERRF_OK;
	size_t keystrlen = keylen * 2 + 1;
	char keystr[keystrlen];

	bzero(keystr, keystrlen);
	tohex(key, keylen, keystr, keystrlen);
	ret = envlist_add_string(nvl, name, keystr);
	explicit_bzero(keystr, keystrlen);
	return (ret);
}

static errf_t *
log_tpl(const struct ebox_tpl *rcfg, boolean_t stage)
{
	errf_t *ret = ERRF_OK;
	uint8_t *hash = NULL;
	size_t hashlen = 0;

	if ((ret = template_hash(rcfg, &hash, &hashlen)) != ERRF_OK) {
		(void) bunyan_error(tlog, "Failed to hash recovery config",
		    BUNYAN_T_END);
		return (ret);
	}

	char hashstr[hashlen * 2 + 1];

	tohex(hash, hashlen, hashstr, hashlen * 2 + 1);

	(void) bunyan_info(tlog, "Adding recovery configuration",
	    BUNYAN_T_STRING, "staged", stage ? "true" : "false",
	    BUNYAN_T_STRING, "hash", hashstr,
	    BUNYAN_T_END);

	free(hash);

	return (ret);
}

errf_t *
add_recovery(const char *dataset, const struct ebox_tpl *rcfg, boolean_t stage,
    const recovery_token_t *rtoken)
{
	errf_t *ret = ERRF_OK;
	kbmd_token_t *kt = NULL;
	struct ebox *ebox = NULL;
	const char *propstr = stage ? STAGEBOX_PROP : BOX_PROP;
	char *eboxstr = NULL;
	nvlist_t *zcp_args = NULL;
	nvlist_t *result = NULL;
	uint8_t *key = NULL;
	size_t keylen = 0;

	if (rcfg == NULL) {
		return (errf("ArgumentError", NULL,
		    "no recovery configuration given"));
	}

	if (rtoken != NULL && !RECOVERY_TOKEN_INRANGE(rtoken)) {
		return (errf("RangeError", NULL,
		    "incorrect recovery token size (%zu) out of range; "
		    "must be at least in range [%u, %u] bytes",
		    rtoken->rt_len,
		    RECOVERY_TOKEN_MINLEN, RECOVERY_TOKEN_MAXLEN));
	}

	if ((ret = log_tpl(rcfg, stage)) != ERRF_OK) {
		return (ret);
	}

	mutex_enter(&piv_lock);

	if (sys_piv == NULL) {
		mutex_exit(&piv_lock);
		return (errf("UnlockError", NULL,
		    "system zpool dataset must be set and unlocked before "
		    "updating its recovery template"));
	}
	kt = sys_piv;

	if (rtoken != NULL) {
		if ((ret = set_piv_rtoken(kt, rtoken)) != ERRF_OK) {
			goto done;
		}
	} else {
		if ((ret = new_recovery_token(kt)) != ERRF_OK)
			goto done;
	}

	if ((ret = kbmd_create_ebox(kt, rcfg, dataset, &key, &keylen,
	    &ebox)) != ERRF_OK ||
	    (ret = ebox_to_str(ebox, &eboxstr)) != ERRF_OK)
		goto done;

	if ((ret = envlist_alloc(&zcp_args)) != ERRF_OK ||
	    (ret = envlist_add_string(zcp_args, "dataset",
	    dataset)) != ERRF_OK ||
	    (ret = envlist_add_string(zcp_args, "prop", propstr)) != ERRF_OK ||
	    (ret = envlist_add_string(zcp_args, "ebox", eboxstr)) != ERRF_OK)
		goto done;

	if (!stage) {
		if ((ret = add_hexkey(zcp_args, "keyhex", key,
		    keylen)) != ERRF_OK) {
			goto done;
		}
	}

	ret = run_channel_program(dataset, add_prog, zcp_args, &result);

done:
	mutex_exit(&piv_lock);
	ebox_free(ebox);
	free(eboxstr);
	nvlist_free(zcp_args);
	nvlist_free(result);
	freezero(key, keylen);

	if (ret == ERRF_OK) {
		ret = post_recovery_config_update();
	}

	return (ret); 
}

errf_t *
activate_recovery(const char *dataset)
{
	errf_t *ret = ERRF_OK;
	kbmd_token_t *kt = NULL;
	struct ebox *ebox = NULL;
	nvlist_t *zcp_args = NULL;
	nvlist_t *result = NULL;
	const uint8_t *key = NULL;
	size_t keylen = 0;

	mutex_enter(&piv_lock);
	if (sys_pool == NULL) {
		mutex_exit(&piv_lock);
		return (errf("NotFoundError", NULL,
		    "system zpool must be set before activating a recovery"
		    "config"));
	}

	if ((ret = kbmd_get_ebox(dataset, B_TRUE, &ebox)) != ERRF_OK ||
	    (ret = kbmd_unlock_ebox(ebox, &kt)) != ERRF_OK)
		goto done;

	key = ebox_key(ebox, &keylen);

	if ((ret = envlist_alloc(&zcp_args)) != ERRF_OK ||
	    (ret = envlist_add_string(zcp_args, "dataset",
	    dataset)) != ERRF_OK ||
	    (ret = envlist_add_string(zcp_args, "ebox", BOX_PROP)) != ERRF_OK ||
	    (ret = envlist_add_string(zcp_args, "stagedebox",
	    STAGEBOX_PROP)) != ERRF_OK ||
	    (ret = add_hexkey(zcp_args, "keyhex", key, keylen)) != ERRF_OK) {
		goto done;
	}

	if ((ret = run_channel_program(dataset, activate_prog, zcp_args,
	    &result)) != ERRF_OK) {
		goto done;
	}

	if (strcmp(dataset, sys_pool) == 0) {
		ebox_free(sys_box);
		sys_box = ebox;
		ebox = NULL;
	}

done:
	if (kt != sys_piv)
		kbmd_token_free(kt);

	mutex_exit(&piv_lock);
	ebox_free(ebox);
	nvlist_free(zcp_args);
	nvlist_free(result);

	if (ret == ERRF_OK) {
		ret = post_recovery_config_update();
	}

	return (ret);
}

errf_t *
remove_recovery(const char *dataset)
{
	errf_t *ret = ERRF_OK;
	zfs_handle_t *zhp = NULL;

	(void) bunyan_trace(tlog, "remove_recovery: enter",
	    BUNYAN_T_END);

	mutex_enter(&piv_lock);

	if (sys_pool == NULL) {
		mutex_exit(&piv_lock);
		return (errf("NotFound", NULL, "system pool is not set"));
	}

	mutex_enter(&g_zfs_lock);

	if ((ret = ezfs_open(g_zfs, dataset,
	    ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME, &zhp)) != ERRF_OK) {
		mutex_exit(&piv_lock);
		ret = errf("EBoxError", ret,
		    "unable to load ebox for %s", sys_pool);
		goto done;
	}

	mutex_exit(&piv_lock);

	if ((ret = ezfs_prop_inherit(zhp, STAGEBOX_PROP)) != ERRF_OK) {
		goto done;
		/*
		 * XXX: figure out what is returned when it doesn't exist, and
		 * convert to non error
		 */
	}

	ret = post_recovery_config_update();

done:
	if (zhp != NULL)
		zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	return (ret);
}
