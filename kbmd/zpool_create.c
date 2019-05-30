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
#include <libnvpair.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include "common.h"
#include "envlist.h"
#include "errf.h"
#include "kbm.h"
#include "kbmd.h"
#include "kspawn.h"
#include "pivy/ebox.h"
#include "pivy/libssh/sshbuf.h"

static size_t zfs_key_len = 32; /* bytes */

static errf_t *
add_opt(nvlist_t **nvl, const char *name, const char *val)
{
	errf_t *ret = ERRF_OK;

	if ((ret = envlist_alloc(nvl)) != ERRF_OK ||
	    (ret = envlist_add_string(*nvl, "option", name)) != ERRF_OK ||
	    (ret = envlist_add_string(*nvl, "value", val)) != ERRF_OK) {
		nvlist_free(*nvl);
	    }

	return (ret);
}

static errf_t *
add_create_options(nvlist_t *nvl, struct ebox *ebox)
{
	static struct {
		const char *option;
		const char *val;
	} encrypt_opts[] = {
		{ "encryption", "on" },
		{ "keyformat", "raw" },
		{ "keylocation", "prompt" }
	};

	/* encrypt_ops + box */
	nvlist_t *args[ARRAY_SIZE(encrypt_opts) + 1] = { 0 };
	errf_t *ret = ERRF_OK;
	char *eboxstr = NULL;
	size_t i = 0;

	if ((ret = ebox_to_str(ebox, &eboxstr)) != ERRF_OK)
		goto done;

	for (i = 0; i < ARRAY_SIZE(encrypt_opts); i++) {
		if ((ret = add_opt(&args[i], encrypt_opts[i].option,
		    encrypt_opts[i].val)) != ERRF_OK) {
			goto done;
		}
	}

	if ((ret = add_opt(&args[i], BOX_PROP, eboxstr)) != ERRF_OK)
		goto done;

	ret = envlist_add_nvlist_array(nvl, KBM_NV_CREATE_ARGS, args,
	    (uint_t)ARRAY_SIZE(args));

done:
	for (size_t i = 0; i < ARRAY_SIZE(args); i++)
		nvlist_free(args[i]);
	freezero(eboxstr, strlen(eboxstr));
	return (ret);
}

static errf_t *
add_key(nvlist_t *nvl, const uint8_t *key, size_t keylen)
{
	return (envlist_add_uint8_array(nvl, KBM_NV_ZPOOL_KEY,
	    (uint8_t *)key, keylen));
}

static errf_t *
add_create_data(nvlist_t *restrict resp, struct ebox *restrict ebox,
    const uint8_t *restrict key, size_t keylen)
{
	errf_t *ret = ERRF_OK;

	if ((ret = add_create_options(resp, ebox)) != ERRF_OK)
		return (ret);
	return (add_key(resp, key, keylen));
}

/*
 * XXX: Until we integrate the gossip protocol, create a template with
 * just a primary config (from the given token).
 */
static errf_t *
get_template(struct piv_token *restrict pk,
    struct ebox_tpl **restrict tplp)
{
	errf_t *ret = ERRF_OK;
	struct piv_slot *slot = NULL;
	struct ebox_tpl *tpl = NULL;
	struct ebox_tpl_config *pri_cfg = NULL;
	struct ebox_tpl_part *pri_part = NULL;

	if ((tpl = ebox_tpl_alloc()) == NULL) {
		ret = errfno("ebox_tpl_alloc", errno, "creating template");
		goto done;
	}

	if ((pri_cfg = ebox_tpl_config_alloc(EBOX_PRIMARY)) == NULL) {
		ret = errfno("ebox_tpl_config_alloc", errno,
		    "creating template");
		goto done;
	}

	if ((ret = piv_txn_begin(pk)) != ERRF_OK)
		goto done;

	if ((ret = piv_select(pk)) != ERRF_OK)
		goto done;

	if ((slot = piv_get_slot(pk, PIV_SLOT_PIV_AUTH)) == NULL) {
		ret = errf("SlotError", NULL, "piv_get_slot(%02X) failed",
		    PIV_SLOT_PIV_AUTH);
		goto done;
	}

	if ((pri_part = ebox_tpl_part_alloc(piv_token_guid(pk), GUID_LEN,
	    PIV_SLOT_PIV_AUTH, piv_slot_pubkey(slot))) == NULL) {
		ret = errfno("ebox_tpl_part_alloc", errno, "creating template");
		goto done;
	}

	if ((slot = piv_get_slot(pk, PIV_SLOT_CARD_AUTH)) == NULL) {
		ret = errf("SlotError", NULL, "piv_get_slot(%02X) failed",
		    PIV_SLOT_CARD_AUTH);
		goto done;
	}
	ebox_tpl_part_set_cak(pri_part, piv_slot_pubkey(slot));

	/*
	 * XXX: We can also set a name for this template part, is there any
	 * useful/meaningful value that could be used?
	 */

	ebox_tpl_config_add_part(pri_cfg, pri_part);
	ebox_tpl_add_config(tpl, pri_cfg);
	*tplp = tpl;

done:
	if (piv_token_in_txn(pk))
		piv_txn_end(pk);

	if (ret != ERRF_OK) {
		ebox_tpl_part_free(pri_part);
		ebox_tpl_config_free(pri_cfg);
		ebox_tpl_free(tpl);
	}
	return (ret);
}

/*
 * For testing -- if kbmadm includes a template, merge in all the EBOX_RECOVERY
 * configs into tpl
 */
static void
get_supplied_template(nvlist_t *restrict nvl, struct ebox_tpl *restrict tpl)
{
	errf_t *ret;
	struct ebox_tpl *utpl = NULL;
	struct ebox_tpl_config *tconfig = NULL, *newcfg = NULL;
	struct ebox_tpl_part *tpart = NULL, *newpart = NULL;
	struct sshbuf *buf = NULL;
	uint8_t *tbytes = NULL;
	uint_t tlen = 0;

	if (nvlist_lookup_uint8_array(nvl, KBM_NV_TEMPLATE, &tbytes,
	    &tlen) != 0)
		return;

	/*
	 * This function is just for testing, if we fail, we just act
	 * like the template isn't there.
	 */
	if ((buf = sshbuf_from(tbytes, tlen)) == NULL)
		return;

	if ((ret = sshbuf_get_ebox_tpl(buf, &utpl)) != ERRF_OK)
		goto done;

	while ((tconfig = ebox_tpl_next_config(utpl, tconfig)) != NULL) {
		if (ebox_tpl_config_type(tconfig) != EBOX_RECOVERY)
			continue;

		newcfg = ebox_tpl_config_alloc(EBOX_RECOVERY);
		if (newcfg == NULL)
			goto done;

		if ((ret = ebox_tpl_config_set_n(newcfg,
		    ebox_tpl_config_n(tconfig))) != ERRF_OK)
			goto done;

		tpart = NULL;
		while ((tpart = ebox_tpl_config_next_part(tconfig,
		    tpart)) != NULL) {
			const char *name = ebox_tpl_part_name(tpart);
			struct sshkey *cak = ebox_tpl_part_cak(tpart);

			newpart = ebox_tpl_part_alloc(ebox_tpl_part_guid(tpart),
			    GUID_LEN, ebox_tpl_part_slot(tpart),
			    ebox_tpl_part_pubkey(tpart));
			if (newpart == NULL)
				goto done;

			if (name != NULL)
				ebox_tpl_part_set_name(newpart, name);
			if (cak != NULL)
				ebox_tpl_part_set_cak(newpart, cak);

			ebox_tpl_config_add_part(newcfg, newpart);
			newpart = NULL;
		}

		ebox_tpl_add_config(tpl, newcfg);
		newcfg = NULL;
	}

done:
	sshbuf_free(buf);
	ebox_tpl_part_free(newpart);
	ebox_tpl_config_free(newcfg);
	ebox_tpl_free(utpl);
}

/*
 * Verify we have a token to use.  Normally we'll setup a new PIV token and
 * return that.  For debugging and testing purposes, we allow kbmadm to
 * supply a PIV token GUID and recovery token which we can use instead.
 */
static errf_t *
assert_token(nvlist_t *restrict req, struct piv_token **restrict pkp,
   uint8_t **restrict recovery_token, size_t *restrict recovery_len)
{
	errf_t *ret;
	uint8_t *guid = NULL;
	uint_t guidlen = 0, len = 0;

	if (nvlist_lookup_uint8_array(req, KBM_NV_GUID, &guid, &guidlen) != 0 ||
	    nvlist_lookup_uint8_array(req, "recovery_token", recovery_token,
	    &len) != 0) {
		return (kbmd_setup_token(pkp, recovery_token, recovery_len));
	}

	if ((ret = piv_find(piv_ctx, guid, guidlen, pkp)) != ERRF_OK)
		return (ret);

	*recovery_len = len;
	return (ERRF_OK);
}

void
kbmd_zpool_create(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;
	struct ebox_tpl *tpl = NULL;
	struct ebox *ebox = NULL;
	struct piv_token *pk = NULL;
	uint8_t *key = NULL, *recovery_token = NULL;
	size_t keylen = 0, recovery_token_len = 0;

	(void) bunyan_debug(tlog, "Received KBM_CMD_ZPOOL_CREATE request",
	    BUNYAN_T_END);

	mutex_enter(&piv_lock);

	if ((ret = envlist_alloc(&resp)) != ERRF_OK)
		goto done;

	if ((key = calloc(1, zfs_key_len)) == NULL) {
		ret = errfno("calloc", errno, "");
		goto done;
	}
	keylen = zfs_key_len;
	arc4random_buf(key, keylen);

	if ((ret = assert_token(req, &pk, &recovery_token,
	    &recovery_token_len)) != ERRF_OK ||
	     (ret = kbmd_assert_pin(pk)) != ERRF_OK) {
		goto done;
	}

	if ((ret = get_template(pk, &tpl)) != ERRF_OK)
		goto done;

	/*
	 * XXX: For testing, we allow kbmadm to supply a template that's used
	 * to supply the recovery parts.  We want to remove this once the
	 * gossip protocol is written.
	 */
	get_supplied_template(req, tpl);

	if ((ret = ebox_create(tpl, key, keylen, recovery_token,
	    recovery_token_len, &ebox)) != ERRF_OK)
		goto done;

	if ((ret = add_create_data(resp, ebox, key, keylen)) != ERRF_OK ||
	    (ret = envlist_add_boolean_value(resp, KBM_NV_SUCCESS,
	    B_TRUE)) != ERRF_OK)
		goto done;

done:
	mutex_exit(&piv_lock);
	freezero(key, keylen);
	freezero(recovery_token, recovery_token_len);
	nvlist_free(req);
	ebox_tpl_free(tpl);

	if (ret == ERRF_OK) {
		kbmd_ret_nvlist(resp);
	} else {
		nvlist_free(resp);
		kbmd_ret_error(ret);
	}
}
