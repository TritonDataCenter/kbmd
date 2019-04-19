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
#include <stdio.h>
#include <strings.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/libssh/sshbuf.h"

/*
 * If the PIV token registration fails, we cache the otherwise fully setup
 * PIV token, and allow a subsequent zpool create command to just pick up
 * where it left off and retry the registration step. Protected by piv_lock.
 */
static kbmd_token_t *incomplete_tok;

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

static errf_t *
try_guid(const uint8_t *guid, const recovery_token_t *rtoken,
    kbmd_token_t **restrict ktp)
{
	errf_t *ret = ERRF_OK;
	kbmd_token_t *kt = NULL;

	ASSERT(MUTEX_HELD(&piv_lock));

	if (guid == NULL)
		return (ret);

	if ((ret = kbmd_find_byguid(guid, GUID_LEN, &kt)) != ERRF_OK)
		return (ret);

	if ((ret = set_piv_rtoken(kt, rtoken)) != ERRF_OK) {
		kbmd_token_free(kt);
		return (ret);
	}

	(void) bunyan_debug(tlog, "Using supplied PIV token",
	    BUNYAN_T_STRING, "token", piv_token_guid_hex(kt->kt_piv),
	    BUNYAN_T_END);

	return (ERRF_OK);
}

static boolean_t
try_sys_piv(const uint8_t *guid, const recovery_token_t *rtoken)
{
	errf_t *ret = ERRF_OK;
	const uint8_t *sys_piv_guid = NULL;
	char gstr[GUID_STR_LEN] = { 0 };

	if (guid != NULL) {
		guidtohex(guid, gstr, sizeof (gstr));
	} else {
		(void) strlcpy(gstr, "(not set)", sizeof (gstr));
	}

	(void) bunyan_trace(tlog, "try_sys_piv: enter",
	    BUNYAN_T_STRING, "guid", gstr,
	    BUNYAN_T_END);

	ASSERT(MUTEX_HELD(&piv_lock));

	if (sys_piv == NULL || guid == NULL) {
		(void) bunyan_trace(tlog,
		    "sys piv not set or guid not specified",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	sys_piv_guid = piv_token_guid(sys_piv->kt_piv);

	if (bcmp(sys_piv_guid, guid, GUID_LEN) != 0) {
		(void) bunyan_trace(tlog, "specified guid is not sys piv",
		    BUNYAN_T_STRING, "guid", gstr,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (sys_piv->kt_rtoken.rt_val == NULL && rtoken == NULL) {
		(void) bunyan_trace(tlog, "System PIV not set",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (sys_piv->kt_rtoken.rt_val != NULL)
		return (B_TRUE);

	if ((ret = set_piv_rtoken(sys_piv, rtoken)) != ERRF_OK) {
		/*
		 * This can only fail due to no memory, so we don't
		 * care about the exact error message.
		 */
		errf_free(ret);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Verify we have a token to use.  If we've already setup the token,
 * we don't require the token to be wiped and re-initialized + setup to
 * retry recreating the zpool.
 */
static errf_t *
kbmd_assert_token(const uint8_t *guid, const recovery_token_t *rtoken,
    kbmd_token_t **restrict ktp, struct ebox_tpl **restrict rcfgp)
{
	errf_t *ret = ERRF_OK;

	ASSERT(MUTEX_HELD(&piv_lock));

	*ktp = NULL;
	*rcfgp = NULL;

	/*
	 * If the system PIV has been designated, and is usable, we
	 * use that.
	 */
	if (try_sys_piv(guid, rtoken)) {
		(void) bunyan_debug(tlog, "Using system token",
		    BUNYAN_T_STRING, "piv_guid",
		    piv_token_guid_hex(sys_piv->kt_piv),
		    BUNYAN_T_END);

		*ktp = sys_piv;
		kbmd_token_free(incomplete_tok);
		incomplete_tok = NULL;
		return (ERRF_OK);
	}

	if ((ret = try_guid(guid, rtoken, ktp)) != ERRF_OK) {
		return (ret);
	} else if (guid != NULL) {
		ASSERT3P(*ktp, !=, NULL);

		(void) bunyan_debug(tlog, "Using supplied PIV token",
		    BUNYAN_T_STRING, "piv_guid",
		    piv_token_guid_hex((*ktp)->kt_piv),
		    BUNYAN_T_END);

		kbmd_token_free(incomplete_tok);
		incomplete_tok = NULL;
		kbmd_set_token(*ktp);
		return (ERRF_OK);
	}

	if (incomplete_tok != NULL) {
		(void) bunyan_debug(tlog,
		    "Using token info from previous attempt(s)",
		    BUNYAN_T_STRING, "piv_guid",
		    piv_token_guid_hex(incomplete_tok->kt_piv),
		    BUNYAN_T_END);

		if ((ret = register_pivtoken(incomplete_tok,
		    rcfgp)) != ERRF_OK ) {

			(void) bunyan_error(tlog,
			    "Failed to register pivtoken, token data saved for "
			    "retry", BUNYAN_T_END);

			return (ret);
		}

		*ktp = incomplete_tok;
		incomplete_tok = NULL;
		kbmd_set_token(*ktp);
		return (ERRF_OK);
	}

	if ((ret = kbmd_setup_token(ktp)) != ERRF_OK)
		return (ret);

	if ((ret = register_pivtoken(*ktp, rcfgp)) != ERRF_OK) {
		(void) bunyan_error(tlog,
		    "Failed to register pivtoken; token data saved for retry",
		    BUNYAN_T_END);

		incomplete_tok = *ktp;
		*ktp = NULL;
		return (ret);
	}

	kbmd_set_token(*ktp);
	return (ERRF_OK);
}

errf_t *
kbmd_zpool_create(const char *dataset, const uint8_t *guid,
    const struct ebox_tpl *rcfg_cmdline, const recovery_token_t *rtoken,
    nvlist_t *resp)
{
	errf_t *ret = ERRF_OK;
	struct ebox *ebox = NULL;
	struct ebox_tpl *rcfg_tok = NULL;
	const struct ebox_tpl *rcfg = NULL;
	kbmd_token_t *kt = NULL;
	uint8_t *key = NULL;
	size_t keylen = 0;
	char gstr[GUID_STR_LEN] = { 0 };

	if (guid != NULL) {
		guidtohex(guid, gstr, sizeof (gstr));
	} else {
		(void) strlcpy(gstr, "(not given)", sizeof (gstr));
	}

	(void) bunyan_info(tlog, "Received zpool create request",
	    BUNYAN_T_STRING, "dataset",
	    (dataset != NULL) ? dataset : "(not set)",
	    BUNYAN_T_STRING, "guid", gstr,
	    BUNYAN_T_END);

	if (dataset == NULL) {
		return (errf("ParameterError", NULL,
		    "system zpool not set and no dataset name given"));
	}

	mutex_enter(&piv_lock);

	if ((ret = kbmd_assert_token(guid, rtoken, &kt,
	    &rcfg_tok)) != ERRF_OK ||
	    (ret = kbmd_assert_pin(kt)) != ERRF_OK) {
		goto done;
	}

	rcfg = (rcfg_cmdline != NULL) ? rcfg_cmdline : rcfg_tok;

	if ((ret = kbmd_create_ebox(kt, rcfg, dataset, &key, &keylen,
	    &ebox)) != ERRF_OK) {
		goto done;
	}

	ret = add_create_data(resp, ebox, key, keylen);

done:
	mutex_exit(&piv_lock);
	ebox_free(ebox);
	ebox_tpl_free(rcfg_tok);
	freezero(key, keylen);
	return (ret);
}
