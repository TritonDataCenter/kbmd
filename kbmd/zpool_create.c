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
#include <stdio.h>
#include <strings.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/libssh/sshbuf.h"

/*
 * If the PIV token registration fails, we cache the guid and pin so a
 * subsequent zpool_create operation can retry. We only support doing
 * this for a single PIV token. If multiple PIV tokens are registered on
 * the same system, and there are multiple failures, only the most
 * recent one is saved. This does mean some sensitive info is saved in memory,
 * though in practice the values shouldn't persist for too long.
 */
static boolean_t failed_registration;
static uint8_t incomplete_guid[GUID_LEN];
static char incomplete_pin[PIN_MAX_LENGTH + 1];

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
		/*
		 * Regardless of the default we want to use aes-gcm-256 for
		 * pools. If a newer/better algorithm does come out, we
		 * can't 'upgrade' existing pools, so we'll just update
		 * this default for new pools.
		 */
		{ "encryption", "aes-gcm-256" },
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
    kbmd_token_t **restrict ktp, boolean_t *restrict is_retryp)
{
	errf_t *ret = ERRF_OK;
	kbmd_token_t *kt = NULL;
	uint8_t local_guid[GUID_LEN] = { 0 };
	boolean_t is_retry = B_FALSE;

	/* Select the PIV token to use. */
	if (guid == NULL) {
		if (failed_registration) {
			/*
			 * If no GUID was given, but we setup a PIV token and
			 * failed to register it, use the GUID of the
			 * previously setup PIV token.
			 */
			bcopy(incomplete_guid, local_guid, GUID_LEN);
			is_retry = B_TRUE;
		} else {
			/* Try the system PIV if one has been set */
			mutex_enter(&guid_lock);
			bcopy(sys_guid, local_guid, GUID_LEN);
			mutex_exit(&guid_lock);

			/*
			 * If no system PIV token is set, return and try
			 * to initialize a new PIV token.
			 */
			if (bcmp(zero_guid, local_guid, GUID_LEN) != 0)
				return (ret);
		}
	} else {
		/* If we were given a GUID to try, use that */
		bcopy(guid, local_guid, GUID_LEN);
	}

	/* Make sure whatever GUID we're trying is present */
	if ((ret = kbmd_find_byguid(local_guid, GUID_LEN, &kt)) != ERRF_OK)
		return (ret);

	if ((ret = set_piv_rtoken(kt, rtoken)) != ERRF_OK) {
		kbmd_token_free(kt);
		return (ret);
	}

	if (is_retry) {
		(void) strlcpy(kt->kt_pin, incomplete_pin, sizeof (kt->kt_pin));
		(void) bunyan_debug(tlog,
		    "Using PIV token from previous attempt",
		    BUNYAN_T_STRING, "token", piv_token_guid_hex(kt->kt_piv),
		    BUNYAN_T_END);
	} else {
		(void) bunyan_debug(tlog, "Using supplied PIV token",
		    BUNYAN_T_STRING, "token", piv_token_guid_hex(kt->kt_piv),
		    BUNYAN_T_END);
	}

	*is_retryp = is_retry;
	*ktp = kt;

	return (ERRF_OK);
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
	boolean_t is_retry = B_FALSE;
	boolean_t need_register = B_TRUE;

	*ktp = NULL;
	*rcfgp = NULL;

	if ((ret = try_guid(guid, rtoken, ktp, &is_retry)) != ERRF_OK)
		return (ret);

	if (*ktp == NULL) {
		if ((ret = kbmd_setup_token(ktp)) != ERRF_OK)
			return (ret);
	} else if (!is_retry) {
		need_register = B_FALSE;
	}

	if (need_register &&
	    (ret = register_pivtoken(*ktp, rcfgp)) != ERRF_OK) {
		(void) bunyan_error(tlog,
		    "Failed to register pivtoken; token data saved for retry",
		    BUNYAN_T_END);

		failed_registration = B_TRUE;
		bcopy(piv_token_guid((*ktp)->kt_piv), incomplete_guid,
		    GUID_LEN);
		(void) strlcpy(incomplete_pin, (*ktp)->kt_pin,
		    sizeof (incomplete_pin));

		return (ret);
	}

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
	kbmd_token_free(kt);
	ebox_free(ebox);
	ebox_tpl_free(rcfg_tok);
	freezero(key, keylen);
	return (ret);
}
