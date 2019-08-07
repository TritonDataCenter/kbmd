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
#include <stdio.h>
#include <strings.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/libssh/sshbuf.h"

static size_t zfs_key_len = 32; /* bytes */

const char *piv_pin_str(enum piv_pin);
errf_t *get_slot(struct piv_token *restrict, enum piv_slotid,
    struct piv_slot **restrict);

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
 * Create an ebox template with 'kt' as the PIV token for the primary
 * config, and the current recovery configuration from the gossip
 * protocol as the recovery configuration.
 *
 * XXX: Until we integrate the gossip protocol support, no recovery
 * configurations are added (but this is where that should occur).
 */
errf_t *
get_template(kbmd_token_t *restrict kt, struct ebox_tpl **restrict tplp)
{
	errf_t *ret = ERRF_OK;
	struct ebox_tpl *tpl = NULL;
	struct ebox_tpl_config *cfg = NULL;

	if ((tpl = ebox_tpl_alloc()) == NULL) {
		ret = errfno("ebox_tpl_alloc", errno, "creating template");
		return (errf("TemplateError", ret,
		    "cannot create ebox template))"));
	}

	if ((ret = create_piv_tpl_config(kt, &cfg)) != ERRF_OK) {
		ret = errf("TemplateError", ret, "cannot create ebox template");
		ebox_tpl_free(tpl);
		return (ret);
	}

	ebox_tpl_add_config(tpl, cfg);
	*tplp = tpl;
	return (ret);
}

/*
 * XXX: Check if request includes a PIV guid and recovery token.  Only
 * for testing.
 */
static errf_t *
req_has_token(nvlist_t *restrict req, kbmd_token_t **restrict ktp)
{
	errf_t *ret = ERRF_OK;
	kbmd_token_t *kt = NULL;
	uint8_t *guid = NULL, *rtok = NULL;
	uint_t guidlen = 0, rtoklen = 0;
	char str[GUID_STR_LEN];

	VERIFY3P(sys_piv, ==, NULL);

	if ((ret = envlist_lookup_uint8_array(req, KBM_NV_GUID, &guid,
	    &guidlen)) != ERRF_OK ||
	    (ret = envlist_lookup_uint8_array(req, "recovery_token", &rtok,
	    &rtoklen)) != ERRF_OK) {
		return (ret);
	}

	guidtohex(guid, str);
	(void) bunyan_debug(tlog, "Using existing token",
	    BUNYAN_T_STRING, "guid", str,
	    BUNYAN_T_END);

	if ((ret = zalloc(sizeof (*kt), &kt)) != ERRF_OK ||
	    (ret = zalloc(rtoklen, &kt->kt_rtoken)) != ERRF_OK) {
		kbmd_token_free(kt);
		return (ret);
	}

	if ((ret = piv_find(piv_ctx, guid, guidlen, &kt->kt_piv)) != ERRF_OK) {
		kbmd_token_free(kt);
		return (ret);
	}

	bcopy(rtok, kt->kt_rtoken, rtoklen);
	kt->kt_rtoklen = rtoklen;
	*ktp = kt;
	kbmd_set_token(kt);

	return (ERRF_OK);
}

/*
 * Verify we have a token to use.  If we've already setup the token,
 * we don't require the token to be wiped and re-initialized + setup to
 * retry recreating the zpool.
 */
static errf_t *
assert_token(nvlist_t *restrict req, kbmd_token_t **restrict ktp)
{
	errf_t *ret;
	uint8_t *guid = NULL, *rtok = NULL;
	uint_t guidlen = 0, rlen = 0;

	ASSERT(MUTEX_HELD(&piv_lock));

	/*
	 * We can only use the cached PIV token if we also have the
	 * recovery token.
	 */
	if (sys_piv != NULL && sys_piv->kt_rtoken != NULL) {
		*ktp = sys_piv;
		return (ERRF_OK);
	}

	/*
	 * XXX: Allow caller to specify PIV token and recovery token.
	 * This is only for testing and should be removed before go live.
	 */
	if ((ret = req_has_token(req, ktp)) == ERRF_OK) {
		return (ERRF_OK);
	}

	/*
	 * Any error but 'not found' means something else has gone wrong and
	 * should be propagated up stack.
	 */
	if (errf_errno(ret) != ENOENT)
		return (ret);
	errf_free(ret);
	ret = ERRF_OK;

	/*
	 * Otherwise go through the normal init + setup for a new PIV token
	 */
	if ((ret = kbmd_setup_token(ktp)) != ERRF_OK)
		return (ret);

	kbmd_set_token(*ktp);
	return (ERRF_OK);
}

void
kbmd_zpool_create(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;
	struct ebox_tpl *tpl = NULL;
	struct ebox *ebox = NULL;
	kbmd_token_t *kt = NULL;
	char *dataset = NULL;
	char *buf = NULL;
	size_t datasetlen = 0;
	uint8_t *key = NULL;
	size_t keylen = 0;

	(void) bunyan_debug(tlog, "Received KBM_CMD_ZPOOL_CREATE request",
	    BUNYAN_T_END);

	mutex_enter(&piv_lock);

	if ((ret = envlist_lookup_string(req, KBM_NV_DATASET,
	    &dataset)) != ERRF_OK) {
		ret = errf("ArgumentError", ret,
		    "request is missing dataset name");
		goto done;
	}
	datasetlen = strlen(dataset);

	if ((ret = envlist_alloc(&resp)) != ERRF_OK)
		goto done;

	if ((key = calloc(1, zfs_key_len)) == NULL) {
		ret = errfno("calloc", errno, "");
		goto done;
	}
	keylen = zfs_key_len;
	arc4random_buf(key, keylen);

	if ((ret = assert_token(req, &kt)) != ERRF_OK ||
	    (ret = kbmd_assert_pin(kt)) != ERRF_OK) {
		goto done;
	}
	VERIFY3P(kt->kt_rtoken, !=, NULL);

	if ((ret = piv_txn_begin(kt->kt_piv)) != ERRF_OK ||
	    (ret = piv_select(kt->kt_piv)) != ERRF_OK) {
		goto done;
	}

	/*
	 * Currently, we create a new template using either the
	 * PIV token given in the create command (for testing) via the -g GUID
	 * option, or the PIV token we've just initialized (no -g GUID given
	 * and an uninitialized PIV token is present on the system).
	 */
	if ((ret = get_template(kt, &tpl)) != ERRF_OK) {
		ret = errf("ZpoolCreateError", ret,
		    "cannot retrieve current ebox template");
		goto done;
	}

	/*
	 * XXX: For testing, we allow kbmadm to supply a template that's used
	 * to supply the recovery parts.  We want to remove this once the
	 * gossip protocol is written.
	 */
	VERIFY3P(add_supplied_template(req, tpl, B_FALSE), ==, ERRF_OK);

	if ((ret = ebox_create(tpl, key, keylen, kt->kt_rtoken,
	    kt->kt_rtoklen, &ebox)) != ERRF_OK ||
	    (ret = set_box_name(ebox, dataset)) != ERRF_OK) {
		goto done;
	}

	ret = add_create_data(resp, ebox, key, keylen);

done:
	if (kt != NULL && kt->kt_piv != NULL && piv_token_in_txn(kt->kt_piv))
		piv_txn_end(kt->kt_piv);

	mutex_exit(&piv_lock);
	freezero(key, keylen);
	nvlist_free(req);
	ebox_free(ebox);
	ebox_tpl_free(tpl);

	if (ret == ERRF_OK) {
		kbmd_ret_nvlist(resp);
	} else {
		ebox_free(ebox);
		nvlist_free(resp);
		kbmd_ret_error(ret);
	}
}
