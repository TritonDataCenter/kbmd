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
#include <sys/types.h>
#include "common.h"
#include "envlist.h"
#include "errf.h"
#include "kbm.h"
#include "kbmd.h"
#include "kspawn.h"

/* A doubly secure luggage combination */
static uint8_t dummy_key[] = "\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05";
static size_t dummy_keylen = sizeof (dummy_key);

static errf_t *
add_zfs_opt(strarray_t *args, const char *name, const char *val)
{
	errf_t *ret;

	if ((ret = strarray_append(args, "-O")) != ERRF_OK ||
	    (ret = strarray_append(args, "%s=%s", name, val)) != ERRF_OK) {
		return (errf("RequestError", ret,
		    "Cannot form zpool create arguments"));
	}

	return (ERRF_OK);
}

void
kbmd_zpool_create(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;
	strarray_t args = STRARRAY_INIT;

	(void) bunyan_debug(tlog, "Received KBM_CMD_ZPOOL_CREATE request",
	    BUNYAN_T_END);

	/* XXX: Initialize token */
	/* XXX: Generate token pin */
	/* XXX: Create token certs */
	/* XXX: Create ebox */
	/* XXX: Register token */

	if ((ret = add_zfs_opt(&args, "encryption", "on")) != ERRF_OK ||
	    (ret = add_zfs_opt(&args, "keyformat", "raw")) != ERRF_OK ||
	    (ret = add_zfs_opt(&args, "keylocation", "prompt")) != ERRF_OK)
		goto fail;

	if ((ret = envlist_alloc(&resp)) != ERRF_OK ||
	    (ret = envlist_add_boolean_value(resp, KBM_NV_SUCCESS,
	    B_TRUE)) != ERRF_OK ||
	    (ret = envlist_add_string_array(resp, KBM_NV_CREATE_ARGS,
	    args.sar_strs, args.sar_n)) != ERRF_OK ||
	    (ret = envlist_add_uint8_array(resp, KBM_NV_ZPOOL_KEY, dummy_key,
	    dummy_keylen)) != ERRF_OK)
		goto fail;

	strarray_fini(&args);
	nvlist_free(req);
	kbmd_ret_nvlist(resp);

fail:
	strarray_fini(&args);
	nvlist_free(req);
	kbmd_ret_error(ret);
}
