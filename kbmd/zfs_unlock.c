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
#include <strings.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/types.h>
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "kbm.h"
#include "kbmd.h"
#include "kspawn.h"
#include "pivy/ebox.h"
#include "pivy/errf.h"

#define	ZFS_CMD	"/sbin/zfs"

/*
 * For now at least, effectively do 'cat key | zfs load-key <dataset>'
 * The current libzfs api doesn't lend itself well to using input methods
 * beyond those available from invoking the command i.e. read from fd or tty,
 * or open and file.  It also does some transformation on the key value prior
 * to issuing the zfs ioctl, so just running the command is simpler for now.
 */
static errf_t *
load_key(const char *dataset, const uint8_t *key, size_t keylen)
{
	errf_t *ret = ERRF_OK;
	custr_t *data[2] = { 0 };
	int fds[3] = { -1, -1, -1 };
	int exitval = 0;
	strarray_t args = STRARRAY_INIT;
	pid_t pid;

	if ((ret = ecustr_alloc(&data[0])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[1])) != ERRF_OK)
			return (ret);

	if ((ret = strarray_append(&args, "%s", ZFS_CMD)) != ERRF_OK ||
	    (ret = strarray_append(&args, "load-key")) != ERRF_OK ||
	    (ret = strarray_append(&args, "%s", dataset)) != ERRF_OK)
		goto done;

	(void) bunyan_debug(tlog, "Attemping to run zfs load-key",
	    BUNYAN_T_STRING, "dataset", dataset,
	    BUNYAN_T_END);

	if ((ret = spawn(ZFS_CMD, args.sar_strs, _environ, &pid,
	    fds)) != ERRF_OK)
		goto done;

	if ((ret = interact(pid, fds, key, keylen, data,
	    &exitval)) != ERRF_OK)
		goto done;

	if (exitval != 0) {
		(void) bunyan_warn(tlog, "zfs load-key command failed",
		    BUNYAN_T_STRING, "stderr", custr_cstr(data[1]),
		    BUNYAN_T_INT32, "exitval", (int32_t)exitval,
		    BUNYAN_T_END);
		ret = errf("CommandError", NULL, "zfs load-key");
	}

done:
	strarray_fini(&args);
	custr_free(data[0]);
	custr_free(data[1]);
	return (ret);
}

void
kbmd_zfs_unlock(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;
	char *dataset = NULL;
	struct ebox *ebox = NULL;
	const uint8_t *key = NULL;
	size_t keylen = 0;

	if ((ret = envlist_lookup_string(req, KBM_NV_ZFS_DATASET,
	    &dataset)) != ERRF_OK) {
		(void) bunyan_warn(tlog,
		    "Could not extract dataset name for unlock request",
		    BUNYAN_T_END);
		goto fail;
	}

	(void) bunyan_debug(tlog, "Request to unlock dataset",
	    BUNYAN_T_STRING, "dataset", dataset,
	    BUNYAN_T_END);

	if ((ret = kbmd_get_ebox(dataset, &ebox)) != ERRF_OK ||
	    (ret = kbmd_unlock_ebox(ebox)) != ERRF_OK) {
		goto fail;
	}

	key = ebox_key(ebox, &keylen);

	if ((ret = load_key(dataset, key, keylen)) != ERRF_OK) {
		goto fail;
	}

	if ((ret = envlist_alloc(&resp)) != ERRF_OK ||
	    (ret = envlist_add_boolean_value(resp, KBM_NV_SUCCESS,
	    B_TRUE)) != ERRF_OK)
		goto fail;

	ebox_free(ebox);
	nvlist_free(req);
	kbmd_ret_nvlist(resp);

fail:
	ebox_free(ebox);
	nvlist_free(req);
	nvlist_free(resp);
	kbmd_ret_error(ret);
}
