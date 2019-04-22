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
#include <umem.h>
#include "common.h"
#include "ecustr.h"
#include "ebox.h"
#include "envlist.h"
#include "errf.h"
#include "kbm.h"
#include "kbmd.h"
#include "libssh/sshbuf.h"

static errf_t *
datasets_str(char **datasets, size_t n, custr_t **cup)
{
	custr_t *cu = NULL;
	errf_t *ret = ERRF_OK;

	if ((ret = ecustr_alloc(&cu)) != ERRF_OK)
		return (ret);

	if (datasets == NULL) {
		ASSERT0(n);
		if ((ret = ecustr_append(cu, "all")) != ERRF_OK)
			goto fail;
		*cup = cu;
		return (ret);
	}

	if ((ret = ecustr_appendc(cu, '[')) != ERRF_OK)
		goto fail;

	for (size_t i = 0; i < n; i++) {
		if (i > 0 && ((ret = ecustr_append(cu, ", ")) != ERRF_OK))
			goto fail;
		if ((ret = ecustr_append(cu, datasets[i])) != ERRF_OK)
			goto fail;
	}
	if ((ret = ecustr_appendc(cu, ']')) != ERRF_OK)
		goto fail;

	*cup = cu;
	return (ret);

fail:
	custr_free(cu);
	*cup = NULL;
	return (ret);
}

static errf_t *
extract_datasets(nvlist_t *req, char ***datasetsp, uint_t *np)
{
	char **datasets;
	errf_t *ret = ERRF_OK;
	custr_t *ds_str = NULL;
	uint_t n;

	*datasetsp = NULL;
	*np = 0;

	if ((ret = envlist_lookup_string_array(req, KBM_NV_ZFS_DATASETS,
	    &datasets, &n)) != ERRF_OK)
		return (ret);

	if ((ret = datasets_str(datasets, n, &ds_str)) != ERRF_OK)
		return (ret);

	(void) bunyan_debug(tlog, "Received KBM_CMD_ZFS_UNLOCK request",
	    BUNYAN_T_STRING, "datasets", custr_cstr(ds_str),
	    BUNYAN_T_END);

	custr_free(ds_str);

	*datasetsp = datasets;
	*np = n;

	return (ret);
}


static errf_t *
get_boxes(nvlist_t *restrict req, struct ebox ***restrict eboxp,
    size_t *restrict nboxp)
{
	errf_t *ret = ERRF_OK;
	struct ebox **eboxes = NULL;
	char **datasets = NULL;
	uint_t ndatasets = 0;
	size_t nbox = 0;

	if ((ret = extract_datasets(req, &datasets, &ndatasets)) != ERRF_OK) {
		ret = errf("RequestError", ret,
		    "Could not extract datasets from request");
		goto fail;
	}

	mutex_enter(&kbmd_box_lock);

	nbox = (ndatasets > 0) ? ndatasets : kbmd_nboxes;
	if ((eboxes = calloc(nbox, sizeof (struct ebox *))) == NULL) {
		mutex_exit(&kbmd_box_lock);
		return (errfno("calloc", errno, ""));
	}

	if (ndatasets == 0) {
		bcopy(kbmd_boxes, eboxes, nbox * sizeof (struct ebox *));
	} else {
		for (size_t i = 0; i < nbox; i++) {
			eboxes[i] = kbmd_get_ebox(datasets[i]);
			if (eboxes[i] == NULL) {
				ret = errf("NotFoundError", NULL,
				    "dataset %s does not contain an ebox",
				    datasets[i]);
				goto fail;
			}
		}
	}
	mutex_exit(&kbmd_box_lock);

	*eboxp = eboxes;
	*nboxp = nbox;
	return (ret);

fail:
	mutex_exit(&kbmd_box_lock);
	free(eboxes);
	return (ret);
}

static uint8_t dummy_guid[16] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

void
kbmd_zfs_unlock(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;
	char **datasets = NULL;
	custr_t *pin = NULL;
	uint_t ndatasets = 0;

	if ((ret = extract_datasets(req, &datasets, &ndatasets)) != ERRF_OK) {
		ret = errf("RequestError", ret,
		    "Could not extract datasets from request");
		goto fail;
	}

	if ((ret = kbmd_get_pin(dummy_guid, &pin)) != ERRF_OK) {
		ret = errf("RequestError", ret, "Could not fetch pin");
		goto fail;
	}

	/* XXX: Remove this before integration */
	(void) bunyan_debug(tlog, "Pin",
	    BUNYAN_T_STRING, "pin", custr_cstr(pin),
	    BUNYAN_T_END);

	/* XXX: Unlock token */

	if ((ret = envlist_alloc(&resp)) != ERRF_OK ||
	    (ret = envlist_add_boolean_value(resp, KBM_NV_SUCCESS,
	    B_TRUE)) != ERRF_OK)
		goto fail;

	nvlist_free(req);
	kbmd_ret_nvlist(resp);

fail:
	nvlist_free(req);
	nvlist_free(resp);
	kbmd_ret_error(ret);
}
