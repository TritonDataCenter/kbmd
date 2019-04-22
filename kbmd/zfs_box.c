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
#include "ebox.h"
#include "envlist.h"
#include "errf.h"
#include "kbmd.h"
#include "libssh/sshbuf.h"
#include "libssh/ssherr.h"

#include <stdio.h>

#define	BOX_PROP	"rfd77:config"

/*
 * kbmd_box_lock protects kbmd_boxes and kbmd_nboxes
 */
mutex_t kbmd_box_lock = ERRORCHECKMUTEX;
struct ebox **kbmd_boxes;
size_t kbmd_nboxes;

struct scan_pool_data {
	errf_t		*spd_err;
	struct ebox	**spd_boxes;
	size_t		spd_nboxes;
	size_t		spd_alloc;
};

#define	SPD_CHUNK 8

/*
 * Make sure we have room to add a box in dp
 */
static errf_t *
reserve_ebox(struct scan_pool_data *dp)
{
	struct ebox **newbox;
	size_t newalloc;

	if (dp->spd_alloc + 1 <= dp->spd_alloc)
		return (ERRF_OK);

	newalloc = dp->spd_alloc + SPD_CHUNK;
	newbox = recallocarray(dp->spd_boxes, dp->spd_alloc, newalloc,
	    sizeof (struct ebox *));
	if (newbox == NULL) {
		return (errfno("calloc", errno, ""));
	}

	dp->spd_boxes = newbox;
	dp->spd_alloc = newalloc;
	return (ERRF_OK);
}

static errf_t *
get_box_string(zfs_handle_t *restrict zhp, char **sp)
{
	const char *dsname = zfs_get_name(zhp);
	errf_t *ret = ERRF_OK;
	nvlist_t *uprops = NULL, *val = NULL;

	uprops = zfs_get_user_props(zhp);

	if ((ret = envlist_lookup_nvlist(uprops, BOX_PROP, &val)) != ERRF_OK) {
		if (!errf_caused_by(ret, "ENOENT")) {
			return (errf("ZfsError", ret, "unexpected error while "
			    "looking up '%s' property on dataset %s",
			    BOX_PROP, dsname));
		}

		erfree(ret);
		(void) bunyan_trace(tlog,
		    "dataset does not have " BOX_PROP " set; skipping",
		    BUNYAN_T_STRING, "dataset", dsname,
		    BUNYAN_T_END);

		*sp = NULL;
		return (ERRF_OK);
	}

	if ((ret = envlist_lookup_string(val, "value", sp)) != ERRF_OK) {
		return (errf("ZfsError", ret, "unexpected error while "
		    "retrieving '%s' value from dataset %s", BOX_PROP, dsname));
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
		ret = errf("ZfsError", errfno("sshbuf_new", errno, ""),
		    "Cannot parse ebox contents of %s", dsname);
		goto done;
	}

	if ((rc = sshbuf_b64tod(boxbuf, str)) != SSH_ERR_SUCCESS) {
		ret = errf("ZfsError", ssherrf("sshbuf_b64tod", rc),
		    "Cannot base64 decode ebox contents for %s", dsname);
		goto done;
	}

	if ((ret = sshbuf_get_ebox(boxbuf, &ebox)) != ERRF_OK) {
		ret = errf("ZfsError", ret,
		    "Cannot parse the ebox contents for %s", dsname);
		goto done;
	}

	*eboxp = ebox;

done:
	sshbuf_free(boxbuf);
	return (ret);
}

errf_t *
kbmd_ebox_to_str(struct ebox *restrict ebox, char **restrict strp)
{
	const char *dsname = ebox_private(ebox);
	errf_t *ret = ERRF_OK;
	struct sshbuf *boxbuf = NULL;
	char *str = NULL;
	int rc;

	VERIFY3P(dsname, !=, NULL);

	if ((boxbuf = sshbuf_new()) == NULL) {
		ret = errf("ZfsError", errfno("sshbuf_new", errno, ""),
		    "Cannot serialize ebox for %s", dsname);
		goto done;
	}

	if ((ret = sshbuf_put_ebox(boxbuf, ebox)) != ERRF_OK) {
		ret = errf("ZfsError", ret,
		    "Cannot serialize ebox for %s", dsname);
		goto done;
	}

	if ((str = sshbuf_dtob64(boxbuf)) == NULL) {
		ret = errf("sshbuf_dtob64", NULL,
		    "Cannot convert ebox for %s to base 64", dsname);
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
add_box(zfs_handle_t *restrict zhp, struct scan_pool_data *restrict dp)
{
	const char *dsname = zfs_get_name(zhp);
	errf_t *ret = ERRF_OK;
	char *boxstr = NULL;
	struct ebox *ebox = NULL;

	if ((ret = get_box_string(zhp, &boxstr)) != ERRF_OK) {
		return (errf("ZfsError", ret,
		    "cannot get %s value from dataset %s", BOX_PROP, dsname));
	}

	/* Dataset didn't have an ebox, skip */
	if (boxstr == NULL)
		return (0);

	if ((ret = reserve_ebox(dp)) != ERRF_OK ||
	    (ret = str_to_ebox(dsname, boxstr, &ebox)) != ERRF_OK ||
	    (ret = set_box_dataset(ebox, dsname)) != ERRF_OK) {
		return (errf("ZfsError", ret, "cannot save ebox for %s",
		    dsname));
	}

	(void) bunyan_trace(tlog, "Found dataset with ebox",
	    BUNYAN_T_STRING, "dataset", dsname,
	    BUNYAN_T_END);

	dp->spd_boxes[dp->spd_nboxes++] = ebox;
	return (ret);
}

static int
kbmd_zfs_callback(zfs_handle_t *zhp, void *data)
{
	struct scan_pool_data *dp = data;
	int rc = 0;

	ASSERT(MUTEX_HELD(&g_zfs_lock));

	/*
	 * We should only be setting the property on filesystems or zvols
	 */
	if ((zfs_get_type(zhp) & (ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME)) == 0) {
		zfs_close(zhp);
		return (0);
	}

	if ((dp->spd_err = add_box(zhp, dp)) != ERRF_OK)
		return (-1);

	if (zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM)
		rc = zfs_iter_filesystems(zhp, kbmd_zfs_callback, data);

	zfs_close(zhp);
	return (rc);
}

errf_t *
kbmd_scan_pools(void)
{
	struct scan_pool_data data = { 0 };
	uint32_t n = 0;
	int rc;

	(void) bunyan_debug(tlog, "Scanning ZFS datasets for eboxes",
	    BUNYAN_T_END);

	mutex_enter(&kbmd_box_lock);
	mutex_enter(&g_zfs_lock);
	rc = zfs_iter_root(g_zfs, kbmd_zfs_callback, &data);
	mutex_exit(&g_zfs_lock);
	if (rc != 0) {
		mutex_exit(&kbmd_box_lock);

		for (size_t i = 0; i < data.spd_nboxes; i++)
			ebox_free(data.spd_boxes[i]);
		free(data.spd_boxes);

		VERIFY3P(data.spd_err, !=, NULL);
		return (data.spd_err);
	}

	for (size_t i = 0; i < kbmd_nboxes; i++)
		ebox_free(kbmd_boxes[i]);
	free(kbmd_boxes);

	kbmd_boxes = data.spd_boxes;
	kbmd_nboxes = data.spd_nboxes;
	n = (uint32_t)kbmd_nboxes;
	mutex_exit(&kbmd_box_lock);

	(void) bunyan_debug(tlog, "Ebox scan complete",
	    BUNYAN_T_UINT32, "numboxes", n,
	    BUNYAN_T_END);

	return (ERRF_OK);
}

struct ebox *
kbmd_get_ebox(const char *dataset)
{
	VERIFY(MUTEX_HELD(&kbmd_box_lock));

	for (size_t i = 0; i < kbmd_nboxes; i++) {
		const char *boxds = ebox_private(kbmd_boxes[i]);

		if (strcmp(boxds, dataset) == 0)
			return (kbmd_boxes[i]);
	}

	return (NULL);
}

errf_t *
kbmd_put_ebox(struct ebox *ebox)
{
	const char *dsname = ebox_private(ebox);
	errf_t *ret = ERRF_OK;
	char *str = NULL;
	nvlist_t *prop = NULL;
	zfs_handle_t *zhp = NULL;

	VERIFY3P(dsname, !=, NULL);

	mutex_enter(&g_zfs_lock);
	zhp = zfs_open(g_zfs, dsname, ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME);
	if (zhp == NULL) {
		ret = errf("ZfsError", NULL, "Unable to open %s: %s",
		    dsname, libzfs_error_description(g_zfs));
		goto done;
	}

	if ((ret = envlist_alloc(&prop)) != ERRF_OK ||
	    (ret = kbmd_ebox_to_str(ebox, &str)) != ERRF_OK ||
	    (ret = envlist_add_string(prop, BOX_PROP, str)) != ERRF_OK) {
	    goto done;
	}

	if (zfs_prop_set_list(zhp, prop) != 0) {
		ret = errf("ZfsError", NULL, "Cannot set %s property on %s: %s",
		    BOX_PROP, dsname, libzfs_error_description(g_zfs));
	}

done:
	if (zhp != NULL)
		zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	nvlist_free(prop);
	return (ret);
}
