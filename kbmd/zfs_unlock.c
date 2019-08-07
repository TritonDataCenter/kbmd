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
#include <fcntl.h>
#include <libzfs.h>
#include <libzfs_core.h>
#include <strings.h>
#include <sys/mnttab.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/errf.h"

errf_t *
load_key(const char *dataset, const uint8_t *key, size_t keylen)
{
	errf_t *ret = ERRF_OK;
	int rc;

	/*
	 * lzc_load_key() returns EEXIST if the key is already loaded.
	 * Don't treat EEXIST as a failure.
	 */
	if ((rc = lzc_load_key(dataset, B_FALSE, (uint8_t *)key,
	    keylen)) != 0 && rc != EEXIST) {
		ret = errfno("lzc_load_key", rc,
		    "failed to load key for %s dataset", dataset);
	}

	return (ret);
}

static errf_t *
get_dataset_mountpoint(const char *dataset, char **mountp)
{
	errf_t *ret = ERRF_OK;
	FILE *mntf = NULL;
	struct mnttab ent = { 0 };

	if ((mntf = fopen(MNTTAB, "r")) == NULL) {
		return (errfno("fopen", errno, "cannot open %s", MNTTAB));
	}

	while (getmntent(mntf, &ent) == 0) {
		if (ent.mnt_fstype == NULL ||
		    ent.mnt_special == NULL ||
		    ent.mnt_mountp == NULL ||
		    strcmp(ent.mnt_fstype, "zfs") != 0 ||
		    strcmp(ent.mnt_special, dataset) != 0) {
			continue;
		}

		/* found it */

		if (fclose(mntf) != 0) {
			return (errfno("fclose", errno, "failed to close %s",
			    MNTTAB));
		}

		if ((*mountp = strdup(ent.mnt_mountp)) == NULL) {
			ret = errfno("strdup", errno, "");
			return (ret);
		}

		return (ERRF_OK);
	}

	if (ferror(mntf) != 0) {
		ret = errf("IOError", NULL, "error while reading %s", MNTTAB);
		/*
		 * If there was some error, it would not be unexpected for
		 * fclose to also fail, so ignore any errors from it.
		 */
		(void) fclose(mntf);
	} else {
		/*
		 * However, if we merely did not find the dataset in the mnttab,
		 * an error while calling fclose is worth reporting.
		 */
		if (fclose(mntf) != 0) {
			ret = errfno("fclose", errno, "failed to close %s",
			    MNTTAB);
		} else {
			ret = errf("NotFoundError", NULL,
			   "ZFS dataset %s does not appear to be mounted",
			   dataset);
		}
	}

	return (ret);
}

/*
 * Attempt to mount the same datasets that are mounted during a 'zpool import'
 * on a non-encrypted pool.  Like 'zpool import', this is best effort.
 */
void
kbmd_mount_zpool(const char *pool, const char *mntopts)
{
	zpool_handle_t *zhp = NULL;

	(void) bunyan_debug(tlog, "Attempting to mount datasets in pool",
	    BUNYAN_T_STRING, "pool", pool,
	    BUNYAN_T_END);

	mutex_enter(&g_zfs_lock);
	if ((zhp = zpool_open_canfail(g_zfs, pool)) == NULL) {
		mutex_exit(&g_zfs_lock);
	}

	if (zpool_get_state(zhp) == POOL_STATE_UNAVAIL) {
		goto done;
	}

	(void) zpool_enable_datasets(zhp, mntopts, 0);

done:
	zpool_close(zhp);
	mutex_exit(&g_zfs_lock);
}

/*
 * The system zpool is defined as the one whose root dataset
 * contains '.system_pool'.  This is almost always 'zones'.
 */
static errf_t *
is_system_zpool(const char *dataset, boolean_t *valp)
{
	errf_t *ret = ERRF_OK;
	char *mountp = NULL;
	struct stat st = { 0 };
	int fd = -1;

	*valp = B_FALSE;

	(void) bunyan_debug(tlog, "Checking if pool is system zpool",
	    BUNYAN_T_STRING, "pool", dataset,
	    BUNYAN_T_END);

	if ((ret = get_dataset_mountpoint(dataset, &mountp)) != ERRF_OK) {
		(void) bunyan_debug(tlog, "Failed to get mountpoint of pool",
		    BUNYAN_T_STRING, "pool", dataset,
		    BUNYAN_T_END);
		return (ret);
	}

	(void) bunyan_debug(tlog, "Found pool mountpoint",
	    BUNYAN_T_STRING, "pool", dataset,
	    BUNYAN_T_STRING, "mountpoint", mountp,
	    BUNYAN_T_END);

	if ((fd = open(mountp, O_RDONLY)) == -1) {
		ret = errfno("open", errno, "failed to open %s", mountp);
		free(mountp);
		return (ret);
	}

	if (fstatat(fd, ".system_pool", &st, 0) != 0) {
		/*
		 * ENOENT is not a fatal error, it merely means the
		 * dataset is not the system pool.  Any other error
		 * however should be considered a failure and reported
		 * back.
		 */
		if (errno != ENOENT) {
			ret = errfno("fstatat", errno,
			    "failed to stat %s/.system_pool", mountp);
		}
	} else {
		*valp = B_TRUE;
	}

	/*
	 * There's currently no easy easy way to chain errfno errf_t's,
	 * and if we failed earlier, we are less likely to care if
	 * the close fails.
	 */
	if (close(fd) != 0 && ret == ERRF_OK) {
		ret = errfno("close", errno, "failed to close %s", mountp);
	}

	free(mountp);
	return (ret);
}

errf_t *
get_dataset_status(const char *dataset, boolean_t *restrict encryptedp,
    boolean_t *restrict lockedp)
{
	errf_t *ret = ERRF_OK;
	zfs_handle_t *zhp = NULL;
	int encryption, keystatus;

	mutex_enter(&g_zfs_lock);
	if ((ret = ezfs_open(g_zfs, dataset,
	    ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME, &zhp)) != ERRF_OK) {
		mutex_exit(&g_zfs_lock);
		ret = errf("ZfsError", ret,
		    "unable to open dataset %s to check encryption status",
		    dataset);
		return (ret);
	}

	/*
	 * If the dataset is not encrypted, we treat it as if the
	 * key was loaded (unlocked).
	 *
	 * NOTE: This might not do the right thing for a child inheriting
	 * the encryption status of its parent, however we shouldn't be
	 * using this on such datasets.
	 */
	encryption = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);
	(void) bunyan_trace(tlog, "Checking encryption status for dataset",
	    BUNYAN_T_STRING, "dataset", dataset,
	    BUNYAN_T_INT32, "encryption", encryption,
	    BUNYAN_T_END);

	if (encryption == ZIO_CRYPT_OFF) {
		*encryptedp = B_FALSE;
		*lockedp = B_FALSE;
		goto done;
	}
	*encryptedp = B_TRUE;

	keystatus = zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS);
	(void) bunyan_trace(tlog, "Checking dataset keystatus",
	    BUNYAN_T_STRING, "dataset", dataset,
	    BUNYAN_T_INT32, "keystatus", keystatus,
	    BUNYAN_T_END);

	if (keystatus == ZFS_KEYSTATUS_AVAILABLE) {
		*lockedp = B_FALSE;
	} else {
		*lockedp = B_TRUE;
	}

done:
	zfs_close(zhp);
	mutex_exit(&g_zfs_lock);
	return (ret);
}

void
kbmd_zfs_unlock(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	char *dataset = NULL;
	struct ebox *ebox = NULL;
	kbmd_token_t *kt = NULL;
	const uint8_t *key = NULL;
	size_t keylen = 0;
	boolean_t is_syspool = B_FALSE;
	boolean_t is_encrypted, is_locked;

	mutex_enter(&piv_lock);

	if ((ret = envlist_lookup_string(req, KBM_NV_ZFS_DATASET,
	    &dataset)) != ERRF_OK && !errf_caused_by(ret, "ENOENT")) {
		(void) bunyan_warn(tlog,
		    "Could not extract dataset name for unlock request",
		    BUNYAN_T_END);
		goto fail;
	}

	(void) bunyan_debug(tlog, "Request to unlock dataset",
	    BUNYAN_T_STRING, "dataset",
	    (dataset == NULL) ? "(default 'zones')" : dataset,
	    BUNYAN_T_END);

	if (dataset == NULL) {
		dataset = "zones";
	}

	if ((ret = get_dataset_status(dataset, &is_encrypted,
	    &is_locked)) != ERRF_OK) {
		goto fail;
	}

	if (!is_encrypted) {
		ret = errf("ArgumentError", NULL,
		    "dataset %s does not appear to be encrypted", dataset);
		goto fail;
	}

	if (!is_locked) {
		ret = errf("AlreadyUnlocked", NULL,
		    "dataset %s's key is already loaded", dataset);
		goto fail;
	}

	if ((ret = kbmd_get_ebox(dataset, &ebox)) != ERRF_OK ||
	    (ret = kbmd_unlock_ebox(ebox, &kt)) != ERRF_OK) {
		goto fail;
	}

	key = ebox_key(ebox, &keylen);
	if ((ret = load_key(dataset, key, keylen)) != ERRF_OK) {
		goto fail;
	}

	/*
	 * If the dataset is the top most dataset in the pool, we
	 * attempt to mount the things that are normally mounted
	 * during 'zpool import'.  Since the key for the pool isn't
	 * available until now, those datasets won't be mounted during
	 * import if the whole pool is encrypted.
	 *
	 * XXX: At some point, we should support '-o mntopts' similar to
	 * what zpool import does (not to be confused with -o 'property=value').
	 * For now, we don't pass any options.
	 */
	if (IS_ZPOOL(dataset)) {
		kbmd_mount_zpool(dataset, NULL);
	}

	/*
	 * Whatever token ends up being the one that works is what we'll
	 * set as the 'system' token.
	 */
	if ((ret = is_system_zpool(dataset, &is_syspool)) == ERRF_OK &&
	    is_syspool) {

		(void) bunyan_debug(tlog, "Setting pool as system zpool",
		    BUNYAN_T_STRING, "pool", dataset,
		    BUNYAN_T_END);

		/*
		 * This is currently just for diagnostic purposes, so
		 * we won't care too much if strdup fails.
		 */
		if (zones_dataset == NULL)
			zones_dataset = strdup(dataset);

		kbmd_set_token(kt);
	} else if (ret != ERRF_OK) {
		/*
		 * If we successfully obtained and loaded the key for
		 * the given dataset, but somehow failed to determine
		 * if the dataset was the system zpool or not, we log
		 * the error, but otherwise treat the operation as
		 * successful.
		 */
		(void) bunyan_warn(tlog,
		    "Successfully unlocked dataset, but system zpool check "
		    "failed",
		    BUNYAN_T_STRING, "dataset", dataset,
		    BUNYAN_T_STRING, "caused_by", errf_name(ret),
		    BUNYAN_T_STRING, "errmsg", errf_message(ret),
		    BUNYAN_T_END);

		errf_free(ret);
	}

	mutex_exit(&piv_lock);
	nvlist_free(req);
	kbmd_ret_nvlist(NULL);

fail:
	ebox_free(ebox);
	mutex_exit(&piv_lock);
	nvlist_free(req);
	kbmd_ret_error(ret);
}
