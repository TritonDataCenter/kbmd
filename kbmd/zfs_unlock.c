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
#include <strings.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/mnttab.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/errf.h"

#define	ZFS_CMD	"/sbin/zfs"

/*
 * For now at least, effectively do 'cat key | zfs load-key <dataset>'
 * The current libzfs api doesn't lend itself well to using input methods
 * beyond those available from invoking the command i.e. read from fd or tty,
 * or open and file.  It also does some transformation on the key value prior
 * to issuing the zfs ioctl, so just running the command is simpler for now.
 *
 * XXX: It appears libzfs_core might have a function that could simplify
 * this.  Need to test that.
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

	if ((ret = get_dataset_mountpoint(dataset, &mountp)) != ERRF_OK) {
		return (ret);
	}

	if ((fd = open(mountp, O_RDONLY)) == -1) {
		ret = errfno("open", errno, "failed to open %s", mountp);
		free(mountp);
		return (ret);
	}

	if ((fstatat(fd, ".system_pool", &st, 0)) != 0) {
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

void
kbmd_zfs_unlock(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;
	char *dataset = NULL;
	struct ebox *ebox = NULL;
	kbmd_token_t *kt = NULL;
	const uint8_t *key = NULL;
	size_t keylen = 0;
	boolean_t is_syspool = B_FALSE;

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

	if ((ret = kbmd_get_ebox(dataset, &ebox)) != ERRF_OK ||
	    (ret = kbmd_unlock_ebox(ebox, &kt)) != ERRF_OK) {
		goto fail;
	}

	key = ebox_key(ebox, &keylen);
	if ((ret = load_key(dataset, key, keylen)) != ERRF_OK) {
		goto fail;
	}

	/*
	 * Whatever token ends up being the one that works is what we'll
	 * set as the 'system' token.
	 */
	if ((ret = is_system_zpool(dataset, &is_syspool)) == ERRF_OK &&
	    is_syspool) {
		/*
		 * This is currently just for diagnostic purposes, so
		 * we won't care too much if strdup fails.
		 */
		if (zones_dataset == NULL)
			zones_dataset = strdup(dataset);

		kbmd_set_token(kt);

		/*
		 * If we are called multiple times for the system dataset,
		 * kbmd_get_ebox() may return the existing sys_box.  Only
		 * replace it if we have a different one.
		 */
		if (sys_box != ebox) {
			ebox_free(sys_box);
			sys_box = ebox;
			ebox = NULL;
		}
	} else {
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

		erfree(ret);
	}

	if ((ret = envlist_alloc(&resp)) != ERRF_OK ||
	    (ret = envlist_add_boolean_value(resp, KBM_NV_SUCCESS,
	    B_TRUE)) != ERRF_OK)
		goto fail;

	mutex_exit(&piv_lock);
	nvlist_free(req);
	kbmd_ret_nvlist(resp);

fail:
	if (ebox != sys_box)
		ebox_free(ebox);

	mutex_exit(&piv_lock);

	nvlist_free(req);
	nvlist_free(resp);
	kbmd_ret_error(ret);
}
