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

#include <errno.h>
#include <synch.h>
#include <sys/list.h>
#include "envlist.h"
#include "kbmd.h"
#include "pivy/ebox.h"
#include "pivy/errf.h"

typedef enum recovery_state {
	RSTATE_SELECT_CONFIG,
	RSTATE_UNLOCK_CONFIG
} recovery_state_t;

typedef struct recovery {
	uint32_t		r_refcnt;
	list_node_t		r_node;
	uint32_t		r_id;
	pid_t			r_pid;
	recovery_state_t	r_state;
	struct ebox		*r_ebox;
	struct ebox_config	*r_config;
	struct ebox_tpl_config	*r_tconfig;
	struct ebox_tpl_part	*r_tpart;
	uint_t			r_n;
	uint_t			r_m;
} recovery_t;

typedef enum conv_type {
	CONV_QUESTION,
	CONV_OPTION
} conv_type_t;

typedef struct conv_item {
	list_node_t	ci_node;
	conv_type_t	ci_type;
	char		*ci_text;
} conv_item_t;

typedef struct conv {
	list_t		conv_list;
	size_t		conv_size;
} conv_t;

static mutex_t recovery_lock = ERRORCHECKMUTEX;
static uint32_t recovery_last_id;
static uint32_t recovery_count;
static list_t recovery_list;

static void
conv_init(conv_t *conv)
{
	list_create(&conv->conv_list, sizeof (conv_item_t),
	    offsetof(conv_item_t, ci_node));
	conv->conv_size = 0;
}

static void
conv_fini(conv_t *conv)
{
	conv_item_t *ci;

	while ((ci = list_remove_head(&conv->conv_list)) != NULL) {
		free(ci->ci_text);
		free(ci);
		conv->conv_size--;
	}

	ASSERT0(conv->conv_size);
}

static errf_t *
conv_add(conv_t *conv, conv_type_t type, const char *txt, ...)
{
	conv_item_t *ci;
	va_list ap;
	int rc;

	if ((ci = malloc(sizeof (*ci))) == NULL) {
		return (errfno("malloc", errno, "adding conversation item"));
	}

	ci->ci_type = type;
	va_start(ap, txt);
	rc = vasprintf(&ci->ci_text, txt, ap);
	va_end(ap);

	if (rc < 0) {
		errf_t *ret =
		    errfno("vasprintf", errno, "adding conversation text");
		free(ci);
		return (ret);
	}

	list_append_tail(&conv->conv_list, ci);
	conv->conv_size++;
	return (ERRF_OK);
}

static errf_t *
add_resp_conv_item(nvlist_t **nvlp, conv_item_t *ci)
{
	errf_t *ret;
	const char *name = NULL;

	switch (ci->ci_type) {
	case CONV_QUESTION:
		name = KBM_NV_QUESTION;
		break;
	case CONV_OPTION:
		name = KBM_NV_OPTION;
		break;
	default:
		panic("invalid ci_type %d", ci->ci_type);
	}

	if ((ret = envlist_alloc(nvlp)) != ERRF_OK)
		return (ret);

	return (envlist_add_string(*nvlp, name, ci->ci_text));
}

static errf_t *
add_resp_conv(nvlist_t *resp, conv_t *conv)
{
	errf_t *ret;
	nvlist_t **nvls;
	conv_item_t *ci;
	size_t i;

	if ((nvls = calloc(conv->conv_size)) == NULL)
		return (errfno("calloc", errno, ""));

	for (i = 0, ci = list_head(&conv->conv_list);
	    i < conv->conv_size && ci != NULL;
	    i++, ci = list_next(&conv->conv_list, ci)) {
		if ((ret = add_resp_conv_item(nvls[i], ci)) != ERRF_OK)
			goto done;
	}

	ret = envlist_add_nvlist_array(resp, KBM_NV_CONV, nvls,
	    conv->conv_size);

done:
	for (i = 0; i < conv->conv_size; i++)
		nvlist_free(nvls[i]);
	free(nvls);
	return (ret);
}

static errf_t *
recovery_alloc(pid_t pid, struct ebox *ebox, recovery_t **rp)
{
	recovery_t *r;

	r = calloc(1, sizeof (*r));
	if (r == NULL)
		return (errfno("calloc", errno, ""));

	r->r_refcnt = 1;
	r->r_state = RSTATE_SELECT_CONFIG;
	r->r_pid = pid;
	r->r_ebox = ebox;

	mutex_enter(&recovery_lock);
	if (recovery_count == UINT32_MAX - 1) {
		mutex_exit(&recovery_lock);
		free(r);
		return (errf("ResourceError", NULL,
		    "too many outstanding recovery attempts"));
	}
	r->r_id = ++recovery_last_id;
	++recovery_count;
	list_insert_tail(&recovery_list, r);
	mutex_exit(&recovery_lock);

	*rp = r;
	return (ERRF_OK);
}

static errf_t *
recovery_lookup(pid_t pid, uint32_t id)
{

}

static errf_t *
add_configs(nvlist_t *restrict resp, struct ebox *restrict ebox)
{
	errf_t *ret = ERRF_OK;
	struct ebox_config *config;
	size_t n;
	uint8_t *guids[GUID_LEN] = { 0 };

	for (n = 0; config = ebox_next_config(ebox, NULL); config != NULL;
	    config = ebox_next_config(ebox, config)) {
		struct ebox_tpl_config *tconfig = ebox_config_tpl(config);

		if (ebox_tpl_config_type(tconfig) == EBOX_RECOVERY)
			n++;
	}

	if ((guids = calloc(n, GUID_LEN)) == NULL) {
		return (errfno("calloc", errno, ""));
	}

	for (n = 0; config = ebox_next_config(ebox, NULL); config != NULL;
	    config = ebox_next_config(ebox, config)) {
		struct ebox_tpl_config *tconfig = ebox_config_tpl(config);

		if (ebox_tpl_config_type(tconfig) != EBOX_RECOVERY)
			continue;

		bcopy(ebox_tpl_part_guid())
	}

}

void
kbmd_recover_start(nvlist_t *req)
{

}
