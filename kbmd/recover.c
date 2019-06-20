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
#include <stddef.h>
#include <string.h>
#include <synch.h>
#include <sys/list.h>
#include "kbmd.h"
#include "pivy/libssh/sshbuf.h"
#include "pivy/words.h"

typedef struct recovery {
	list_node_t		r_node;
	uint32_t		r_id;
	pid_t			r_pid;
	struct ebox		*r_ebox;
	struct ebox_config	*r_cfg;
	uint_t			r_ncfg; /* # of _recovery_ configs */
	uint_t			r_n;	/* # of parts needed */
	uint_t			r_m;	/* total# of parts */
} recovery_t;

enum part_state {
	PART_STATE_LOCKED,
	PART_STATE_UNLOCKED
};

#define	CFG_FOREACH(_cfg, _box)				\
	for ((_cfg) = ebox_next_config((_box), NULL);	\
	(_cfg) != NULL;					\
	(_cfg) = ebox_next_config((_box), (_cfg)))

struct config_question {
	struct ebox_config *cq_cfg;
	char	cq_desc[128];
	char	cq_answer[16];
};

/*
 * Recovery instances use an very coarse locking strategy -- everything is
 * protected by recovery_lock.  It should be rare that more than one
 * recovery operation is happening at a given time.  When that happens, the
 * number of operations should be low (i.e. 10 simultaneous recovery operations
 * would be well beyond the expected use case).  A limit far above what should
 * ever be needed is enforced to flag any potential bugs.
 */

#define	RECOVERY_MAX 16
static mutex_t recovery_lock = ERRORCHECKMUTEX;
static list_t recovery_list;
static uint32_t recovery_count;

static void
recovery_free(void *a)
{
	recovery_t *r = a;

	if (r == NULL)
		return;

	ebox_free(r->r_ebox);
	free(r);
}

void
kbmd_recover_init(void)
{
	mutex_enter(&recovery_lock);
	list_create(&recovery_list, sizeof (recovery_t),
	    offsetof (recovery_t, r_node));
	mutex_exit(&recovery_lock);
}

static errf_t *
make_config_question(struct ebox_config *cfg, size_t idx)
{
	errf_t *ret;
	struct ebox_tpl_config *tcfg = ebox_config_tpl(cfg);
	struct config_question *cq;

	cq = ebox_tpl_config_alloc_private(tcfg, sizeof (*cq));
	if (cq == NULL) {
		ret = errfno("ebox_tpl_config_alloc_private", errno, "");
		return (ret);
	}

	cq->cq_cfg = cfg;
	(void) snprintf(cq->cq_answer, sizeof (cq->cq_answer), "%u", idx + 1);

	/* TODO */
	return (ERRF_OK);
}

static recovery_t *
recovery_get(uint32_t id, pid_t pid)
{
	recovery_t *r;

	ASSERT(MUTEX_HELD(&recovery_lock));

	for (r = list_head(&recovery_list); r != NULL;
	    r = list_next(&recovery_list, r)) {
		if (r->r_id == id && r->r_pid == pid)
			return (r);
	}
	return (NULL);
}

static void
recovery_exit_cb(pid_t pid, void *arg)
{
	recovery_t *r = arg;

	mutex_enter(&recovery_lock);
	list_remove(&recovery_list, r);
	mutex_exit(&recovery_lock);

	recovery_free(r);
}

/*
 * Generate all the challenges for each part (each PIV token in the
 * recovery configuration).
 */
static errf_t *
start_recovery(recovery_t *restrict r, struct ebox_config *restrict cfg)
{
	struct ebox_tpl_config *tconfig = ebox_config_tpl(cfg);
	struct ebox_part *part = NULL;

	r->r_cfg = cfg;
	r->r_n = ebox_tpl_config_n(tconfig);

	while ((part = ebox_config_next_part(cfg, part)) != NULL) {
		errf_t *ret;
		enum part_state *pstate;

		/*
		 * XXX: We should add more context so that we can
		 * say 'recovering <zpool name> part NNN' or
		 * 'recovering soft token .....' or such
		 */
		if ((ret = ebox_gen_challenge(cfg, part,
		    "Recovering box")) != ERRF_OK) {
			return (ret);
		}

		if ((pstate = ebox_part_alloc_private(part,
		    sizeof (*pstate))) == NULL) {
			return (errfno("ebox_part_alloc_private", errno, ""));
		}
		*pstate = PART_STATE_LOCKED;

		r->r_m++;
	}

	return (ERRF_OK);
}

static errf_t *
recovery_alloc_cb(const struct ebox_tpl *tpl __unused,
    struct ebox_tpl_config *tcfg, void *arg)
{
	size_t *np = arg;

	if (ebox_tpl_config_type(tcfg) == EBOX_RECOVERY) {
		(*np)++;
	}

	return (ERRF_OK);
}

static errf_t *
recovery_alloc(pid_t pid, struct ebox *ebox, recovery_t **rp)
{
	errf_t *ret = ERRF_OK;
	recovery_t *r;
	struct ebox_tpl_config *tcfg = NULL;
	struct ebox_config *cfg = NULL;
	size_t n;

	ASSERT(MUTEX_HELD(&recovery_lock));

	if (recovery_count == RECOVERY_MAX) {
		ret = errf("RecoveryFailure", NULL,
		    "too many (%u) outstanding recovery attempts",
		    recovery_count);
		return (ret);
	}

	n = 0;
	VERIFY0(ebox_tpl_foreach_cfg(ebox_tpl(ebox), recovery_alloc_cb,
	    &n));

	if (n == 0) {
		return (errf("RecoveryFailure", NULL,
		    "ebox does not have any recovery configurations"));
	}

	if ((ret = zalloc(sizeof (*r), &r)) != ERRF_OK) {
		return (errf("RecoveryFailure", ret,
		    "no memory for recovery instance"));
	}

	r->r_pid = pid;
	r->r_ebox = ebox;
	r->r_ncfg = n;

	/*
	 * Pick a random id and make sure it's unique.  Zero is also explicitly
	 * excluded as a valid id to help debugging.  In practice, we should
	 * never need to do more than one pass through the loop, but no
	 * reason to not be 100% correct here instead of relying on probability.
	 */
	do {
		r->r_id = arc4random();
		if (r->r_id == 0)
			continue;
	} while (recovery_get(r->r_id, pid) != NULL);

	n = 0;
	CFG_FOREACH(cfg, ebox) {
		tcfg = ebox_config_tpl(cfg);

		if (ebox_tpl_config_type(tcfg) != EBOX_RECOVERY)
			continue;

		/*
		 * If there is only a single recovery configuration, we
		 * always use that.  This should be the common case.
		 */
		if (r->r_ncfg == 1) {
			r->r_cfg = cfg;
			if ((ret = start_recovery(r, cfg)) != ERRF_OK) {
				free(r);
				return (errf("RecoveryFailure", ret,
				    "failed to initialize recovery instance"));
			}
			break;
		}

		if ((ret = make_config_question(cfg, n)) != ERRF_OK) {
			free(r);
			return (errf("RecoveryFailure", ret,
			    "failed to select a recovery instance"));
		}

		n++;
	}
	VERIFY3U(n, ==, r->r_ncfg);

	if ((ret = kbmd_watch_pid(pid, recovery_exit_cb, r)) != ERRF_OK) {
		free(r);
		return (ret);
	}

	list_insert_tail(&recovery_list, r);
	recovery_count++;

	*rp = r;
	return (ERRF_OK);
}

struct get_config_resp_data {
	char			*gcrp_answer;
	struct ebox_config	*gcrp_cfg;
};

static errf_t *
get_config_resp_cb(const struct ebox_tpl *tpl, struct ebox_tpl_config *tcfg,
 void *arg)
{
	struct get_config_resp_data *data = arg;
	struct config_question *cq = ebox_tpl_config_private(tcfg);

	if (cq == NULL) {
		VERIFY3S(ebox_tpl_config_type(tcfg), !=, EBOX_RECOVERY);
		return (ERRF_OK);
	}

	if (strcmp(data->gcrp_answer, cq->cq_answer) == 0) {
		data->gcrp_cfg = cq->cq_cfg;
		return (FOREACH_STOP);
	}

	return (ERRF_OK);
}

static struct ebox_config *
get_config_response(recovery_t *restrict r, nvlist_t *restrict resp)
{
	struct get_config_resp_data arg = { 0 };

	if (nvlist_lookup_string(resp, KBM_NV_ANSWER, &arg.gcrp_answer) != 0)
		return (NULL);

	(void) ebox_tpl_foreach_cfg(ebox_tpl(r->r_ebox), get_config_resp_cb,
	    &arg);
	return (arg.gcrp_cfg);
}

struct select_config_data {
	nvlist_t	**scd_nvls;
	size_t		scd_i;
};

static errf_t *
select_config_cb(const struct ebox_tpl *tpl __unused,
    struct ebox_tpl_config *tcfg, void *arg)
{
	errf_t *ret = ERRF_OK;
	struct select_config_data *data = arg;
	struct config_question *cq = ebox_tpl_config_private(tcfg);
	nvlist_t *nvl = NULL;

	if ((ret = envlist_alloc(&nvl)) != ERRF_OK ||
	    (ret = envlist_add_string(nvl, KBM_NV_DESC,
	    cq->cq_desc)) != ERRF_OK ||
	    (ret = envlist_add_string(nvl, KBM_NV_ANSWER,
	    cq->cq_answer)) != ERRF_OK) {
		nvlist_free(nvl);
		return (ret);
	}

	data->scd_nvls[data->scd_i++] = nvl;
	return (ERRF_OK);
}

static errf_t *
select_config(nvlist_t *restrict req, nvlist_t *restrict resp,
    recovery_t *restrict r)
{
	errf_t *ret = ERRF_OK;
	struct ebox_config *cfg;
	struct select_config_data arg = { 0 };

	ASSERT(MUTEX_HELD(&recovery_lock));

	if ((cfg = get_config_response(r, resp)) != NULL)
		return (start_recovery(r, cfg));

	if ((arg.scd_nvls = calloc(r->r_ncfg, sizeof (nvlist_t *))) == NULL) {
		ret = errfno("calloc", errno, "");
		return (ret);
	}

	if ((ret = ebox_tpl_foreach_cfg(ebox_tpl(r->r_ebox), select_config_cb,
	    &arg)) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_add_string(resp, KBM_NV_PROMPT,
	    "Select recovery configuration")) != ERRF_OK)
		goto done;

	if ((ret = envlist_add_nvlist_array(resp, KBM_NV_CONFIGS, arg.scd_nvls,
	    r->r_ncfg)) != ERRF_OK)
		goto done;

	ret = envlist_add_int32(resp, KBM_NV_ACTION, (int32_t)KBM_ACT_CONFIG);

done:
	if (arg.scd_nvls != NULL) {
		for (size_t i = 0; i < r->r_ncfg; i++)
			nvlist_free(arg.scd_nvls[i]);
		free(arg.scd_nvls);
	}

	return (ret);
}

static errf_t *
add_challenge(nvlist_t **restrict nvlp, struct ebox_tpl_part *restrict tpart,
    struct sshbuf *restrict chalbuf, const char **restrict words,
    size_t wordlen)
{
	errf_t *ret;
	nvlist_t *nvl = NULL;
	char *chal = NULL;
	const char *name = ebox_tpl_part_name(tpart);
	const uint8_t *guid = ebox_tpl_part_guid(tpart);

	if ((ret = envlist_alloc(&nvl)) != ERRF_OK)
		return (ret);

	if ((chal = sshbuf_dtob64(chalbuf)) == NULL) {
		ret = errfno("sshbuf_dtob64", errno, "");
		goto fail;
	}

	if ((ret = envlist_add_uint8_array(nvl, KBM_NV_GUID, guid,
	    GUID_LEN)) != ERRF_OK)
		goto fail;

	if ((ret = envlist_add_string(nvl, KBM_NV_CHALLENGE, chal)) != ERRF_OK)
		goto fail;

	if ((ret = envlist_add_string_array(nvl, KBM_NV_WORDS,
	    (char * const *)words, wordlen)) != ERRF_OK)
		goto fail;

	if (name != NULL &&
	    (ret = envlist_add_string(nvl, KBM_NV_NAME, name)) != ERRF_OK)
		goto fail;

	*nvlp = nvl;
	free(chal);
	return (ERRF_OK);

fail:
	nvlist_free(nvl);
	free(chal);
	return (ret);
}

static errf_t *
process_chal_response(recovery_t *restrict r, nvlist_t *restrict resp)
{
	errf_t *ret = ERRF_OK;
	char *answer = NULL;
	struct sshbuf *buf = NULL;
	struct sshbuf *pbuf = NULL;
	struct piv_ecdh_box *box = NULL;
	enum part_state *pstate = NULL;
	struct ebox_part *part = NULL;

	if (nvlist_lookup_string(resp, KBM_NV_ANSWER, &answer) != 0)
		return (ERRF_OK);

	if ((buf = sshbuf_new()) == NULL)
		return (errf("OutOfMemory", NULL, ""));

	if (sshbuf_b64tod(buf, answer) != 0)
		goto done;

	pbuf = sshbuf_fromb(buf);
	if (sshbuf_get_piv_box(pbuf, &box) != 0)
		goto done;

	/*
	 * A failed response just means we keep asking, and not a fatal error.
	 */
	if ((ret = ebox_challenge_response(r->r_cfg, box, &part)) != ERRF_OK) {
		/*  XXX: warn failed + maybe msg to user? */
		errf_free(ret);
		ret = ERRF_OK;
		goto done;
	}

	pstate = ebox_part_private(part);
	if (*pstate != PART_STATE_UNLOCKED) {
		*pstate = PART_STATE_UNLOCKED;
		r->r_n--;
		r->r_m--;
	}

done:
	sshbuf_free(buf);
	sshbuf_free(pbuf);
	return (ERRF_OK);
}

static errf_t *
challenge(nvlist_t *restrict req, nvlist_t *restrict resp,
    recovery_t *restrict r)
{
	errf_t *ret = ERRF_OK;
	struct ebox_config *cfg = r->r_cfg;
	struct ebox_part *part = NULL;
	struct sshbuf *buf = NULL;
	nvlist_t **nvls = NULL;
	const uint8_t *words = NULL;
	const char **wordstrs = NULL;
	size_t wordlen = 0;
	size_t m;

	ASSERT(MUTEX_HELD(&recovery_lock));

	if ((ret = process_chal_response(r, resp)) != ERRF_OK)
		return (ret);

	if (r->r_n == 0) {
		ret = envlist_add_boolean(resp, KBM_NV_RECOVERY_COMPLETE);
		kbmd_unwatch_pid(r->r_pid);
		list_remove(&recovery_list, r);
		recovery_free(r);
		return (ret);
	}

	if ((nvls = calloc(r->r_m, sizeof (nvlist_t *))) == NULL) {
		ret = errfno("calloc", errno, "");
		goto done;
	}

	if ((buf = sshbuf_new()) == NULL) {
		ret = errf("OutOfMemory", NULL, "");
		goto done;
	}

	if ((ret = envlist_add_uint32(resp, KBM_NV_REMAINING,
	    r->r_m)) != ERRF_OK)
		goto done;

	m = 0;
	while ((part = ebox_config_next_part(cfg, part)) != NULL) {
		enum part_state *statep;
		const struct ebox_challenge *chal;
		char **tmp;

		statep = ebox_part_private(part);
		if (*statep == PART_STATE_UNLOCKED)
			continue;

		chal = ebox_part_challenge(part);
		words = ebox_challenge_words(chal, &wordlen);

		sshbuf_reset(buf);
		if ((ret = sshbuf_put_ebox_challenge(buf, chal)) != ERRF_OK)
			goto done;

		tmp = reallocarray(wordstrs, wordlen, sizeof (char *));
		if (tmp == NULL) {
			ret = errfno("reallocarray", errno, "");
			goto done;
		}
		for (size_t i = 0; i < wordlen; i++)
			wordstrs[i] = wordlist[words[i]];

		if ((ret = add_challenge(&nvls[m], ebox_part_tpl(part), buf,
		    wordstrs, wordlen)) != ERRF_OK)
			goto done;

		m++;
	}
	ASSERT3U(m, ==, r->r_m);

	ret = envlist_add_nvlist_array(resp, KBM_NV_PARTS, nvls, r->r_m);

done:
	if (nvls != NULL) {
		for (size_t i = 0; i < r->r_m; i++)
			nvlist_free(nvls[i]);
		free(nvls);
	}
	sshbuf_free(buf);
	free(wordstrs);
	return (ret);
}

static void
recover_common(nvlist_t *restrict req, recovery_t *restrict r)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;

	ASSERT(MUTEX_HELD(&recovery_lock));

	if ((ret = envlist_alloc(&resp)) != ERRF_OK)
		goto fail;

	if ((nvlist_lookup_boolean(req, KBM_NV_RESP_QUIT)) == 0) {
		if ((ret = envlist_add_boolean(resp,
		    KBM_NV_RESP_QUIT)) != ERRF_OK) {
			goto fail;
		}
		goto done;
	}

	/*
	 * The two NULL checks are intentional-if we haven't selected a
	 * configuration, we attempt to do so.  The selection can
	 * happen in two ways:
	 *
	 *	1. Only one configuration exists.  This is the usual case and
	 *	the single configuration is selected and r->r_cfg is set.
	 *
	 *	2. Multiple configuration exist.  This typically happens when
	 *	a recovery occurs during a transition between and older
	 *	recovery configuration and the current configuration (since
	 *	we always add the new, then remove the old config).  In this
	 *	case, we must prompt to select the appropriate configuration
	 *	to use.  r->r_cfg will not be set until the user selects
	 *	the configuration (which might include multiple round trips
	 *	of prompting).
	 *
	 * As a result, if r->r_cfg is still NULL after a successful return of
	 * select_config(), it means we're prompting the user to select a
	 * configuration, and shouldn't attempt to start the challenge yet.
	 */
	if (r->r_cfg == NULL &&
	   (ret = select_config(req, resp, r)) != ERRF_OK ||
	   r->r_cfg == NULL)
		goto done;

	ret = challenge(req, resp, r);

done:
	if ((ret = envlist_add_boolean_value(resp, KBM_NV_SUCCESS,
	    B_TRUE)) != ERRF_OK) {
		goto fail;
	}

	nvlist_free(req);
	mutex_exit(&recovery_lock);
	kbmd_ret_nvlist(resp);

fail:
	nvlist_free(req);
	mutex_exit(&recovery_lock);
	kbmd_ret_error(ret);
}

void
kbmd_recover_start(nvlist_t *req, pid_t pid)
{
	errf_t *ret = ERRF_OK;
	struct ebox *ebox = NULL;
	recovery_t *r = NULL;

	if ((ret = kbmd_get_ebox(zones_dataset, &ebox)) != ERRF_OK)
		goto fail;

	mutex_enter(&recovery_lock);

	if ((ret = recovery_alloc(pid, ebox, &r)) != ERRF_OK) {
		ASSERT3P(r, ==, NULL);
		mutex_exit(&recovery_lock);
		goto fail;
	}
	ebox = NULL;

	return (recover_common(req, r));

fail:
	if (ebox != NULL)
		ebox_free(ebox);
	nvlist_free(req);
	kbmd_ret_error(ret);
}

void
kbmd_recover_resp(nvlist_t *req, pid_t pid)
{
	errf_t *ret = NULL;
	recovery_t *r = NULL;
	uint32_t id;

	if ((ret = envlist_lookup_uint32(req, KBM_NV_RECOVER_ID,
	    &id)) != ERRF_OK)
		kbmd_ret_error(ret);

	mutex_enter(&recovery_lock);
	if ((r = recovery_get(id, pid)) == NULL) {
		mutex_exit(&recovery_lock);
		ret = errf("NotFoundError", NULL,
		   "no matching recovery session found");
		kbmd_ret_error(ret);
	}

	recover_common(req, r);
}

errf_t *
get_request_template(nvlist_t *restrict nvl, struct ebox_tpl **restrict tplp)
{
	errf_t *ret = ERRF_OK;
	struct sshbuf *buf = NULL;
	uint8_t *bytes = NULL;
	uint_t nbytes = 0;

	if ((ret = envlist_lookup_uint8_array(nvl, KBM_NV_TEMPLATE, &bytes,
	    &nbytes)) != ERRF_OK)
		return (ret);

	if ((buf = sshbuf_from(bytes, nbytes)) == NULL) {
		return (errfno("sshbuf_from", errno,
		    "cannot allocate ebox template"));
	}

	ret = sshbuf_get_ebox_tpl(buf, tplp);
	sshbuf_free(buf);
	return (ret);
}

void
kbmd_update_recovery(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;
	kbmd_token_t *kt = NULL;
	struct ebox *ebox_old = NULL, *ebox_new = NULL;
	struct ebox_tpl *tpl = NULL;

	if ((ret = envlist_alloc(&resp)) != ERRF_OK) {
		kbmd_ret_error(ret);
	}

	mutex_enter(&piv_lock);

	if (sys_box == NULL) {
		mutex_exit(&piv_lock);
		nvlist_free(resp);
		kbmd_ret_error(errf("UnlockError", NULL,
		    "system zpool dataset must be unlocked before updating "
		    "its recovery template"));
	}
	VERIFY3P(zones_dataset, !=, NULL);

	if ((ret = get_template(kpiv, &tpl)) != ERRF_OK ||
	    (ret = add_supplied_template(req, tpl, B_TRUE)) != ERRF_OK) {
		mutex_exit(&piv_lock);
		nvlist_free(resp);
		kbmd_ret_error(ret);
	}

	if ((ret = kbmd_get_ebox(zones_dataset, &ebox_old)) != ERRF_OK ||
	    (ret = kbmd_unlock_ebox(ebox_old, &kt)) != ERRF_OK) {
		mutex_exit(&piv_lock);
		nvlist_free(resp);
		kbmd_ret_error(ret);
	}
	VERIFY3P(kt, ==, kpiv);
	VERIFY0(strcmp(ebox_private(ebox_old), zones_dataset));

	if ((ret = kbmd_ebox_clone(ebox_old, &ebox_new, tpl, kt)) != ERRF_OK) {
		mutex_exit(&piv_lock);
		nvlist_free(resp);
		ebox_tpl_free(tpl);
		kbmd_ret_error(ret);
	}

	if ((ret = kbmd_put_ebox(ebox_new)) != ERRF_OK) {
		nvlist_free(resp);
		ebox_tpl_free(tpl);
		mutex_exit(&piv_lock);
		kbmd_ret_error(ret);
	}

	if (ebox_old == sys_box)
		sys_box = ebox_new;
	ebox_free(ebox_old);
	ebox_old = ebox_new;
	ebox_new = NULL;

	kbmd_set_token(kt);

	mutex_exit(&piv_lock);
	kbmd_ret_nvlist(resp);
}
