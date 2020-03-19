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

#include <errno.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <string.h>
#include <synch.h>
#include <sys/refhash.h>
#include "kbmd.h"
#include "pivy/libssh/sshbuf.h"
#include "pivy/libssh/ssherr.h"
#include "pivy/libssh/sshkey.h"
#include "pivy/words.h"

typedef struct recovery {
	refhash_link_t		r_link;
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

struct config_question {
	struct ebox_config *cq_cfg;
	char	cq_answer[16];
};

struct add_data {
	nvlist_t **ad_nvls;
	size_t ad_i;
};

/*
 * Recovery instances use an very coarse locking strategy -- everything is
 * protected by recovery_lock.  It should be rare that more than one
 * recovery operation is happening at a given time.  When that happens, the
 * number of operations should be low (i.e. 10 simultaneous recovery operations
 * would be well beyond the expected use case).  A limit far above what should
 * ever be needed is enforced to flag any potential bugs.
 */

#define	BUCKET_COUNT 7
#define	RECOVERY_MAX 16
static mutex_t recovery_lock = ERRORCHECKMUTEX;
static refhash_t *recovery_hash;
static uint32_t recovery_count;

static uint64_t
rec_hash(const void *tp)
{
	const uint32_t *idp = tp;
	return (*idp);
}

static int
rec_cmp(const void *ta, const void *tb)
{
	const uint32_t *id_a = ta;
	const uint32_t *id_b = tb;

	if (*id_a < *id_b) {
		return (-1);
	}
	if (*id_a > *id_b) {
		return (1);
	}
	return (0);
}

static void
recovery_free(void *a)
{
	recovery_t *r = a;

	if (r == NULL)
		return;

	/*
	 * r_cfg points to a config within r_ebox, so ebox_free() will
	 * free it when freeing r_ebox.
	 */
	ebox_free(r->r_ebox);
	free(r);
}

static void
recovery_add(recovery_t *r)
{
	VERIFY(MUTEX_HELD(&recovery_lock));

	refhash_insert(recovery_hash, r);
	recovery_count++;
}

static void
recovery_remove(recovery_t *r)
{
	VERIFY(MUTEX_HELD(&recovery_lock));

	recovery_count--;
	refhash_remove(recovery_hash, r);
}

static void
recovery_hold(recovery_t *r)
{
	VERIFY(MUTEX_HELD(&recovery_lock));

	refhash_hold(recovery_hash, r);
}

static void
recovery_rele(recovery_t *r)
{
	VERIFY(MUTEX_HELD(&recovery_lock));

	refhash_rele(recovery_hash, r);
}

void
kbmd_recover_init(int dfd)
{
	mutex_enter(&recovery_lock);
	recovery_hash = refhash_create(BUCKET_COUNT, rec_hash, rec_cmp,
	    recovery_free, sizeof (recovery_t), offsetof(recovery_t, r_link),
	    offsetof(recovery_t, r_id), 0);
	mutex_exit(&recovery_lock);

	if (recovery_hash == NULL) {
		kbmd_dfatal(dfd, "failed to create recovery hash table");
	}
}

static errf_t *
count_parts(struct ebox_tpl_part *tpart __unused, void *arg)
{
	size_t *np = arg;

	(*np)++;
	return (ERRF_OK);
}

static errf_t *
count_recovery_configs(struct ebox_tpl_config *tcfg, void *arg)
{
	size_t *np = arg;

	if (ebox_tpl_config_type(tcfg) != EBOX_RECOVERY) {
		return (ERRF_OK);
	}

	(*np)++;
	return (ERRF_OK);
}

static errf_t *
strip_primary_cb(struct ebox_tpl_config *tcfg, void *arg)
{
	struct ebox_tpl *tpl = arg;
	if (ebox_tpl_config_type(tcfg) == EBOX_PRIMARY) {
		ebox_tpl_remove_config(tpl, tcfg);
		ebox_tpl_config_free(tcfg);
	}
	return (ERRF_OK);
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
	(void) snprintf(cq->cq_answer, sizeof (cq->cq_answer), "%zu", idx + 1);

	return (ERRF_OK);
}

static recovery_t *
recovery_get(uint32_t id, pid_t pid)
{
	recovery_t *r;

	VERIFY(MUTEX_HELD(&recovery_lock));

	r = refhash_lookup(recovery_hash, &id);
	/*
	 * While the id's are globally unique, we also currently restrict a
	 * recovery instance to the process that originally created it.
	 * A process trying to use another process's recovery id is ignored.
	 */
	if (r == NULL || r->r_pid != pid) {
		return (NULL);
	}

	return (r);
}

static void
recovery_exit_cb(pid_t pid, void *arg)
{
	recovery_t *r = arg;

	mutex_enter(&recovery_lock);
	recovery_remove(r);
	recovery_rele(r);
	mutex_exit(&recovery_lock);
}

errf_t *
template_hash(const struct ebox_tpl *tpl, uint8_t **hashp, size_t *lenp)
{
	errf_t *ret = ERRF_OK;
	struct ebox_tpl *tpl_clone = NULL;
	struct sshbuf *buf = NULL;
	char *b64str = NULL;

	*hashp = NULL;
	*lenp = 0;

	if ((tpl_clone = ebox_tpl_clone(tpl)) == NULL) {
		ret = errf("OutOfMemory", NULL, "ebox_tpl_clone failed");
		goto done;
	}

	if ((buf = sshbuf_new()) == NULL) {
		ret = errfno("sshbuf_new", errno, "cannot create sshbuf");
		goto done;
	}

	if ((ret = ebox_tpl_foreach_cfg(tpl_clone, strip_primary_cb,
	    tpl_clone)) != ERRF_OK) {
		goto done;
	}

	/*
	 * Serialize the template and then hash the base64 serialized form.
	 */
	if ((ret = sshbuf_put_ebox_tpl(buf, tpl_clone)) != ERRF_OK) {
		goto done;
	}

	if ((b64str = sshbuf_dtob64(buf)) == NULL) {
		ret = errf("sshbuf_dtob64", NULL,
		    "unable to convert ebox template to base64");
		goto done;
	}

	if ((ret = zalloc(SHA512_DIGEST_LENGTH, hashp)) != ERRF_OK) {
		goto done;
	}
	*lenp = SHA512_DIGEST_LENGTH;

	/*
	 * SHA512() returns a pointer to the buffer containing the hash.
	 * Since we supply our own buffer, we don't need to worry about the
	 * return value.
	 */
	(void) SHA512((const unsigned char *)b64str, strlen(b64str), *hashp);

done:
	free(b64str);
	sshbuf_free(buf);
	ebox_tpl_free(tpl_clone);
	return (ret);
}

static errf_t *
add_part(struct ebox_tpl_part *tpart, void *arg)
{
	errf_t *ret = ERRF_OK;
	struct add_data *data = arg;
	nvlist_t *nvl = NULL;
	struct sshkey *pubkey = NULL;
	struct sshbuf *buf = NULL;
	const uint8_t *guid = NULL;
	const char *name = NULL;
	enum piv_slotid slotid;
	int rc;

	if ((ret = envlist_alloc(&nvl)) != ERRF_OK) {
		goto done;
	}

	pubkey = ebox_tpl_part_pubkey(tpart);
	guid = ebox_tpl_part_guid(tpart);
	name = ebox_tpl_part_name(tpart);
	slotid = ebox_tpl_part_slot(tpart);

	if ((ret = envlist_add_uint8_array(nvl, KBM_NV_GUID, guid,
	    GUID_LEN)) != ERRF_OK ||
	    (ret = envlist_add_int32(nvl, KBM_NV_SLOT, slotid)) != ERRF_OK)
		goto done;

	if ((buf = sshbuf_new()) == NULL) {
		ret = errfno("sshbuf_new", ENOMEM, "failed to allocate sshbuf");
		goto done;
	}

	if ((rc = sshkey_format_text(pubkey,  buf)) != 0) {
		ret = ssherrf("sshkey_format_text", rc,
		    "failed to convert public key");
		sshbuf_free(buf);
		goto done;
	}

	ret = envlist_add_string(nvl, KBM_NV_PUBKEY,
	    (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	if (ret != ERRF_OK) {
		goto done;
	}

	if (name != NULL &&
	   (ret = envlist_add_string(nvl, KBM_NV_NAME, name)) != ERRF_OK) {
		goto done;
	}

	data->ad_nvls[data->ad_i++] = nvl;

done:
	if (ret != ERRF_OK) {
		nvlist_free(nvl);
	}

	return (ret);
}

static errf_t *
add_config(struct ebox_tpl_config *tcfg, void *arg)
{
	errf_t *ret = ERRF_OK;
	struct add_data *cfgdata = arg;
	struct add_data part_data = { 0 };
	nvlist_t *nvl = NULL;
	size_t nparts = 0;
	uint_t n = 0;

	if (ebox_tpl_config_type(tcfg) != EBOX_RECOVERY) {
		return (ERRF_OK);
	}

	VERIFY0(ebox_tpl_foreach_part(tcfg, count_parts, &nparts));

	if ((ret = envlist_alloc(&nvl)) != ERRF_OK ||
	    (ret = ecalloc(nparts, sizeof (nvlist_t *),
	    &part_data.ad_nvls)) != ERRF_OK) {
		nvlist_free(nvl);
		return (ret);
	}

	n = ebox_tpl_config_n(tcfg);
	if ((ret = envlist_add_uint32(nvl, KBM_NV_N, (uint32_t)n)) != ERRF_OK) {
		goto done;
	}

	if ((ret = ebox_tpl_foreach_part(tcfg, add_part,
	    &part_data)) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_add_nvlist_array(nvl, KBM_NV_PARTS,
	    part_data.ad_nvls, nparts)) != ERRF_OK) {
		goto done;
	}

	cfgdata->ad_nvls[cfgdata->ad_i++] = nvl;

done:
	for (size_t i = 0; i < nparts; i++) {
		nvlist_free(part_data.ad_nvls[i]);
	}
	free(part_data.ad_nvls);

	if (ret != ERRF_OK) {
		nvlist_free(nvl);
	}

	return (ret);
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
recovery_alloc(pid_t pid, struct ebox *ebox, recovery_t **rp)
{
	errf_t *ret = ERRF_OK;
	recovery_t *r;
	struct ebox_tpl_config *tcfg = NULL;
	struct ebox_config *cfg = NULL;
	size_t ncfg = 0;

	ASSERT(MUTEX_HELD(&recovery_lock));

	if (recovery_count == RECOVERY_MAX) {
		ret = errf("RecoveryFailure", NULL,
		    "too many (%u) outstanding recovery attempts",
		    recovery_count);
		return (ret);
	}

	VERIFY0(ebox_tpl_foreach_cfg(ebox_tpl(ebox), count_recovery_configs,
	    &ncfg));

	if (ncfg == 0) {
		return (errf("RecoveryFailure", NULL,
		    "ebox does not have any recovery configurations"));
	}

	if ((ret = zalloc(sizeof (*r), &r)) != ERRF_OK) {
		return (errf("RecoveryFailure", ret,
		    "no memory for recovery instance"));
	}

	r->r_pid = pid;
	r->r_ebox = ebox;
	r->r_ncfg = ncfg;

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

	ncfg = 0;
	while ((cfg = ebox_next_config(ebox, cfg)) != NULL) {
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
			ncfg++;
			break;
		}

		if ((ret = make_config_question(cfg, ncfg)) != ERRF_OK) {
			free(r);
			return (errf("RecoveryFailure", ret,
			    "failed to select a recovery instance"));
		}

		ncfg++;
	}
	VERIFY3U(ncfg, ==, r->r_ncfg);

	recovery_add(r);
	recovery_hold(r);
	if ((ret = kbmd_watch_pid(pid, recovery_exit_cb, r)) != ERRF_OK) {
		recovery_remove(r);
		recovery_rele(r);
		return (ret);
	}

	*rp = r;
	return (ERRF_OK);
}

struct get_config_resp_data {
	char			*gcrp_answer;
	struct ebox_config	*gcrp_cfg;
};

static errf_t *
get_config_resp_cb(struct ebox_tpl_config *tcfg, void *arg)
{
	struct get_config_resp_data *data = arg;
	struct config_question *cq = ebox_tpl_config_private(tcfg);

	if (cq == NULL) {
		VERIFY3S(ebox_tpl_config_type(tcfg), !=, EBOX_RECOVERY);
		return (ERRF_OK);
	}

	if (strcmp(data->gcrp_answer, cq->cq_answer) == 0) {
		(void) bunyan_debug(tlog, "Recovery configuration selected",
		    BUNYAN_T_STRING, "cfgnum", cq->cq_answer,
		    BUNYAN_T_END);

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

static errf_t *
select_config_cb(struct ebox_tpl_config *tcfg, void *arg)
{
	errf_t *ret = ERRF_OK;
	struct add_data *data = arg;
	struct config_question *cq = ebox_tpl_config_private(tcfg);
	nvlist_t *nvl = NULL;

	if ((ret = add_config(tcfg, arg)) != ERRF_OK) {
		return (ret);
	}

	VERIFY3U(data->ad_i, >, 0);
	nvl = data->ad_nvls[data->ad_i - 1];

	if ((ret = envlist_add_string(nvl, KBM_NV_ANSWER,
	    cq->cq_answer)) != ERRF_OK) {
		return (ret);
	}

	return (ERRF_OK);
}

static errf_t *
select_config(nvlist_t *restrict req, nvlist_t *restrict resp,
    recovery_t *restrict r)
{
	errf_t *ret = ERRF_OK;
	struct ebox_config *cfg;
	struct add_data arg = { 0 };

	ASSERT(MUTEX_HELD(&recovery_lock));

	if ((cfg = get_config_response(r, resp)) != NULL)
		return (start_recovery(r, cfg));

	if ((ret = ecalloc(r->r_ncfg, sizeof (nvlist_t *),
	    &arg.ad_nvls)) != ERRF_OK) {
		return (ret);
	}

	if ((ret = ebox_tpl_foreach_cfg(ebox_tpl(r->r_ebox), select_config_cb,
	    &arg)) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_add_string(resp, KBM_NV_PROMPT,
	    "Select recovery configuration")) != ERRF_OK)
		goto done;

	if ((ret = envlist_add_nvlist_array(resp, KBM_NV_CONFIGS, arg.ad_nvls,
	    r->r_ncfg)) != ERRF_OK)
		goto done;

	ret = envlist_add_int32(resp, KBM_NV_ACTION, (int32_t)KBM_ACT_CONFIG);

done:
	if (arg.ad_nvls != NULL) {
		for (size_t i = 0; i < r->r_ncfg; i++)
			nvlist_free(arg.ad_nvls[i]);
		free(arg.ad_nvls);
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

	if (nvlist_lookup_string(resp, KBM_NV_ANSWER, &answer) != 0) {
		(void) bunyan_debug(tlog, "No answer in response",
		    BUNYAN_T_END);
		return (ERRF_OK);
	}

	if ((buf = sshbuf_new()) == NULL) {
		return (errf("OutOfMemory", NULL, ""));
	}

	if (sshbuf_b64tod(buf, answer) != 0) {
		ret = errf("ChallengeError", NULL,
		    "Failed to decode challenge response");
		goto done;
	}

	pbuf = sshbuf_fromb(buf);
	if (sshbuf_get_piv_box(pbuf, &box) != 0) {
		ret = errf("ChallengeError", NULL,
		    "Invalid challenge response");
		goto done;
	}

	if ((ret = ebox_challenge_response(r->r_cfg, box, &part)) != ERRF_OK) {
		goto done;
	}

	pstate = ebox_part_private(part);
	if (*pstate != PART_STATE_UNLOCKED) {
		struct ebox_tpl_part *tpart = ebox_part_tpl(part);
		const char *pname = ebox_tpl_part_name(tpart);

		if (pname == NULL) {
			pname = "(not set)";
		}

		(void) bunyan_debug(tlog, "Unlocked part",
		    BUNYAN_T_STRING, "partname", pname,
		    BUNYAN_T_END);

		*pstate = PART_STATE_UNLOCKED;
		r->r_n--;
		r->r_m--;
	}

done:
	sshbuf_free(buf);
	sshbuf_free(pbuf);
	return (ret);
}

struct update_data {
	kbmd_token_t		*ud_tok;
	const recovery_token_t	*ud_rtok;
	struct ebox_tpl		*ud_rcfg;
	size_t		ud_primary_count;
};

static errf_t *
piv_replace_cb(struct ebox_tpl_config *tcfg, void *arg)
{
	struct update_data *data = arg;
	struct ebox_tpl_part *tpart = NULL;

	if (ebox_tpl_config_type(tcfg) != EBOX_PRIMARY) {
		return (ERRF_OK);
	}

	if (data->ud_primary_count++ > 0) {
		return (errf("TemplateError", NULL,
		    "template has multiple EBOX_PRIMARY configs"));
	}

	/*
	 * Since this is an EBOX_PRIMARY config, we assume a single
	 * template part.  We also shouldn't have been able to create an
	 * ebox without an EBOX_PRIMARY config without a part.
	 */
	tpart = ebox_tpl_config_next_part(tcfg, NULL);
	if (tpart == NULL) {
		return (errf("TemplateError", NULL,
		    "EBOX_PRIMARY has no config parts"));
	}

	return (replace_pivtoken(ebox_tpl_part_guid(tpart), data->ud_rtok,
	    data->ud_tok, &data->ud_rcfg));
}

/*
 * Using the ebox template, determine the GUID of the old PIV token,
 * and call the replace pivtoken plugin using rtoken as the recovery
 * token/key for the replacement and newkt as the new recovery token.
 * On success, newkt's recovery token is set to the new value returned
 * from the plugin.
 */
static errf_t *
do_piv_replace(struct ebox *ebox, kbmd_token_t *newkt,
    const recovery_token_t *rtoken, struct ebox_tpl **rcfgp)
{
	errf_t *ret = ERRF_OK;
	struct update_data data = {
		.ud_tok = newkt,
		.ud_rtok = rtoken,
	};

	*rcfgp = NULL;

	if ((ret = ebox_tpl_foreach_cfg(ebox_tpl(ebox), piv_replace_cb,
	    &data)) != ERRF_OK) {
		ret = errf("RecoveryError", ret,
		    "failed to create ebox template with new PIV token");
	}

	*rcfgp = data.ud_rcfg;

	return (ret);
}

static errf_t *
post_recovery(recovery_t *r)
{
	errf_t *ret = ERRF_OK;
	kbmd_token_t *kt = NULL;
	struct ebox *new_ebox = NULL;
	struct ebox_tpl *tpl = NULL;
	struct ebox_tpl *rcfg = NULL;
	struct ebox_tpl *rcfg_oldebox = NULL;
	struct ebox_tpl *rcfg_newpiv = NULL;
	const char *dataset = NULL;
	const uint8_t *key = NULL;
	size_t keylen = 0;
	recovery_token_t rtoken = { 0 };
	boolean_t is_encrypted = B_TRUE, is_locked = B_TRUE;

	if ((ret = ebox_recover(r->r_ebox, r->r_cfg)) != ERRF_OK &&
	    !errf_caused_by(ret, "AlreadyUnlocked")) {
		return (ret);
	}

	dataset = ebox_private(r->r_ebox);

	key = ebox_key(r->r_ebox, &keylen);
	VERIFY3P(key, !=, NULL);

	rtoken.rt_val = (uint8_t *)ebox_recovery_token(r->r_ebox,
	    &rtoken.rt_len);

	rcfg_oldebox = ebox_tpl(r->r_ebox);

	/*
	 * If we can determine if the dataset key is already loaded,
	 * we'll avoid re-loading the key.  If not, we'll still try.
	 */
	ret = get_dataset_status(dataset, &is_encrypted, &is_locked);
	errf_free(ret);

	if (is_locked && (ret = load_key(dataset, key, keylen)) != ERRF_OK) {
		return (ret);
	}

	if ((ret = kbmd_setup_token(&kt)) != ERRF_OK) {
		if (errf_caused_by(ret, "NotFoundError")) {
			/*
			 * XXX: Might we also want to spit this out to
			 * syslog and/or the console?
			 */
			(void) bunyan_warn(tlog,
			    "No uninitialized tokens found for replacement; "
			    "recovery will need to be run again when one is "
			    "available",
			    BUNYAN_T_END);
		} else {
			ret = errf("RecoveryError", ret,
			    "cannot setup replacement token");
		}

		return (ret);
	}

	/*
	 * This sets kt's recovery token to the new value from
	 * the plugin on success (see above).
	 *
	 * TODO: If we setup a new PIV token, but failed to do the
	 * replacement, we want a way to retry the recovery without
	 * re-initializing the PIV token and just retry the replacement.
	 */
	if ((ret = do_piv_replace(r->r_ebox, kt, &rtoken,
	    &rcfg_newpiv)) != ERRF_OK) {
		kbmd_token_free(kt);
		return (ret);
	}

	/*
	 * If the replacement plugin gives us a recovery token, we use that.
	 * Otherwise we use the recovery configuration from the ebox we
	 * recovered.
	 */
	rcfg = (rcfg_newpiv != NULL) ? rcfg_newpiv : rcfg_oldebox;

	if ((ret = piv_txn_begin(kt->kt_piv)) != ERRF_OK ||
	    (ret = piv_select(kt->kt_piv)) != ERRF_OK ||
	    (ret = create_template(kt, rcfg, &tpl)) != ERRF_OK) {
		if (piv_token_in_txn(kt->kt_piv))
			piv_txn_end(kt->kt_piv);
		kbmd_token_free(kt);
		ebox_tpl_free(rcfg_newpiv);
		return (ret);
	}
	ebox_tpl_free(rcfg_newpiv);
	piv_txn_end(kt->kt_piv);

	/*
	 * The new/replacement ebox needs to use the new/replacement
	 * recovery token in kt -- not the old one in rtoken!
	 *
	 * TODO: Figure out how to handle a staged ebox when doing a
	 * recovery.
	 */
	if ((ret = ebox_create(tpl, key, keylen, kt->kt_rtoken.rt_val,
	    kt->kt_rtoken.rt_len, &new_ebox)) != ERRF_OK ||
	    (ret = set_box_name(new_ebox, dataset)) != ERRF_OK ||
	    (ret = kbmd_put_ebox(new_ebox, B_FALSE)) != ERRF_OK) {
		ebox_free(new_ebox);
		return (ret);
	}

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

	(void) bunyan_trace(tlog, "challenge(): enter", BUNYAN_T_END);

	ASSERT(MUTEX_HELD(&recovery_lock));

	/*
	 * Any failures with processing a response are noted, but otherwise
	 * ignored.
	 */
	if ((ret = process_chal_response(r, req)) != ERRF_OK) {
		(void) bunyan_info(tlog, "Failed to process challenge response",
		    BUNYAN_T_STRING, "caused_by", errf_name(ret),
		    BUNYAN_T_STRING, "errmsg", errf_message(ret),
		    BUNYAN_T_STRING, "err_func", errf_function(ret),
		    BUNYAN_T_STRING, "err_file", errf_file(ret),
		    BUNYAN_T_UINT32, "err_line", (uint32_t)errf_line(ret),
		    BUNYAN_T_END);
		errf_free(ret);
		ret = ERRF_OK;
	}

	if (r->r_n == 0) {
		(void) bunyan_debug(tlog,
		    "challenge threshold met; decrypting box",
		    BUNYAN_T_END);

		if ((ret = post_recovery(r)) != ERRF_OK) {
			(void) bunyan_info(tlog, "Recovery failed",
			    BUNYAN_T_STRING, "caused_by", errf_name(ret),
			    BUNYAN_T_STRING, "errmsg", errf_message(ret),
			    BUNYAN_T_STRING, "err_func", errf_function(ret),
			    BUNYAN_T_STRING, "err_file", errf_file(ret),
			    BUNYAN_T_UINT32, "err_line",
			    (uint32_t)errf_line(ret),
			    BUNYAN_T_END);
		} else {
			(void) bunyan_info(tlog, "Recovery complete",
			    BUNYAN_T_END);
		}

		/*
		 * No matter the result of the recovery, once we hit
		 * the threshold, we're done recovering, so tell kbmadm
		 * we're done.
		 *
		 * If adding this fails, it just means kbmadm might generate
		 * an error. Realistically, this only happens when the
		 * system is extremely starved for memory.  Under such
		 * circumstances, it's unlikely much of anything
		 * will actually be working correctly.
		 *
		 */
		(void) nvlist_add_boolean_value(resp, KBM_NV_RECOVERY_COMPLETE,
		    B_TRUE);

		kbmd_unwatch_pid(r->r_pid);
		recovery_remove(r);
		recovery_rele(r);
		return (ret);
	}

	if ((ret = ecalloc(r->r_m, sizeof (nvlist_t *), &nvls)) != ERRF_OK) {
		goto done;
	}

	if ((buf = sshbuf_new()) == NULL) {
		ret = errf("OutOfMemory", NULL, "");
		goto done;
	}

	if ((ret = envlist_add_int32(resp, KBM_NV_ACTION,
	    KBM_ACT_CHALLENGE)) != ERRF_OK ||
	    (ret = envlist_add_uint32(resp, KBM_NV_REMAINING,
	    r->r_n)) != ERRF_OK) {
		goto done;
	}

	m = 0;
	while ((part = ebox_config_next_part(cfg, part)) != NULL) {
		enum part_state *statep;
		struct ebox_tpl_part *tpart = ebox_part_tpl(part);
		const struct ebox_challenge *chal;
		const char **tmp;

		statep = ebox_part_private(part);
		if (*statep == PART_STATE_UNLOCKED)
			continue;

		chal = ebox_part_challenge(part);
		words = ebox_challenge_words(chal, &wordlen);

		(void) bunyan_trace(tlog, "Adding challenge part",
		    BUNYAN_T_STRING, "partname", ebox_tpl_part_name(tpart),
		    BUNYAN_T_UINT32, "wordlen", (uint32_t)wordlen,
		    BUNYAN_T_END);

		sshbuf_reset(buf);
		if ((ret = sshbuf_put_ebox_challenge(buf, chal)) != ERRF_OK)
			goto done;

		tmp = reallocarray(wordstrs, wordlen, sizeof (char *));
		if (tmp == NULL) {
			ret = errfno("reallocarray", errno, "");
			goto done;
		}
		wordstrs = tmp;

		for (size_t i = 0; i < wordlen; i++) {
			wordstrs[i] = wordlist[words[i]];
		}

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
	boolean_t quit;

	ASSERT(MUTEX_HELD(&recovery_lock));

	(void) bunyan_key_add(tlog, "recover_id", BUNYAN_T_UINT32, r->r_id);

	if ((ret = envlist_alloc(&resp)) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_add_uint32(resp, KBM_NV_RECOVER_ID,
	    r->r_id)) != ERRF_OK) {
		ret = errf("InternalError", ret,
		    "user response is missing a recovery id");
		goto done;
	}

	if ((nvlist_lookup_boolean_value(req, KBM_NV_RESP_QUIT, &quit)) == 0 &&
	    quit) {
		(void) bunyan_info(tlog, "User terminated recovery",
		    BUNYAN_T_END);

		ret = envlist_add_boolean_value(resp, KBM_NV_RESP_QUIT, B_TRUE);
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
	   ((ret = select_config(req, resp, r)) != ERRF_OK ||
	   r->r_cfg == NULL))
		goto done;

	ret = challenge(req, resp, r);

done:
	nvlist_free(req);
	mutex_exit(&recovery_lock);
	(void) bunyan_key_remove(tlog, "recover_id");

	kbmd_return(ret, resp);
}

void
kbmd_recover_start(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	struct ebox *ebox = NULL;
	recovery_t *r = NULL;
	const char *dataset = NULL;
	uint32_t cfgnum = 0;
	pid_t pid = req_pid();

	(void) bunyan_info(tlog, "Request to start recovery",
	    BUNYAN_T_END);

	if ((ret = get_dataset(req, &dataset)) != ERRF_OK)
		goto fail_nolock;

	if ((ret = kbmd_get_ebox(dataset, B_FALSE, &ebox)) != ERRF_OK)
		goto fail_nolock;

	mutex_enter(&recovery_lock);

	if ((ret = recovery_alloc(pid, ebox, &r)) != ERRF_OK) {
		ASSERT3P(r, ==, NULL);
		goto fail;
	}

	if ((ret = envlist_lookup_uint32(req, KBM_NV_CONFIG_NUM,
	    &cfgnum)) != ERRF_OK) {
		/*
		 * If the operator does not specify a specific configuration
		 * at the start of recovery, we just prompt them to select
		 * a configuration (instead of erroring out).
		 */
		errf_free(ret);
	} else {
		if (cfgnum == 0 || cfgnum > r->r_ncfg) {
			(void) bunyan_info(tlog,
			    "Operator requested recovery with non-existent "
			    "recovery config",
			    BUNYAN_T_UINT32, "cfgnum", cfgnum,
			    BUNYAN_T_UINT32, "ncfg", r->r_ncfg,
			    BUNYAN_T_END);
			cfgnum = 0;
		} else if (r->r_cfg != NULL) {
			struct ebox_config *cfg = NULL;
			size_t i = 1;

			while ((cfg = ebox_next_config(ebox, cfg)) != NULL) {
				if (i == cfgnum) {
					break;
				}

				i++;
			}
			r->r_cfg = cfg;

			if ((ret = start_recovery(r, cfg)) != ERRF_OK) {
				goto fail;
			}

		}
	}

	(void) bunyan_info(tlog, "Recovery started",
	    BUNYAN_T_UINT32, "recover_id", r->r_id,
	    (cfgnum > 0) ? BUNYAN_T_UINT32 : BUNYAN_T_END, "cfgnum", cfgnum,
	    BUNYAN_T_END);

	return (recover_common(req, r));

fail:
	if (r != NULL) {
		kbmd_unwatch_pid(pid);
		recovery_remove(r);
		recovery_rele(r);
	} else {
		/*
		 * The recovery_t instance takes ownership of the ebox we
		 * created.  If there is no recovery instance, then we
		 * might still have an allocated ebox to dispose of.
		 */
		ebox_free(ebox);
	}
	mutex_exit(&recovery_lock);

fail_nolock:
	nvlist_free(req);
	kbmd_return(ret, NULL);
}

void
kbmd_recover_resp(nvlist_t *req)
{
	errf_t *ret = NULL;
	recovery_t *r = NULL;
	pid_t pid = req_pid();
	uint32_t id;

	if ((ret = envlist_lookup_uint32(req, KBM_NV_RECOVER_ID,
	    &id)) != ERRF_OK) {
		ret = errf("InternalError", ret,
		    "response is missing a recovery id");
		kbmd_return(ret, NULL);
	}

	mutex_enter(&recovery_lock);
	if ((r = recovery_get(id, pid)) == NULL) {
		mutex_exit(&recovery_lock);
		ret = errf("NotFoundError", NULL,
		   "no matching recovery session for id %" PRIu32 " found",
		   id);
		kbmd_return(ret, NULL);
	}

	(void) bunyan_info(tlog, "Received recovery response",
	    BUNYAN_T_INT32, "request_pid", pid,
	    BUNYAN_T_END);

	recover_common(req, r);
}

static errf_t *
add_template_hash(nvlist_t *restrict nvl, struct ebox_tpl *restrict tpl)
{
	errf_t *ret = ERRF_OK;
	uint8_t *hash = NULL;
	size_t hashlen = 0;

	if ((ret = template_hash(tpl, &hash, &hashlen)) != ERRF_OK) {
		return (ret);
	}

	ret = envlist_add_uint8_array(nvl, KBM_NV_CONFIG_HASH, hash,
	    (uint_t)hashlen);
	free(hash);

	return (ret);
}

static errf_t *
tpl_to_nvlist(struct ebox_tpl *restrict tpl, nvlist_t **restrict nvlp)
{
	errf_t *ret = ERRF_OK;
	size_t ncfg = 0;
	struct add_data data = { 0 };

	*nvlp = NULL;

	if (tpl == NULL) {
		return (ERRF_OK);
	}

	VERIFY0(ebox_tpl_foreach_cfg(tpl, count_recovery_configs, &ncfg));
	if (ncfg == 0) {
		return (ERRF_OK);
	}

	if ((ret = envlist_alloc(nvlp)) != ERRF_OK) {
		return (ret);
	}

	if ((ret = add_template_hash(*nvlp, tpl)) != ERRF_OK) {
		goto done;
	}

	if ((ret = ecalloc(ncfg, sizeof (nvlist_t *), &data.ad_nvls)) != NULL) {
		goto done;
	}

	if ((ret = ebox_tpl_foreach_cfg(tpl, add_config, &data)) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_add_nvlist_array(*nvlp, KBM_NV_CONFIGS, data.ad_nvls,
	    ncfg)) != ERRF_OK) {
		goto done;
	}

done:
	if (data.ad_nvls != NULL) {
		for (size_t i = 0; i < ncfg; i++) {
			nvlist_free(data.ad_nvls[i]);
		}
		free(data.ad_nvls);
	}

	if (ret != ERRF_OK) {
		nvlist_free(*nvlp);
		*nvlp = NULL;
	}

	return (ret);
}

static errf_t *
add_template(const char *dataset, nvlist_t *restrict nvl, boolean_t staged)
{
	errf_t *ret = ERRF_OK;
	struct ebox *ebox = NULL;
	struct ebox_tpl *tpl = NULL;
	nvlist_t *tpl_nvl = NULL;
	const char *name = staged ? "staged" : "active";

	if ((ret = kbmd_get_ebox(dataset, staged, &ebox)) != ERRF_OK) {
		if (errf_caused_by(ret, "NotFoundError")) {
			errf_free(ret);
			return (ERRF_OK);
		}

		goto done;
	}

	if ((tpl = ebox_tpl(ebox)) == NULL) {
		ret = errf("TemplateError", NULL,
		    "%s ebox does not contain a template", name);
		goto done;
	}

	if ((ret = tpl_to_nvlist(tpl, &tpl_nvl)) != ERRF_OK) {
		return (ret);
	}

	if (tpl_nvl != NULL) {
		ret = envlist_add_nvlist(nvl, name, tpl_nvl);
	}

done:
	nvlist_free(tpl_nvl);
	ebox_free(ebox);

	return (ret);
}

void
kbmd_list_recovery(nvlist_t *req)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *resp = NULL;
	nvlist_t *cfgs = NULL;
	const char *dataset = NULL;

	(void) bunyan_info(tlog, "List recovery config request", BUNYAN_T_END);

	if (get_dataset(req, &dataset) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_alloc(&resp)) != ERRF_OK ||
	    (ret = envlist_alloc(&cfgs)) != ERRF_OK) {
		nvlist_free(resp);
		resp = NULL;
		goto done;
	}

	if ((ret = add_template(dataset, cfgs, B_FALSE)) != ERRF_OK ||
	    (ret = add_template(dataset, cfgs, B_TRUE)) != ERRF_OK) {
		goto done;
	}

	ret = envlist_add_nvlist(resp, KBM_NV_CONFIGS, cfgs);

done:
	nvlist_free(req);
	nvlist_free(cfgs);
	kbmd_return(ret, resp);
}
