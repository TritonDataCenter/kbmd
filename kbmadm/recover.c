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
 * Copyright 2019 Joyent, Inc.
 */

#include <errno.h>
#include <libtecla.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "kbmadm.h"
#include "kbm.h"
#include "pivy/errf.h"

/*
 * To avoid copy/paste issues with the challenge value, we conservatively
 * wrap the output at 60 columns.
 */
#define	CHALLENGE_COLS 60

static const char *get_prompt(nvlist_t *restrict, const char *);
static errf_t *get_action(nvlist_t *restrict, kbm_act_t *restrict);
static errf_t *select_config(GetLine *restrict, nvlist_t *restrict,
    nvlist_t *restrict);
static errf_t *challenge(GetLine *restrict, nvlist_t *restrict,
    nvlist_t *restrict);
static boolean_t recovery_complete(nvlist_t *);
static errf_t *readline(GetLine *restrict, const char *, char **restrict);
static void printwrap(FILE *, const char *, size_t);

errf_t *
do_recover(int argc, char **argv)
{
	FILE *term;
	GetLine *gl;
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL, *resp = NULL;
	uint32_t id;
	int fd = -1;

	if ((term = fopen("/dev/tty", "w+")) == NULL)
		return (errfno("fopen", errno, ""));

	gl_change_terminal(gl, term, term, getenv("TERM"));

	if ((ret = req_new(KBM_CMD_RECOVER_START, &req)) != ERRF_OK ||
	    (ret = open_door(&fd)) != ERRF_OK ||
	    (ret = nv_door_call(fd, req, &resp)) != ERRF_OK ||
	    (ret = check_error(resp)) != ERRF_OK)
		goto done;

	if ((ret = envlist_lookup_uint32(resp, KBM_NV_RECOVER_ID,
	    &id)) != ERRF_OK)
		goto done;

	nvlist_free(req);
	req = NULL;

	while (!recovery_complete(resp)) {
		kbm_act_t action;

		if ((ret = get_action(resp, &action)) != ERRF_OK)
			goto done;

		if ((ret = req_new(KBM_CMD_RECOVER_RESP, &req)) != ERRF_OK ||
		    (ret = envlist_add_int32(req, KBM_NV_RECOVER_ID,
		    id)) != ERRF_OK)
			goto done;

		switch (action) {
		case KBM_ACT_CONFIG:
			ret = select_config(gl, resp, req);
			break;
		case KBM_ACT_CHALLENGE:
			ret = challenge(gl, resp, req);
			break;
		}

		if (ret != ERRF_OK)
			goto done;

		nvlist_free(resp);
		resp = NULL;

		if ((ret = nv_door_call(fd, req, &resp)) != ERRF_OK ||
		    (ret = check_error(resp)) != ERRF_OK)
			goto done;
	}

done:
	if (fd >= 0)
		(void) close(fd);
	nvlist_free(req);
	nvlist_free(resp);
	/*  XXX: cleanup gl */
	(void) fclose(term);
	return (ret);
}

static errf_t *
select_config(GetLine *restrict gl, nvlist_t *restrict q,
    nvlist_t *restrict req)
{
	errf_t *ret;
	const char *prompt = NULL;
	char *response = NULL;
	nvlist_t **cfg = NULL;
	uint_t ncfg = 0;
	int c;

	if ((ret = envlist_lookup_nvlist_array(q, KBM_NV_CONFIGS, &cfg,
	    &ncfg)) != ERRF_OK) {
		return (errf("InternalError", ret,
		    "response is missing '%s' value", KBM_NV_CONFIGS));
	}

	(void) nvlist_lookup_string(q, KBM_NV_PROMPT, (char **)&prompt);

	(void) printf("Select recovery configuration:\n");

	for (uint_t i = 0; i < ncfg; i++) {
		char *ans = NULL;
		char *desc = NULL;

		if ((ret = envlist_lookup_string(cfg[i], KBM_NV_DESC,
		    &desc)) != ERRF_OK ||
		    (ret = envlist_lookup_string(cfg[i], KBM_NV_ANSWER,
		    &ans)) != ERRF_OK)
			return (ret);

		(void) printf("%s. %s\n", ans, desc);
	}

	prompt = get_prompt(q, "> ");

	if ((ret = readline(gl, prompt, &response)) != ERRF_OK)
		return (ret);

	ret = envlist_add_string(req, KBM_NV_ANSWER, response);
	free(response);

	return (ret);
}

static errf_t *
challenge(GetLine *restrict gl, nvlist_t *restrict q,
    nvlist_t *restrict req)
{
	errf_t *ret;
	const char *prompt;
	nvlist_t **parts;
	custr_t *desc;
	char *answer = NULL;
	uint_t nparts;
	uint32_t remain;

	if ((ret = ecustr_alloc(&desc)) != ERRF_OK)
		return (ret);

	if ((ret = envlist_lookup_nvlist_array(q, KBM_NV_PARTS, &parts,
	    &nparts)) != ERRF_OK ||
	    (ret = envlist_lookup_uint32(q, KBM_NV_REMAINING,
	    &remain)) != ERRF_OK)
		return (ret);

	(void) printf("Remaining challenges (%u required):\n", remain);

	for (size_t i = 0; i < nparts; i++) {
		uint8_t *guid = NULL;
		char *name = NULL;
		char *challenge = NULL;
		char **words = NULL;
		uint_t nwords = 0, guidlen = 0;
		char gstr[GUID_STR_LEN] = { 0 };

		if (nvlist_lookup_uint8_array(parts[i], KBM_NV_GUID,
		    &guid, &guidlen) != 0) {
			(void) printf("WARNING: part %u missing GUID\n\n", i);
			continue;
		}
		guidstr(guid, gstr);

		if (nvlist_lookup_string_array(parts[i], KBM_NV_WORDS,
		    &words, &nwords) != 0) {
			(void) printf("WARNING: part %u missing verification "
			    "words\n\n", i);
			continue;
		}

		if (nvlist_lookup_string(parts[i], KBM_NV_CHALLENGE,
		    &challenge) != 0) {
			(void) printf("WARNING: part %u missing challenge\n\n");
			continue;
		}

		/* The name is optional */
		(void) nvlist_lookup_string(parts[i], KBM_NV_NAME, &name);

		custr_reset(desc);
		if ((ret = ecustr_append_printf(desc, "GUID: %s",
		    gstr)) != ERRF_OK)
			return (ret);
		if (name != NULL &&
		    (ret = ecustr_append_printf(desc, " (Name: %s)",
		    name) != ERRF_OK))
			return (ret);

		(void) printf("--- BEGIN CHALLENGE for %s ---\n",
		    custr_cstr(desc));
		printwrap(stdout, challenge, CHALLENGE_COLS);
		(void) printf("--- END CHALLENGE ---\n");

		(void) printf("VERIFICATION WORDS for %s:\n", custr_cstr(desc));
		for (size_t j = 0; j < nwords; j++) {
			(void) printf("%s%s", (j > 0) ? " " : "", words[j]);
		}
		(void) fputc('\n', stdout);
		(void) fputc('\n', stdout);
	}

	prompt = get_prompt(q, "Enter challenge response:");

	if ((ret = readline(gl, prompt, &answer)) != ERRF_OK) {
		return (ret);
	}

	ret = envlist_add_string(req, KBM_NV_ANSWER, answer);
	freezero(answer, strlen(answer) + 1);

	return (ret);
}

/* Print out buf, wrapping at col */
static void
printwrap(FILE *f, const char *buf, size_t col)
{
	size_t len = strlen(buf);

	VERIFY3U(len, <=, INT_MAX);
	VERIFY3U(col, <=, INT_MAX);

	/*
	 * Currently, this is only used to print base64 encoded strings,
	 * which by definition only use 7-bit ASCII characters.  If any
	 * future use contemplates using this to display multi-byte strings,
	 * this loop will need to be smarter.
	 */
	while (len > 0) {
		int amt = (len > col) ? col : len;

		(void) fprintf(f, "%.*s\n", amt, buf);
		buf += amt;
		len -= amt;
	}
}

static errf_t *
get_action(nvlist_t *restrict resp, kbm_act_t *restrict actp)
{
	errf_t *ret;
	int32_t act;

	if ((ret = envlist_lookup_int32(resp, KBM_NV_ACTION, &act)) != ERRF_OK)
		return (ret);

	switch ((kbm_act_t)act) {
	case KBM_ACT_CONFIG:
	case KBM_ACT_CHALLENGE:
		*actp = act;
		return (ERRF_OK);
	default:
		panic("Unknown recovery action %d", act);
	}
}

static boolean_t
recovery_complete(nvlist_t *resp)
{
	if (nvlist_lookup_boolean(resp, KBM_NV_RECOVERY_COMPLETE) == 0)
		return (B_TRUE);
	return (B_FALSE);
}

static errf_t *
readline(GetLine *restrict gl, const char *prompt, char **restrict linep)
{
	char *line;

	line = gl_get_line(gl, (prompt == NULL) ? "> " : prompt, NULL, -1);

	if (line != NULL) {
		if ((*linep = strdup(line)) == NULL)
			return (errfno("strdup", errno, ""));
		return (ERRF_OK);
	}

	GlReturnStatus status = gl_return_status(gl);

#define GLERROR(_err, _cause) \
    errf("GetLineError", _cause, "gl_get_line returned %s", #_err)

	switch (status) {
	case GLR_NEWLINE:
		return (GLERROR(GLR_NEWLINE, NULL));
	case GLR_BLOCKED:
		return (GLERROR(GLR_BLOCKED, NULL));
	case GLR_SIGNAL:
		return (GLERROR(GLR_SIGNAL, NULL));
	case GLR_TIMEOUT:
		return (GLERROR(GLR_TIMEOUT, NULL));
	case GLR_FDABORT:
		return (GLERROR(GLR_FDABORT, NULL));
	case GLR_EOF:
		return (GLERROR(GLR_EOF, NULL));
	case GLR_ERROR:
		/*
		 * The gl_get_line() man page explicitly says that one can call
		 * gl_return_status() on error for gl_get_line() and then
		 * examine errno on GLR_ERROR, so presumably errno is preserved
		 * across the gl_return_status_call.
		 */
		return (GLERROR(GLR_ERROR, errfno("gl_get_line", errno, "")));
	default:
		panic("gl_return_status returned unknown value %d", status);
	}
}

static const char *
get_prompt(nvlist_t *restrict nvl, const char *def)
{
	char *val;

	if (nvlist_lookup_string(nvl, KBM_NV_PROMPT, &val) == 0)
		return (val);
	return (def);
}
