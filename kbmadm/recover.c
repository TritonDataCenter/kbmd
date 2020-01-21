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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <libtecla.h>
#include <limits.h>
#include <regex.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "kbmadm.h"
#include "kbm.h"
#include "pivy/errf.h"

static const char r_begin[] = "-+ *begin response";
static const char r_end[] = "-+ *end response";
static regex_t rc_begin;
static regex_t rc_end;
static boolean_t rc_compiled;

/*
 * To avoid copy/paste issues with the challenge value, we conservatively
 * wrap the output at 60 columns.
 */
#define	CHALLENGE_COLS 60

static void assert_regex(void);
static const char *get_prompt(nvlist_t *restrict, const char *);
static errf_t *get_action(nvlist_t *restrict, kbm_act_t *restrict);
static errf_t *get_answer(GetLine *restrict, const char *, custr_t **restrict);
static errf_t *select_config(nvlist_t *restrict, nvlist_t *restrict);
static errf_t *challenge(nvlist_t *restrict, nvlist_t *restrict);
static boolean_t recovery_complete(nvlist_t *);
static errf_t *readline(GetLine *restrict, const char *, custr_t *);
static void printwrap(FILE *, const char *, size_t);
static void strip_whitespace(custr_t *);

static errf_t *
create_gl(GetLine **glp)
{
	GetLine *gl = NULL;
	FILE *term = NULL;

	if ((gl = new_GetLine(1024, 1024)) == NULL)
		return (errfno("new_GetLine", errno, "cannot setup terminal"));

	if ((term = fopen("/dev/tty", "w+")) == NULL)
		return (errfno("fopen", errno, ""));

	gl_change_terminal(gl, term, term, getenv("TERM"));

	*glp = gl;
	return (ERRF_OK);
}

errf_t *
recover(const char *dataset, uint32_t cfgnum)
{
	errf_t *ret = ERRF_OK;
	nvlist_t *req = NULL, *resp = NULL;
	uint32_t id;

	if (isatty(STDIN_FILENO) == 0) {
		if (errno != ENOTTY) {
			ret = errfno("isatty", errno,
			    "unable to determine status of stdin");
		} else {
			ret = errf("RecoveryError", NULL,
			    "recovery must be run from a terminal");
		}
		return (ret);
	}

	if ((ret = req_new(KBM_CMD_RECOVER_START, &req)) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_add_string(req, KBM_NV_DATASET,
	    dataset)) != ERRF_OK) {
		goto done;
	}

	if (cfgnum > 0 && (ret = envlist_add_uint32(req, KBM_NV_CONFIG_NUM,
	    (uint32_t)cfgnum)) != ERRF_OK) {
		goto done;
	}

	if ((ret = send_request(req, &resp)) != ERRF_OK) {
		goto done;
	}

	if ((ret = envlist_lookup_uint32(resp, KBM_NV_RECOVER_ID,
	    &id)) != ERRF_OK) {
		ret = errf("RecoverError", ret,
		    "kbmd response is missing a recovery id");
		goto done;
	}

	while (!recovery_complete(resp)) {
		kbm_act_t action;

		if ((ret = get_action(resp, &action)) != ERRF_OK)
			goto done;

		nvlist_free(req);
		req = NULL;
		if ((ret = req_new(KBM_CMD_RECOVER_RESP, &req)) != ERRF_OK ||
		    (ret = envlist_add_uint32(req, KBM_NV_RECOVER_ID,
		    id)) != ERRF_OK)
			goto done;

		switch (action) {
		case KBM_ACT_CONFIG:
			ret = select_config(resp, req);
			break;
		case KBM_ACT_CHALLENGE:
			ret = challenge(resp, req);
			break;
		}

		if (ret != ERRF_OK)
			goto done;

		nvlist_free(resp);
		resp = NULL;

		if ((ret = send_request(req, &resp)) != ERRF_OK) {
			goto done;
		}
	}

done:
	nvlist_free(req);
	nvlist_free(resp);

	if (ret == ERRF_OK && IS_ZPOOL(dataset)) {
		mount_zpool(dataset, NULL);
	}

	return (ret);
}

errf_t *
show_configs(nvlist_t **cfgs, uint_t ncfgs, boolean_t verbose)
{
	errf_t *ret = ERRF_OK;

	for (size_t i = 0; i < ncfgs; i++) {
		nvlist_t **parts = NULL;
		uint_t m = 0;
		uint32_t n = 0;
		int namewidth = 16;

		if ((ret = envlist_lookup_nvlist_array(cfgs[i], KBM_NV_PARTS,
		    &parts, &m)) != ERRF_OK ||
		    (ret = envlist_lookup_uint32(cfgs[i], KBM_NV_N,
		    &n)) != ERRF_OK) {
			ret = errf("InternalError", ret,
			    "kbmd returned config %zu with bad data", i + 1);
			return (ret);
		}

		for (size_t j = 0; j < m; j++) {
			char *name = NULL;
			size_t len;

			if ((ret = envlist_lookup_string(parts[j], KBM_NV_NAME,
			    &name)) != ERRF_OK) {
				continue;
			}

			len = strlen(name);
			if (len > INT_MAX) {
				ret = errf("InternalError", NULL,
				    "kbmd returned a name longer than INT_MAX "
				    "(%zu bytes)", len);
				return (ret);
			}

			if (len > namewidth) {
				namewidth = len;
			}
		}

		(void) printf("CONFIG #%zu\n", i + 1);
		(void) printf("\tN = %" PRIu32 "\n", n);
		(void) printf("\t%-32s %-4s %*s%s\n", "GUID", "SLOT",
		    -namewidth, "NAME", verbose ? " PUBKEY" : "");

		for (size_t j = 0; j < m; j++) {
			char gstr[GUID_STR_LEN] = { 0 };
			uint8_t *guid = NULL;
			char *name = NULL;
			char *pubkey = NULL;
			int32_t slot = 0;
			uint_t guid_len = 0;

			if ((ret = envlist_lookup_uint8_array(parts[j],
			    KBM_NV_GUID, &guid, &guid_len)) != ERRF_OK ||
			    (ret = envlist_lookup_string(parts[j],
			    KBM_NV_PUBKEY, &pubkey)) != ERRF_OK ||
			    (ret = envlist_lookup_int32(parts[j],
			    KBM_NV_SLOT, &slot)) != ERRF_OK) {
				ret = errf("InternalError", ret,
				    "kbmd return config %zu part %zu with bad "
				    "data", i + 1, j + 1);
				return (ret);
			}

			if ((ret = envlist_lookup_string(parts[j],
			    KBM_NV_NAME, &name)) != ERRF_OK) {
				/*
				 * The name is optional, so just ignore
				 * any errors with it.
				 */
				errf_free(ret);
			}

			guidtohex(guid, gstr, sizeof (gstr));
			(void) printf("\t%*s %4x %*s%s%s\n",
			    -(GUID_STR_LEN-1), gstr,
			    slot,
			    namewidth, (name == NULL) ? "" : name,
			    verbose ? " " : "", verbose ? pubkey : "");
		}

		(void) fputc('\n', stdout);
	}

	return (ERRF_OK);
}

static errf_t *
select_config(nvlist_t *restrict q, nvlist_t *restrict req)
{
	errf_t *ret = ERRF_OK;
	GetLine *gl = NULL;
	const char *prompt = NULL;
	custr_t *response = NULL;
	nvlist_t **cfg = NULL;
	uint_t ncfg = 0;

	if ((ret = envlist_lookup_nvlist_array(q, KBM_NV_CONFIGS, &cfg,
	    &ncfg)) != ERRF_OK) {
		ret = errf("InternalError", ret,
		    "response is missing '%s' value", KBM_NV_CONFIGS);
		return (ret);
	}

	if ((ret = create_gl(&gl)) != ERRF_OK) {
		return (ret);
	}

	if ((ret = ecustr_alloc(&response)) != ERRF_OK) {
		del_GetLine(gl);
		return (ret);
	}

	(void) printf("Select recovery configuration:\n");

	if ((ret = show_configs(cfg, ncfg, B_FALSE)) != ERRF_OK) {
		custr_free(response);
		del_GetLine(gl);
		return (ret);
	}

	/*
	 * If no prompt was given, we use a default value of '> '
	 */
	prompt = get_prompt(q, "> ");

	if ((ret = readline(gl, prompt, response)) != ERRF_OK) {
		custr_free(response);
		del_GetLine(gl);
		return (ret);
	}
	strip_whitespace(response);

	ret = envlist_add_string(req, KBM_NV_ANSWER, custr_cstr(response));
	custr_free(response);
	del_GetLine(gl);

	return (ret);
}

static errf_t *
challenge(nvlist_t *restrict q, nvlist_t *restrict req)
{
	errf_t *ret;
	GetLine *gl = NULL;
	const char *prompt;
	nvlist_t **parts;
	custr_t *desc = NULL, *answer = NULL;
	uint_t nparts;
	uint32_t remain;

	if ((ret = ecustr_alloc(&desc)) != ERRF_OK ||
	    (ret = create_gl(&gl)) != ERRF_OK) {
		if (gl != NULL)
			del_GetLine(gl);
		return (ret);
	}

	if ((ret = envlist_lookup_nvlist_array(q, KBM_NV_PARTS, &parts,
	    &nparts)) != ERRF_OK ||
	    (ret = envlist_lookup_uint32(q, KBM_NV_REMAINING,
	    &remain)) != ERRF_OK) {
		custr_free(desc);
		del_GetLine(gl);
		return (ret);

	}

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
			(void) printf("WARNING: part %zu missing GUID\n\n", i);
			continue;
		}
		guidtohex(guid, gstr, sizeof (gstr));

		if (nvlist_lookup_string_array(parts[i], KBM_NV_WORDS,
		    &words, &nwords) != 0) {
			(void) printf("WARNING: part %zu missing verification "
			    "words\n\n", i);
			continue;
		}

		if (nvlist_lookup_string(parts[i], KBM_NV_CHALLENGE,
		    &challenge) != 0) {
			(void) printf("WARNING: part %zu missing challenge\n\n",
			    i);
			continue;
		}

		/* The name is optional */
		(void) nvlist_lookup_string(parts[i], KBM_NV_NAME, &name);

		custr_reset(desc);
		if ((ret = ecustr_append_printf(desc, "GUID: %s",
		    gstr)) != ERRF_OK)
			goto done;
		if (name != NULL &&
		    (ret = ecustr_append_printf(desc, " (Name: %s)",
		    name)) != ERRF_OK)
			goto done;

		(void) printf("--- BEGIN CHALLENGE for %s ---\n",
		    custr_cstr(desc));
		printwrap(stdout, challenge, CHALLENGE_COLS);
		(void) printf("--- END CHALLENGE ---\n");

		(void) printf("VERIFICATION WORDS: ");
		for (size_t j = 0; j < nwords; j++) {
			(void) printf("%s%s", (j > 0) ? " " : "", words[j]);
		}
		(void) fputc('\n', stdout);
		(void) fputc('\n', stdout);
	}

	prompt = get_prompt(q, "Enter challenge response");

	if ((ret = get_answer(gl, prompt, &answer)) != ERRF_OK) {
		ret = errf("RecoverError", ret, "Failed to read user response");
		goto done;
	}

	ret = envlist_add_string(req, KBM_NV_ANSWER, custr_cstr(answer));

done:
	custr_free(desc);
	custr_free(answer);
	del_GetLine(gl);
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

	if ((ret = envlist_lookup_int32(resp, KBM_NV_ACTION,
	    &act)) != ERRF_OK) {
		ret = errf("RecoveryError", ret,
		    "kbmd response is missing an action");
		return (ret);
	}

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
	boolean_t val;

	if (nvlist_lookup_boolean_value(resp, KBM_NV_RECOVERY_COMPLETE,
	    &val) == 0) {
		return (val);
	}
	return (B_FALSE);
}

static errf_t *
readline(GetLine *restrict gl, const char *prompt, custr_t *line)
{
	errf_t *ret = ERRF_OK;
	char *strline;

	strline = gl_get_line(gl, (prompt == NULL) ? "" : prompt, NULL, -1);

	if (strline != NULL) {
		custr_reset(line);
		if ((ret = ecustr_append(line, strline)) != ERRF_OK) {
			return (ret);
		}
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

/*
 * Strips _all_ whitespace (leading, trailing, and intra string).
 * Pivy box will breakup it's output into (currently) 60-byte long lines,
 * (like the text form of a X.509 certificate), and it's likely responses
 * will be copy/pasted into our terminal, so we need to join all the lines
 * and remove any embedded whitespace which might get introduced during pasting
 * (in addition to the newlines) so we can later base64 decode the result.
 */
static void
strip_whitespace(custr_t *cus)
{
	const char *p;
	size_t i, start, len;

	p = custr_cstr(cus);
	i = 0;
	while (p[i] != '\0') {
		if (!isspace(p[i])) {
			i++;
			continue;
		}

		start = i;
		len = 0;
		while (p[start + len] != '\0' && isspace(p[start + len]))
			len++;

		VERIFY0(custr_remove(cus, start, len));
		/*
		 * While the current implementation does not change the
		 * address of the underlying buffer during a remove, we
		 * should not assume it in case this changes in future
		 * implementations.  Since we are always removing after p[i],
		 * we should however always be still use i as a valid index
		 * after obtaining the new pointer to the data.
		 */
		p = custr_cstr(cus);
	}
}

/*
 * When reading a challenge response, we support pasting in the base64
 * encoded answer with arbitrary embedded whitespace, across an
 * arbitrary number of lines.
 *
 * We also recognize (but do not require) the '-- Begin Response --' and
 * '-- End Response --' delimiters in the input.  If the begin delimiter is
 * seen, we discard all previous input, and require the end delimiter.  When
 * the delimiters are present, any input after the end delimiter is discarded.
 *
 * Nesting of delimiters is not supported.
 */
enum {
	OUTSIDE_BLOCK,
	IN_BLOCK,
	PAST_BLOCK
};

static errf_t *
get_answer(GetLine *restrict gl, const char *prompt, custr_t **restrict answerp)
{
	errf_t *ret = ERRF_OK;
	custr_t *ans = NULL;
	char *line = NULL;
	int state = OUTSIDE_BLOCK;
	regmatch_t match = { 0 };

	*answerp = NULL;
	assert_regex();
	if ((ret = ecustr_alloc(&ans)) != ERRF_OK) {
		return (ret);
	}

	(void) printf("%s:\n", prompt);

	while ((line = gl_get_line(gl, "", NULL, -1)) != NULL) {
		switch (state) {
		case OUTSIDE_BLOCK:
			if (regexec(&rc_begin, line, 1, &match,
			    REG_ICASE) == 0) {
				custr_reset(ans);
				state = IN_BLOCK;
				continue;
			}
			break;
		case IN_BLOCK:
			if (regexec(&rc_end, line, 1, &match, REG_ICASE) == 0) {
				state = PAST_BLOCK;
				continue;
			}
		case PAST_BLOCK:
			continue;
		}

		if ((ret = ecustr_append(ans, line)) != ERRF_OK) {
			custr_free(ans);
			return (ret);
		}
	}

	if (state == IN_BLOCK) {
		ret = errf("InputError", NULL,
		    "End delimiter missing in input");
		custr_free(ans);
		return (ret);
	}

	strip_whitespace(ans);
	*answerp = ans;
	return (ret);
}

static const char *
get_prompt(nvlist_t *restrict nvl, const char *def)
{
	char *val;

	if (nvlist_lookup_string(nvl, KBM_NV_PROMPT, &val) == 0)
		return (val);
	return (def);
}

static void
assert_regex(void)
{
	if (rc_compiled) {
		return;
	}

	VERIFY0(regcomp(&rc_begin, r_begin, REG_EXTENDED|REG_ICASE));
	VERIFY0(regcomp(&rc_end, r_end, REG_EXTENDED|REG_ICASE));
	rc_compiled = B_TRUE;
}
