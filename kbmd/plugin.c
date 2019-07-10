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
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <libnvpair.h>
#include <string.h>
#include <strings.h>
#include <umem.h>
#include <uuid/uuid.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "kbmd.h"
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "pivy/errf.h"
#include "kspawn.h"
#include "pivy/piv.h"
#include "pivy/libssh/sshbuf.h"
#include "pivy/libssh/ssherr.h"
#include "pivy/libssh/sshkey.h"

/*
 * Since there's nowhere else to put this yet, the plugins work like this:
 *
 * - All plugins return 0 on success, >0 on error.
 * - Error messages can be written to stderr.  On error, the contents of stdout
 *   is ignored.
 *
 * get-pin <guid>
 *	Return the pin for the piv token w/ the given guid.  Writes the pin
 *	to stdout.
 *
 * register-token
 *	Takes a JSON description of the piv token on stdin (in a funny
 *	conincidence, this is the same format used by the KBMAPI CreateToken
 *	API call).  Writes out the base64-encoded recovery token value to
 *	stdout on success.
 *
 * replace-token <guid> <rtoken>
 *	Takes a JSON blob for a PIV token to replace the previous system
 *	token <guid> with the recovery token <rtoken> and replaces the
 *	PIV token data in KBMAPI.
 *
 *	Writes the new recovery token to stdout on success.  This is
 *	different from 'new-token' in that this uses the recovery token
 *	to authenticate and replace the PIV token (as well as generate
 *	a new recovery token).
 *
 * new-token <guid>
 *	Asks for a new recovery token for the given GUID.  Unlike
 *	replace-token, the GUID does not change.  This is used when
 *	replacing/updating the recovery configuration (we can only
 *	obtain the current recovery token by performing an actual
 *	recovery, so when changing the recovery configuration, we
 *	must create a brand new ebox complete with a new recovery
 *	token).
 *
 * In all cases, the PIV token must not currently be in a transaction
 * when we call out to the plugins.  Since they are separate processes, they
 * will be unable to use the PIV token if we keep it locked in a transaction.
 */

#define	PLUGIN_VERSION		"1"

/* XXX: This path should change */
#define	PLUGIN_PATH		"/usr/lib/kbm/plugins/"

#define	GET_PIN_CMD		"get-pin"
#define	REGISTER_TOK_CMD	"register-pivtoken"
#define	REPLACE_TOK_CMD		"replace-pivtoken"
#define	NEW_TOK_CMD		"new-rtoken"

#define	GET_PIN_PATH		PLUGIN_PATH GET_PIN_CMD
#define	REGISTER_TOK_PATH	PLUGIN_PATH REGISTER_TOK_CMD
#define	REPLACE_TOK_PATH	PLUGIN_PATH REPLACE_TOK_CMD
#define	NEW_TOK_PATH		PLUGIN_PATH NEW_TOK_CMD

extern char **_environ;

/*
 * Truncate the string cu to the first line, removing the trailing \n if
 * present
 */
static void
extract_line(custr_t *cu)
{
	const char *s = custr_cstr(cu);
	const char *end = strchr(s, '\n');
	size_t idx;

	if (end == NULL)
		return;

	idx = (size_t)(end - s);
	VERIFY0(custr_trunc(cu, idx));
}

/*
 * Remove leading and trailing whitespace
 */
static void
trim_whitespace(custr_t *cu)
{
	const char *start = custr_cstr(cu);
	const char *p;
	size_t amt;

	/* Remove leading whitespace */
	if ((amt = strspn(start, " \t\n")) > 0) {
		VERIFY0(custr_remove(cu, 0, amt));
	}

	/* Remove trailing whitespace */
	start = custr_cstr(cu);
	p = start + custr_len(cu) - 1;
	amt = 0;
	while (p > start) {
		if (*p == ' ' || *p == '\t' || *p == '\n') {
			amt++;
		}
		p--;
	}

	if (amt > 0) {
		VERIFY0(custr_rtrunc(cu, amt - 1));
	}
}

static errf_t *
check_plugin_version(const char *cmd)
{
	errf_t *ret = ERRF_OK;
	strarray_t args = STRARRAY_INIT;
	int fds[3] = { -1, -1, -1 };
	pid_t pid;

	if ((ret = strarray_append(&args, "%s", cmd)) != ERRF_OK ||
	    (ret = strarray_append(&args, "-v")) != ERRF_OK) {
		return (errf("PluginError", ret, ""));
	}

	(void) bunyan_debug(tlog, "Checking plugin version",
	    BUNYAN_T_STRING, "plugin", cmd,
	    BUNYAN_T_END);

	ret = spawn(cmd, args.sar_strs, _environ, &pid, fds);
	strarray_fini(&args);
	if (ret != ERRF_OK) {
		return (errf("PluginError", ret, ""));
	}

	custr_t *data[2] = { 0 };
	int exitval;

	if ((ret = ecustr_alloc(&data[0])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[1])) != ERRF_OK ||
	    (ret = interact(pid, fds, NULL, 0, data, &exitval)) != ERRF_OK) {
		custr_free(data[0]);
		custr_free(data[1]);
		return (errf("PluginError", ret, ""));
	}

	if (exitval != 0) {
		(void) bunyan_warn(tlog, "Error checking plugin version",
		    BUNYAN_T_STRING, "plugin", cmd,
		    BUNYAN_T_INT32, "retval", exitval,
		    BUNYAN_T_END);

		ret = errf("PluginError", NULL,
		    "Unexpected return value %d from version check on %s",
		    exitval, cmd);
	} else {
		trim_whitespace(data[0]);

		if (strcmp(custr_cstr(data[0]), PLUGIN_VERSION) != 0) {
			ret = errf("PluginVersionError", NULL,
			    "plugin version '%s' is incompatible",
			    custr_cstr(data[0]));
		}
	}

	custr_free(data[0]);
	custr_free(data[1]);

	return (ret);
}

errf_t *
kbmd_get_pin(const uint8_t guid[restrict], custr_t **restrict pinp)
{
	errf_t *ret = ERRF_OK;
	strarray_t args = STRARRAY_INIT;
	int fds[3] = { -1, -1, -1 };
	pid_t pid;

	*pinp = NULL;

	if ((ret = strarray_append(&args, GET_PIN_CMD)) != ERRF_OK ||
	    (ret = strarray_append_guid(&args, guid)) != ERRF_OK) {
		return (errf("PluginError", ret, ""));
	}

	/*
	 * NOTE: this depends on the GUID being the most recently appended
	 * string to args
	 */
	(void) bunyan_debug(tlog, "Running " GET_PIN_CMD " plugin",
	    BUNYAN_T_STRING, "path", GET_PIN_PATH,
	    BUNYAN_T_STRING, "guid", args.sar_strs[args.sar_n - 1],
	    BUNYAN_T_END);

	/*
	 * Let the command inherit our environment.
	 * XXX: Maybe set the environment to a fixed known value?
	 */
	ret = spawn(GET_PIN_PATH, args.sar_strs, _environ, &pid, fds);
	strarray_fini(&args);
	if (ret != ERRF_OK)
		return (errf("PluginError", ret, ""));

	custr_t *data[2] = { 0 };
	int exitval;

	if ((ret = ecustr_alloc(&data[0])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[1])) != ERRF_OK ||
	    (ret = interact(pid, fds, NULL, 0, data, &exitval)) != ERRF_OK) {
		custr_free(data[0]);
		custr_free(data[1]);
		return (errf("PluginError", ret, ""));
	}

	/*
	 * XXX: What do with any stderr output?  We can append it to
	 * errf, but there's limited buffer space and likely would be
	 * truncated.
	 */
	if (exitval != 0) {
		(void) bunyan_warn(tlog, "Get pin plugin returned an error",
		    BUNYAN_T_STRING, "plugin", GET_PIN_CMD,
		    BUNYAN_T_INT32, "retval", (int32_t)exitval,
		    BUNYAN_T_END);

		ret = errf("PluginError", NULL, "Plugin returned %d (%s)",
		    exitval, GET_PIN_CMD);
	} else {
		extract_line(data[0]);
		if (custr_len(data[0]) == 0) {
			ret = errf("PluginError", NULL,
			    "script did not return any data");
		} else {
			*pinp = data[0];
			data[0] = NULL;
		}
	}

	custr_free(data[0]);
	custr_free(data[1]);
	return (ret);
}

static errf_t *
add_cn_uuid(nvlist_t *nvl)
{
	char uuid_str[UUID_PRINTABLE_STRING_LENGTH] = { 0 };

	uuid_unparse_lower(sys_uuid, uuid_str);
	return (envlist_add_string(nvl, "cn_uuid", uuid_str));
}

static errf_t *
add_pubkey(const char *restrict slotstr, struct piv_slot *restrict slot,
   nvlist_t *restrict nvl)
{
	errf_t *ret;
	struct sshkey *pubkey = piv_slot_pubkey(slot);
	struct sshbuf *b = NULL;
	int r;

	if ((b = sshbuf_new()) == NULL)
		return (ssherrf("sshbuf_new", SSH_ERR_ALLOC_FAIL));

	if ((r = sshkey_format_text(pubkey, b)) != 0) {
		sshbuf_free(b);
		return (ssherrf("sshkey_format_text", r));
	}

	ret = envlist_add_string(nvl, slotstr, (const char *)sshbuf_ptr(b));
	sshbuf_free(b);

	return (ret);
}

static errf_t *
add_attest(struct piv_token *restrict pt, const char *restrict slotstr,
    struct piv_slot *restrict slot, nvlist_t *restrict nvl)
{
	errf_t *ret = ERRF_OK;
	uint8_t *cert = NULL;
	size_t certlen = 0;

	/*
	 * If no nvlist is present, it means the token doesn't support
	 * attestation, and we just skip adding the cert.
	 */
	if (nvl == NULL)
		return (ret);

	if ((ret = ykpiv_attest(pt, slot, &cert, &certlen)) != ERRF_OK)
		return (ret);

	const uint8_t *ptr = cert;
	char *certpem = NULL, *bioptr = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	long biolen = 0;

	/* Write out decoded cert to certpem */
	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		make_sslerrf(ret, "BIO_new",
		    "parsing attestation cert for slot %s", slotstr);
		goto done;
	}

	x509 = d2i_X509(NULL, &ptr, certlen);
	if (!PEM_write_bio_X509(bio, x509)) {
		make_sslerrf(ret, "PEM_write_BIO_X509",
		    "parsing attestation cert for slot %s", slotstr);
		goto done;
	}

	biolen = BIO_get_mem_data(bio, &bioptr);
	VERIFY3S(biolen, >, 0);

	/*
	 * It's unclear if we can guarantee bioptr is NUL terminated, so
	 * to be safe, we copy and NUL terminate
	 */
	if ((certpem = calloc(1, biolen + 1)) == NULL) {
		ret = errfno("calloc", errno,
		    "parsing attestation cert for slot %s", slotstr);
		goto done;
	}
	bcopy(bioptr, certpem, biolen);

	ret = envlist_add_string(nvl, slotstr, certpem);
	free(certpem);

done:
	X509_free(x509);
	BIO_free(bio);
	free(cert);
	return (ret);
}

static errf_t *
add_keys(struct piv_token *restrict pt, nvlist_t *restrict pubkeys,
    nvlist_t *restrict attest)
{
	errf_t *ret = ERRF_OK;

	for (uint_t i = 0x9A; i < 0x9F; i++) {
		struct piv_slot *cert = NULL;
		char slotstr[3] = { 0 };

		(void) snprintf(slotstr, sizeof (slotstr), "0x02X", i);

		ret = piv_read_cert(pt, i);
		cert = piv_get_slot(pt, i);

		/*
		 * If no key is present, skip that slot and don't report an
		 * error
		 */
		if (cert == NULL && errf_caused_by(ret, "NotFoundError")) {
			errf_free(ret);
			ret = ERRF_OK;
			continue;
		} else if (cert == NULL) {
			return (errf("PluginError", ret,
			    "failed to read cert in slot %s", slotstr));
		}

		if ((ret = add_pubkey(slotstr, cert, pubkeys)) != ERRF_OK ||
		    (ret = add_attest(pt, slotstr, cert, attest)) != ERRF_OK)
			return (ret);
	}

	return (ret);
}

static errf_t *
add_serial(nvlist_t *nvl, const struct piv_token *restrict pt)
{
	/*
	 * Only newer (5.0 and presumably later) yubikeys support
	 * querying the serial.  If not present, we silently skip
	 * adding.
	 */
	if (!ykpiv_token_has_serial(pt))
		return (ERRF_OK);

	uint32_t serial = ykpiv_token_serial(pt);

	return (envlist_add_uint32(nvl, "serial", serial));
}

static errf_t *
pivtoken_to_json(struct piv_token *restrict pt, const char *restrict pin,
    char **restrict jsonp)
{
	errf_t *ret = ERRF_OK;
	char *json = NULL;
	nvlist_t *nvl = NULL, *pubkeys = NULL, *attest = NULL;
	const char *guid = piv_token_guid_hex(pt);

	/*
	 * First create an nvlist similar in form to the desired JSON.
	 * Then nvlist_dump_json() is used to take care of proper formatting
	 * and escaping of the JSON output.
	 */
	if ((ret = envlist_alloc(&nvl)) != ERRF_OK ||
	    (ret = envlist_alloc(&pubkeys)) != ERRF_OK)
		goto done;

	if ((ret = envlist_add_string(nvl, "guid", guid)) != ERRF_OK ||
	    (ret = add_cn_uuid(nvl)) != ERRF_OK ||
	    (ret = envlist_add_string(nvl, "pin", pin)) != ERRF_OK)
		goto done;

	if ((ret = piv_txn_begin(pt)) != ERRF_OK ||
	    (ret = piv_select(pt)) != ERRF_OK)
		goto done;

	if (piv_token_is_ykpiv(pt)) {
		/*
		 * Only allocate attest if we're a yubikey (and thus
		 * support attestation).  Otherwise leave it NULL so
		 * add_attest() will skip attempting to perform attestation.
		 */
		if ((ret = envlist_alloc(&attest)) != ERRF_OK)
			goto done;

		/*
		 * The reader on a Yubikey is a part of the Yubikey (as
		 * opposed to a separate reader + javacard), so we can
		 * safely assume the reader name is the model of a Yubikey.
		 */
		if ((ret = envlist_add_string(nvl, "model",
		    piv_token_rdrname(pt))) != ERRF_OK ||
		    (ret = add_serial(nvl, pt)) != ERRF_OK)
			goto done;
	}

	if ((ret = add_keys(pt, pubkeys, attest)) != ERRF_OK ||
	    (ret = envlist_add_nvlist(nvl, "pubkeys", pubkeys)) != ERRF_OK ||
	    ((attest != NULL &&
	    (ret = envlist_add_nvlist(nvl, "attestation", attest)) != ERRF_OK)))
		goto done;

	if ((ret = envlist_dump_json(nvl, &json)) != ERRF_OK)
		goto done;

	*jsonp = json;
	json = NULL;

done:
	if (piv_token_in_txn(pt))
		piv_txn_end(pt);

	nvlist_free(attest);
	nvlist_free(pubkeys);
	nvlist_free(nvl);
	if (json != NULL)
		freezero(json, strlen(json) + 1);
	return (ret);
}

static errf_t *
plugin_pivtoken_common(struct piv_token *restrict pt, const char *restrict pin,
    const char *cmd, char *const *args, custr_t *restrict in,
    custr_t **restrict keyp)
{
	errf_t *ret = ERRF_OK;
	custr_t *data[3] = { in, NULL, NULL };
	char *json = NULL;
	int fds[3] = { -1, -1, -1 };
	int exitval;
	pid_t pid;

	if ((ret = ecustr_alloc(&data[1])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[2])) != ERRF_OK)
		goto done;

	if ((ret = pivtoken_to_json(pt, pin, &json)) != ERRF_OK ||
	    (ret = ecustr_append(data[0], json)) != ERRF_OK ||
	    (ret = ecustr_appendc(data[0], '\n')) != ERRF_OK)
		goto done;

	if ((ret = spawn(cmd, args, _environ, &pid, fds)) != ERRF_OK ||
	    (ret = interact(pid, fds, custr_cstr(data[0]), custr_len(data[0]),
	    &data[1], &exitval)) != ERRF_OK) {
		goto done;
	}

	if (exitval != 0) {
		/*
		 * XXX: What to do with any stderr output?  It's very likely
		 * it'll be too large to fit in an errf_t
		 */
		ret = errf("PluginError", NULL, "non-zero plugin exit (%d)",
		    exitval);
		goto done;
	}

	extract_line(data[1]);
	if (custr_len(data[1]) == 0) {
		ret = errf("PluginError", NULL,
		    "plugin did not return a recovery key");
		goto done;
	}

	*keyp = data[1];
	data[1] = NULL;

done:
	if (json != NULL)
		freezero(json, strlen(json) + 1);
	custr_free(data[1]);
	custr_free(data[2]);
	return (ret);
}

static errf_t *
set_recovery_token(kbmd_token_t *restrict kt, custr_t *restrict rtoken)
{
	errf_t *ret = ERRF_OK;
	struct sshbuf *buf = NULL;
	size_t len;
	int rc;

	if ((buf = sshbuf_new()) == NULL)
		return (errfno("sshbuf_new", errno, ""));

	rc = sshbuf_b64tod(buf, custr_cstr(rtoken));
	if (rc != SSH_ERR_SUCCESS) {
		sshbuf_free(buf);
		return (ssherrf("sshbuf_b64tod", rc,
		    "cannot decode recovery token"));
	}

	len = sshbuf_len(buf);
	if ((ret = zalloc(len, &kt->kt_rtoken)) != ERRF_OK) {
		sshbuf_free(buf);
		return (ret);
	}

	rc = sshbuf_get(buf, kt->kt_rtoken, len);
	if (rc != SSH_ERR_SUCCESS) {
		ret = ssherrf("sshbuf_get", rc, "");
		sshbuf_free(buf);
		freezero(kt->kt_rtoken, len);
		kt->kt_rtoken = NULL;
		return (ret);
	}

	kt->kt_rtoklen = len;
	sshbuf_free(buf);
	return (ERRF_OK);
}

errf_t *
kbmd_register_pivtoken(kbmd_token_t *kt)
{
	errf_t *ret = ERRF_OK;
	custr_t *input = NULL;
	custr_t *rtoken = NULL;
	strarray_t args = STRARRAY_INIT;

	VERIFY(!piv_token_in_txn(kt->kt_piv));

	if ((ret = ecustr_alloc(&input)) != ERRF_OK) {
		goto done;
	}

	if ((ret = strarray_append(&args, REGISTER_TOK_CMD)) != ERRF_OK) {
		goto done;
	}

	if ((ret = plugin_pivtoken_common(kt->kt_piv, kt->kt_pin,
	    REGISTER_TOK_PATH, args.sar_strs, input, &rtoken)) != ERRF_OK) {
		goto done;
	}

	ret = set_recovery_token(kt, rtoken);

done:
	strarray_fini(&args);
	custr_free(rtoken);
	custr_free(input);
	return (ret);
}

errf_t *
kbmd_replace_pivtoken(const uint8_t *guid, size_t guidlen,
    const uint8_t *rtoken, size_t rtokenlen, kbmd_token_t *kt)
{
	errf_t *ret = ERRF_OK;
	custr_t *input = NULL;
	custr_t *rtok64 = NULL;
	custr_t *new_rtoken = NULL;
	strarray_t args = STRARRAY_INIT;

	VERIFY(!piv_token_in_txn(kt->kt_piv));

	if ((ret = ecustr_alloc(&input)) != ERRF_OK ||
	    (ret = ecustr_alloc(&rtok64)) != ERRF_OK) {
		goto done;
	}

	if ((ret = ecustr_append_b64(rtok64, rtoken, rtokenlen)) != ERRF_OK) {
		goto done;
	}

	if ((ret = strarray_append(&args, REPLACE_TOK_CMD)) != ERRF_OK ||
	    (ret = strarray_append_guid(&args, guid)) != ERRF_OK ||
	    (ret = strarray_append(&args, "%s", custr_cstr(rtok64))) != ERRF_OK)
		goto done;

	/*
	 * The input to the script is:
	 *	{ <new token JSON...
	 *	...
	 *	}
	 */
	if ((ret = plugin_pivtoken_common(kt->kt_piv, kt->kt_pin,
	    REPLACE_TOK_PATH, args.sar_strs, input, &new_rtoken)) != ERRF_OK) {
		goto done;
	}

	ret = set_recovery_token(kt, new_rtoken);

done:
	strarray_fini(&args);
	custr_free(input);
	custr_free(rtok64);
	custr_free(new_rtoken);
	return (ret);
}

errf_t *
kbmd_new_recovery_token(kbmd_token_t *restrict kt, uint8_t **restrict rtokenp,
    size_t *restrict rtokenlenp)
{
	errf_t *ret = ERRF_OK;
	uint8_t *buf = NULL;
	strarray_t args = STRARRAY_INIT;
	int fds[3] = { -1, -1, -1 };
	pid_t pid;

	VERIFY(!piv_token_in_txn(kt->kt_piv));

	*rtokenp = NULL;
	*rtokenlenp = 0;

	if ((ret = strarray_append(&args, NEW_TOK_CMD)) != ERRF_OK ||
	    (ret = strarray_append_guid(&args,
	    piv_token_guid(kt->kt_piv))) != ERRF_OK) {
		return (errf("PluginError", ret,
		    "failed to create cmdline for %s", NEW_TOK_CMD));
	}

	(void) bunyan_debug(tlog, "Running " NEW_TOK_CMD " plugin",
	    BUNYAN_T_STRING, "path", NEW_TOK_PATH,
	    BUNYAN_T_STRING, "guid", args.sar_strs[args.sar_n - 1],
	    BUNYAN_T_END);

	ret = spawn(NEW_TOK_PATH, args.sar_strs, _environ, &pid, fds);
	strarray_fini(&args);
	if (ret != ERRF_OK) {
		return (errf("PluginError", ret, ""));
	}

	custr_t *data[2] = { 0 };
	int exitval;

	if ((ret = ecustr_alloc(&data[0])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[1])) != ERRF_OK ||
	    (ret = interact(pid, fds, NULL, 0, data, &exitval)) != ERRF_OK) {
		custr_free(data[0]);
		custr_free(data[1]);
		return (errf("PluginError", ret, ""));
	}

	if (exitval != 0) {
		(void) bunyan_warn(tlog,
		    "New recovery token  plugin returned an error",
		    BUNYAN_T_STRING, "plugin", NEW_TOK_CMD,
		    BUNYAN_T_INT32, "retval", (int32_t)exitval,
		    BUNYAN_T_END);

		ret = errf("PluginError", NULL, "Plugin returned %d (%s)",
		    exitval, NEW_TOK_CMD);
	} else {
		extract_line(data[0]);
		if (custr_len(data[0]) == 0) {
			ret = errf("PluginError", NULL,
			    "script did not return any data");
		} else {
			ret = ecustr_fromb64(data[0], rtokenp, rtokenlenp);
		}
	}

	custr_free(data[0]);
	custr_free(data[1]);
	return (ret);
}
