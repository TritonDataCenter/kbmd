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

#include <bunyan.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <libnvpair.h>
#include <libscf.h>
#include <string.h>
#include <strings.h>
#include <umem.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/sysmacros.h>
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

#include <stdio.h>

/*
 * In all cases, the PIV token must not currently be in a transaction
 * when we call out to the plugins.  Since they are separate processes, they
 * will be unable to use the PIV token if we keep it locked in a transaction.
 */

#define	PLUGIN_VERSION		"1"

#define	PLUGIN_PREFIX		"kbm-plugin-"

#define	PLUGIN_PATH		"/usr/lib/kbm/plugins/"

#define	GET_PIN_CMD		"get-pin"
#define	REGISTER_TOK_CMD	"register-pivtoken"
#define	REPLACE_TOK_CMD		"replace-pivtoken"
#define	NEW_TOK_CMD		"new-rtoken"
#define	POST_RECOVERY_UPDATE	"post-rcfg-update"

extern char **_environ;

static mutex_t plugin_mutex = ERRORCHECKMUTEX;
static custr_t *kbmd_plugin;

static size_t
count_segments(const char *str, const char *sep)
{
	size_t n = 0;

	while (*str != '\0') {
		n++;

		if ((str = strpbrk(str, sep)) == NULL)
			return (n);
		str++;
	}

	return (n);
}

/* Split src into multiple strings, separated be sep */
static errf_t *
split(custr_t *restrict src, const char *sep, custr_t ***restrict segsp,
    size_t *restrict nsegp)
{
	errf_t *ret = ERRF_OK;
	custr_t **segs = NULL;
	size_t nsegs = 0;
	const char *p = NULL;

	nsegs = count_segments(custr_cstr(src), sep);

	if ((ret = ecalloc(nsegs + 1, sizeof (custr_t *), &segs)) != ERRF_OK)
		return  (ret);

	p = custr_cstr(src);
	for (size_t i = 0; i < nsegs; i++) {
		custr_t *seg = NULL;
		size_t len = 0;

		if ((ret = ecustr_alloc(&seg)) != ERRF_OK)
			goto done;

		segs[i] = seg;

		if ((len = strcspn(p, sep)) == 0)
			len = strlen(p);

		if ((ret = ecustr_append_printf(seg, "%.*s",
		    (int)len, p)) != ERRF_OK)
			goto done;

		p += len + 1;
	}

	*segsp = segs;
	*nsegp = nsegs;

done:
	if (ret != ERRF_OK) {
		for (size_t i = 0; i < nsegs; i++)
			custr_free(segs[i]);
		free(segs);
	}

	return (ret);
}

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
		} else {
			break;
		}
		p--;
	}

	if (amt > 0) {
		VERIFY0(custr_rtrunc(cu, amt - 1));
	}
}

#if 0
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
	    (ret = interact(pid, fds, NULL, 0, data, &exitval,
	    B_FALSE)) != ERRF_OK) {
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
#endif

static errf_t *
plugin_create_args(strarray_t *args, const char *subcmd)
{
	errf_t *ret = ERRF_OK;

	mutex_enter(&plugin_mutex);
	ret = strarray_append(args, "%s", custr_cstr(kbmd_plugin));
	mutex_exit(&plugin_mutex);

	if (ret != ERRF_OK)
		return (ret);

	return (strarray_append(args, "%s", subcmd));
}

errf_t *
kbmd_get_pin(const uint8_t guid[restrict], custr_t **restrict pinp)
{
	errf_t *ret = ERRF_OK;
	strarray_t args = STRARRAY_INIT;
	char gstr[GUID_STR_LEN] = { 0 };
	int fds[3] = { -1, -1, -1 };
	pid_t pid;

	*pinp = NULL;

	guidtohex(guid, gstr, sizeof (gstr));

	if ((ret = plugin_create_args(&args, GET_PIN_CMD)) != ERRF_OK) {
		return (errf("PluginError", ret, ""));
	}

	if ((ret = strarray_append(&args, "%s", gstr)) != ERRF_OK) {
		return (errf("PluginError", ret, ""));
	}

	/*
	 * NOTE: this depends on the GUID being the most recently appended
	 * string to args
	 */
	(void) bunyan_debug(tlog, "Running " GET_PIN_CMD " plugin",
	    BUNYAN_T_STRING, "path", args.sar_strs[0],
	    BUNYAN_T_STRING, "guid", args.sar_strs[args.sar_n - 1],
	    BUNYAN_T_END);

	/*
	 * Let the command inherit our environment.
	 * XXX: Maybe set the environment to a fixed known value?
	 */
	ret = spawn(args.sar_strs[0], args.sar_strs, _environ, &pid, fds);
	if (ret != ERRF_OK) {
		strarray_fini(&args);
		return (errf("PluginError", ret, "failed to run plugin %s",
		    args.sar_strs[1]));
	}

	custr_t *data[2] = { 0 };
	int exitval;

	if ((ret = ecustr_alloc(&data[0])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[1])) != ERRF_OK ||
	    (ret = interact(pid, fds, NULL, 0, data, &exitval,
	    B_FALSE)) != ERRF_OK) {
		strarray_fini(&args);
		custr_free(data[0]);
		custr_free(data[1]);
		return (errf("PluginError", ret, ""));
	}

	/*
	 * errf_ts have limited buffer space for an error, so just
	 * log plugin failures to the kbmd log and require the operator
	 * to examine them.
	 */
	if (custr_len(data[1]) > 0) {
		(void) bunyan_warn(tlog, "Get pin plugin had error output",
		    BUNYAN_T_STRING, "plugin", args.sar_strs[0],
		    BUNYAN_T_STRING, "stderr", custr_cstr(data[1]),
		    BUNYAN_T_END);
	}

	if (exitval != 0) {
		(void) bunyan_warn(tlog, "Get pin plugin returned an error",
		    BUNYAN_T_STRING, "plugin", args.sar_strs[0],
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

	strarray_fini(&args);
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
	/*
	 * The 9B slot never has a cert, and reading it will generate
	 * an ArgumentError, so we just explicitly skip it.
	 */
	const static enum piv_slotid slotids[] = {
	    PIV_SLOT_9A, PIV_SLOT_9C, PIV_SLOT_9D, PIV_SLOT_9E
	};

	errf_t *ret = ERRF_OK;

	for (size_t i = 0; i < ARRAY_SIZE(slotids); i++) {
		struct piv_slot *cert = NULL;
		enum piv_slotid slotid = slotids[i];
		char slotstr[9] = { 0 };

		/*
		 * KBMAPI wants the slot names as '9a', '9c', etc --
		 * without the 0x prefix and lowercase.
		 */
		(void) snprintf(slotstr, sizeof (slotstr), "%02x", slotid);

		ret = piv_read_cert(pt, slotid);
		cert = piv_get_slot(pt, slotid);

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
			    "failed to read cert in slot 0x%s", slotstr));
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
    const char *cmd, char *const *args, custr_t **restrict outp)
{
	errf_t *ret = ERRF_OK;
	custr_t *data[3] = { 0 };
	char *json = NULL;
	int fds[3] = { -1, -1, -1 };
	int exitval;
	pid_t pid;

	if ((ret = ecustr_alloc(&data[0])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[1])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[2])) != ERRF_OK)
		goto done;

	if ((ret = pivtoken_to_json(pt, pin, &json)) != ERRF_OK ||
	    (ret = ecustr_append(data[0], json)) != ERRF_OK ||
	    (ret = ecustr_appendc(data[0], '\n')) != ERRF_OK)
		goto done;

	(void) bunyan_debug(tlog, "Running plugin",
	    BUNYAN_T_STRING, "plugin", cmd,
	    BUNYAN_T_STRING, "subcmd", args[1],
	    BUNYAN_T_END);

	if ((ret = spawn(cmd, args, _environ, &pid, fds)) != ERRF_OK ||
	    (ret = interact(pid, fds, custr_cstr(data[0]), custr_len(data[0]),
	    &data[1], &exitval, B_FALSE)) != ERRF_OK) {
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

	*outp = data[1];
	data[1] = NULL;

done:
	close_fds(fds);
	if (json != NULL)
		freezero(json, strlen(json) + 1);
	custr_free(data[0]);
	custr_free(data[1]);
	custr_free(data[2]);
	return (ret);
}

static errf_t *
set_recovery_token(kbmd_token_t *restrict kt, custr_t *restrict rtokstr)
{
	errf_t *ret = ERRF_OK;
	struct sshbuf *buf = NULL;
	const void *ptr = NULL;
	recovery_token_t rtoken = { 0 };
	size_t len;
	int rc;

	if ((buf = sshbuf_new()) == NULL) {
		ret = errf("DecodeError", errfno("sshbuf_new", errno, ""),
		    "failed to allocate buffer to decode recovery token");
		goto done;
	}

	if (custr_len(rtokstr) == 0) {
		ret = errf("DecodeError", NULL, "empty recovery token");
		goto done;
	}

	rc = sshbuf_b64tod(buf, custr_cstr(rtokstr));
	if (rc != SSH_ERR_SUCCESS) {
		ret = errf("DecodeError", ssherrf("sshbuf_b64tod", rc),
		    "failed to decode recovery token");
		goto done;
	}

	ptr = sshbuf_ptr(buf);
	len = sshbuf_len(buf);
	if (ptr == NULL && len > 0) {
		ret = errf("DecodeError", NULL, "sshbuf failed sanity check");
		goto done;
	}
	rtoken.rt_val = (uint8_t *)ptr;
	rtoken.rt_len = len;

	if ((ret = set_piv_rtoken(kt, &rtoken)) != ERRF_OK) {
		ret = errf("DecodeError", ret, "failed to save recovery token");
	}

done:
	sshbuf_free(buf);
	return (ret);
}

static errf_t *
parse_register_output(custr_t *restrict data, custr_t **restrict rtoken,
    struct ebox_tpl **restrict rcfgp)
{
	errf_t *ret = ERRF_OK;
	struct sshbuf *buf = NULL;
	custr_t **lines = NULL;
	size_t nlines = 0;

	*rcfgp = NULL;

	trim_whitespace(data);
	if ((ret = split(data, "\n", &lines, &nlines)) != ERRF_OK) {
		return (ret);
	}

	if  (nlines < 2) {
		ret = errf("OutputError", NULL,
		    "output had %zu lines; expected at least 2", nlines);
		goto done;
	}

	for (size_t i = 2; i < nlines; i++) {
		if ((ret = ecustr_append(lines[1],
		    custr_cstr(lines[i]))) != ERRF_OK) {
			goto done;
		}
	}

	if ((buf = sshbuf_new()) == NULL) {
		ret = errf("OutOfMemory", NULL, "sshbuf_new() failed");
		goto done;
	}

	if (sshbuf_b64tod(buf, custr_cstr(lines[1])) != 0) {
		ret = errf("PluginError", NULL,
		    "failed to decode recovery template");
		goto done;
	}

	if ((ret = sshbuf_get_ebox_tpl(buf, rcfgp)) != ERRF_OK) {
		goto done;
	}

	*rtoken = lines[0];
	lines[0] = NULL;

done:
	for (size_t i = 0; i < nlines; i++) {
		custr_free(lines[i]);
	}
	free(lines);
	sshbuf_free(buf);

	return (ret);
}

errf_t *
register_pivtoken(kbmd_token_t *restrict kt, struct ebox_tpl **restrict rcfgp)
{
	errf_t *ret = ERRF_OK;
	custr_t *output = NULL;
	custr_t *rtoken = NULL;
	struct ebox_tpl *rcfg = NULL;
	strarray_t args = STRARRAY_INIT;

	VERIFY(!piv_token_in_txn(kt->kt_piv));

	*rcfgp = NULL;

	if ((ret = plugin_create_args(&args, REGISTER_TOK_CMD)) != ERRF_OK) {
		ret = errf("RegisterError", ret,
		    "failed to register PIV token");
		goto done;
	}

	if ((ret = plugin_pivtoken_common(kt->kt_piv, kt->kt_pin,
	    args.sar_strs[0], args.sar_strs, &output)) != ERRF_OK) {
		ret = errf("RegisterError", ret,
		    "failed to register PIV token");
		goto done;
	}

	if ((ret = parse_register_output(output, &rtoken, &rcfg)) != ERRF_OK) {
		ret = errf("RegisterError", ret,
		    "failed to register PIV token");
		goto done;
	}

	if ((ret = set_recovery_token(kt, rtoken)) != ERRF_OK) {
		ret = errf("RegisterError", ret,
		    "failed to register PIV token");
		goto done;
	}

	*rcfgp = rcfg;
	rcfg = NULL;

done:
	strarray_fini(&args);
	custr_free(rtoken);
	custr_free(output);
	ebox_tpl_free(rcfg);
	return (ret);
}

errf_t *
replace_pivtoken(const uint8_t guid[GUID_LEN],
    const recovery_token_t *rtoken, kbmd_token_t *restrict kt,
    struct ebox_tpl **restrict rcfgp)
{
	errf_t *ret = ERRF_OK;
	custr_t *rtok64 = NULL;
	custr_t *new_rtoken = NULL;
	strarray_t args = STRARRAY_INIT;

	VERIFY(!piv_token_in_txn(kt->kt_piv));

	if ((ret = ecustr_alloc(&rtok64)) != ERRF_OK) {
		goto done;
	}

	if ((ret = ecustr_append_b64(rtok64, rtoken->rt_val,
	    rtoken->rt_len)) != ERRF_OK) {
		goto done;
	}

	if ((ret = plugin_create_args(&args, REPLACE_TOK_CMD)) != ERRF_OK ||
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
	    args.sar_strs[0], args.sar_strs, &new_rtoken)) != ERRF_OK) {
		goto done;
	}

	ret = set_recovery_token(kt, new_rtoken);

	/* TODO: get new recovery config, for now we return NULL */
	*rcfgp = NULL;

done:
	strarray_fini(&args);
	custr_free(rtok64);
	custr_free(new_rtoken);
	return (ret);
}

errf_t *
new_recovery_token(kbmd_token_t *restrict kt)
{
	errf_t *ret = ERRF_OK;
	custr_t *rtoken = NULL;
	strarray_t args = STRARRAY_INIT;

	VERIFY(!piv_token_in_txn(kt->kt_piv));

	if ((ret = plugin_create_args(&args, NEW_TOK_CMD)) != ERRF_OK ||
	    (ret = strarray_append_guid(&args,
	    piv_token_guid(kt->kt_piv))) != ERRF_OK) {
		ret = errf("PluginError", ret,
		    "failed to create cmdline for %s", NEW_TOK_CMD);
		goto done;
	}

	if ((ret = plugin_pivtoken_common(kt->kt_piv, kt->kt_pin,
	    args.sar_strs[0], args.sar_strs, &rtoken)) != ERRF_OK) {
		goto done;
	}

	ret = set_recovery_token(kt, rtoken);

done:
	strarray_fini(&args);
	custr_free(rtoken);
	return (ret);
}

errf_t *
post_recovery_config_update(void)
{
	errf_t *ret = ERRF_OK;
	strarray_t args = STRARRAY_INIT;
	int fds[3] = { -1, -1, -1 };
	int rc;
	pid_t pid;

	if ((ret = plugin_create_args(&args,
	    POST_RECOVERY_UPDATE)) != ERRF_OK) {
		return (errf("PluginError", ret, ""));
	}

	(void) bunyan_debug(tlog, "Running " POST_RECOVERY_UPDATE " plugin",
	    BUNYAN_T_STRING, "path", args.sar_strs[0],
	    BUNYAN_T_END);

	if ((ret = spawn(args.sar_strs[0], args.sar_strs, _environ, &pid,
	    fds)) != ERRF_OK) {
		ret = errf("PluginError", ret, "failed to run plugin %s",
		    args.sar_strs[1]);
		goto done;
	}

	(void) close(fds[0]);
	(void) close(fds[1]);
	(void) close(fds[2]);

	if ((ret = exitval(pid, &rc)) != ERRF_OK) {
		ret = errf("PluginError", ret,
		    "error obtaining %s plugin exit value",
		    POST_RECOVERY_UPDATE);
	}

	if (rc != 0) {
		ret = errf("PluginError", NULL, "%s plugin returned %d",
		    POST_RECOVERY_UPDATE, rc);
	}

done:
	strarray_fini(&args);
	return (ret);
}

#if 0
static boolean_t
parse_info_line(custr_t *restrict line, size_t *restrict offp,
   custr_t *restrict key, custr_t *restrict val)
{
	const char *p = custr_cstr(line) + *offp;
	const char *end = strchrnul(p, '\n');
	const char *keyp = NULL, *valp = NULL;
	const char *eq = strchr(p, '=');
	size_t keylen = 0, vallen = 0;

	if (*offp == custr_len(line))
		return (B_FALSE);

	custr_reset(key);
	custr_reset(val);

	if (eq != NULL)
		keylen = (size_t)(uintptr_t)(eq - p);
	else
		keylen = (size_t)(uintptr_t)(end - p);

	if (keylen > INT_MAX)
		return (B_FALSE);

	if (custr_append_printf(key, "%.*s", (int)keylen, p) != 0)
		return (B_FALSE);

	eq++;
	if (*eq == '\0')
		goto done;

	vallen = (size_t)(uintptr_t)(end - eq);
	if (vallen > INT_MAX)
		return (B_FALSE);

	if (custr_append_printf(val, "%.*s", (int)vallen, eq) != 0)
		return (B_FALSE);

done:
	trim_whitespace(key);
	trim_whitespace(val);
	*offp += (uintptr_t)(end - p);
	return (B_TRUE);
}

static errf_t *
check_plugin_version(custr_t *restrict plugin,
    unsigned long *restrict plugin_versionp)
{
	errf_t *ret = ERRF_OK;
	strarray_t args = STRARRAY_INIT;
	int fds[3] = { -1, -1, -1 };
	pid_t pid;

	if ((ret = strarray_append(&args, "%s",
	    custr_cstr(plugin))) != ERRF_OK ||
	    (ret = strarray_append(&args, "info")) != ERRF_OK)
		goto done;

	(void) bunyan_debug(tlog, "Checking plugin version",
	    BUNYAN_T_STRING, "plugin", custr_cstr(plugin),
	    BUNYAN_T_END);

	ret = spawn(custr_cstr(plugin), args.sar.strs, _environ, &pid, fds);
	strarray_fini(&args);
	if (ret != ERRF_OK) {
		(void) bunyan_debug(tlog, "Failed to run plugin",
		    BUNYAN_T_STRING, "errmsg", errf_message(ret),
		    BUNYAN_T_END);
		return (ret);
	}

	custr_t *data[2] = { 0 };
	int exitval;

	if ((ret = ecustr_alloc(&data[0])) != ERRF_OK ||
	    (ret = ecustr_alloc(&data[1])) != ERRF_OK ||
	    (ret = interact(pid, fds, NULL, 0, data, &exitval,
	    B_FALSE)) != ERRF_OK) {
		ret = errf("PluginError", ret, "");
		goto done;
	}

	if (exitval != 0) {
		(void) bunyan_warn(tlog,
		    "Plugin returned error querying version",
		    BUNYAN_T_STRING, "plugin", custr_cstr(plugin),
		    BUNYAN_T_INT32, "exitval", exitval,
		    BUNYAN_T_END);
		ret = errf("PluginError", NULL,
		    "plugin returned non-zero exit value %d", exitval);
		goto done;
	}

	trim_whitespace(data[0]);

	/*
	 * Currently, we only support 'version=1'
	 */

done:
	custr_free(data[0]);
	custr_free(data[1]);
	return (ret);
}
#endif

static errf_t *
get_plugin_path(custr_t *prefix)
{
	errf_t *ret = ERRF_OK;
	const char *fmri = NULL, *plugin_path = NULL;
	scf_simple_prop_t *prop = NULL;

	if ((plugin_path = getenv(PLUGIN_PATH_ENV)) != NULL) {
		(void) bunyan_debug(tlog,
		    "Using $" PLUGIN_PATH_ENV " as plugin path",
		    BUNYAN_T_STRING, "plugin_path", plugin_path,
		    BUNYAN_T_END);
		goto done;
	}

	if ((fmri = getenv("SMF_FMRI")) == NULL) {
		(void) bunyan_info(tlog,
		    "Failed to get SMF FMRI, using default",
		    BUNYAN_T_STRING, "default fmri", DEFAULT_FMRI,
		    BUNYAN_T_END);
		fmri = DEFAULT_FMRI;
	}

	if ((prop = scf_simple_prop_get(NULL, fmri, KBMD_PG,
	    KBMD_PROP_INC)) == NULL) {
		(void) bunyan_debug(tlog,
		    "Failed to read plugin SMF property group; using default",
		    BUNYAN_T_END);
		plugin_path = PLUGIN_PATH;
		goto done;
	}

	if ((plugin_path = scf_simple_prop_next_astring(prop)) == NULL) {
		(void) bunyan_debug(tlog,
		    "Failed to read plugin SMF property; using default",
		    BUNYAN_T_END);
		plugin_path = PLUGIN_PATH;
	}

	if (strlen(plugin_path) == 0) {
		(void) bunyan_debug(tlog,
		    "SMF contained empty plugin path; using default",
		    BUNYAN_T_END);
		plugin_path = PLUGIN_PATH;
	}

done:
	/*
	 * We have no way to really recover or deal with this, so we
	 * die if it fails.
	 */
	VERIFY3P(plugin_path, !=, NULL);
	custr_reset(prefix);
	if ((ret = ecustr_append(prefix, plugin_path)) != ERRF_OK)
		return (ret);

	/* Make sure the prefix ends with a '/' */
	VERIFY3U(custr_len(prefix), >, 0);
	if (custr_cstr(prefix)[custr_len(prefix) - 1] != '/') {
		ret = ecustr_appendc(prefix, '/');
	}

	if (prop != NULL) {
		scf_simple_prop_free(prop);
	}

	(void) bunyan_debug(tlog, "Using plugin path",
	    BUNYAN_T_STRING, "path", plugin_path,
	    BUNYAN_T_END);

	return (ret);
}

void
load_plugin(void)
{
	errf_t *ret = ERRF_OK;
	custr_t *path = NULL;
	custr_t *plugin = NULL;
	DIR *dir = NULL;
	struct dirent *de = NULL;
	size_t prefixlen;
	size_t maxversion = 0;

	(void) bunyan_trace(tlog, "load_plugin: enter", BUNYAN_T_END);

	if ((ret = ecustr_alloc(&path)) != ERRF_OK ||
	    (ret = ecustr_alloc(&plugin)) != ERRF_OK)
		goto done;

	if ((ret = get_plugin_path(path)) != ERRF_OK)
		goto done;
	prefixlen = custr_len(path);

	(void) bunyan_debug(tlog, "Scanning for plugins",
	    BUNYAN_T_STRING, "plugin_path", custr_cstr(path),
	    BUNYAN_T_END);

	if ((dir = opendir(custr_cstr(path))) == NULL) {
		(void) bunyan_error(tlog, "Error opening plugin dir",
		    BUNYAN_T_STRING, "plugin dir", custr_cstr(path),
		    BUNYAN_T_STRING, "errmsg", strerror(errno),
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_END);
		goto done;
	}

	while ((de = readdir(dir)) != NULL) {
		unsigned long version;
		unsigned long plugin_version;

		(void) bunyan_trace(tlog, "Found entry",
		     BUNYAN_T_STRING, "filename", de->d_name,
		     BUNYAN_T_END);

		if (strncmp(de->d_name, PLUGIN_PREFIX,
		    sizeof (PLUGIN_PREFIX) - 1) != 0)
			continue;

		if (strlen(de->d_name) < sizeof (PLUGIN_PREFIX))
			continue;

		if ((ret = eparse_ulong(de->d_name + sizeof (PLUGIN_PREFIX) -1,
		    &version)) != ERRF_OK) {
			errf_free(ret);
			ret = ERRF_OK;
			continue;
		}

		(void) bunyan_debug(tlog, "Found plugin",
		    BUNYAN_T_STRING, "filename", de->d_name,
		    BUNYAN_T_UINT64, "version", version,
		    BUNYAN_T_END);

		if (version <= maxversion)
			continue;

		/*
		 * Make sure the version the plugin reports agrees with its
		 * name
		 */
		if (custr_len(path) > prefixlen)
			VERIFY0(custr_trunc(path, prefixlen));

		if ((ret = ecustr_append(path, de->d_name)) != ERRF_OK)
			goto done;

#if 0
		if ((ret = check_plugin_version(path,
		    &plugin_version)) != ERRF_OK) {
			(void) bunyan_info(tlog,
			    "Couldn't verify plugin version; skipping",
			    BUNYAN_T_STRING, "plugin", custr_cstr(path),
			    BUNYAN_T_END);

			errf_free(ret);
			continue;
		}

		if (plugin_version != version) {
			(void) bunyan_info(tlog,
			    "Plugin version mismatch; skippping",
			    BUNYAN_T_UINT32, "expected version",
			    (uint32_t)version,
			    BUNYAN_T_UINT32, "reported version",
			    (uint32_t)plugin_version,
			    BUNYAN_T_END);
			continue;
		}
#endif

		maxversion = version;
		custr_reset(plugin);
		if ((ret = ecustr_append(plugin, custr_cstr(path))) != ERRF_OK)
			goto done;

	}

	mutex_enter(&plugin_mutex);
	if (kbmd_plugin != NULL)
		custr_free(kbmd_plugin);
	kbmd_plugin = plugin;
	plugin = NULL;

	(void) bunyan_info(tlog, "Using plugin",
	    BUNYAN_T_STRING, "pathname", custr_cstr(kbmd_plugin),
	    BUNYAN_T_END);

	mutex_exit(&plugin_mutex);

done:
	if (dir != NULL) {
		/* Any error other than EINTR is considered fatal */
		for (;;) {
			if (closedir(dir) == 0)
				break;
			VERIFY3S(errno, ==, EINTR);
		}
	}

	custr_free(path);
	custr_free(plugin);
}
