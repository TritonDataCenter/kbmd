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

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "kbmd.h"
#include "pivy/libssh/sshbuf.h"
#include "pivy/libssh/ssherr.h"
#include "pivy/libssh/sshkey.h"
#include "pivy/tlv.h"

/*  We need the piv_cert_comp enum */
#include "pivy/piv-internal.h"

#define funcerrf(cause, fmt, ...)       \
    errf(__func__, cause, fmt , ##__VA_ARGS__)

#define	ADMIN_KEY_LENGTH 24

kbmd_token_t *sys_piv;

/*
 * The default values of a piv token that hasn't been setup.
 */
static const uint8_t DEFAULT_ADMIN_KEY[ADMIN_KEY_LENGTH] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const char DEFAULT_PIN[] = "123456";
static const char DEFAULT_PUK[] = "12345678";

/*
 * Set the given PIN type to a new random pin pin_len characters long and
 * set pin to the new value.
 *
 * NOTE: 'pin' should be sized at least 'pin_len' + 1 bytes in length (to
 * hold the terminating NUL).
 */
static errf_t *
set_pin(struct piv_token *restrict pk, char pin[restrict], size_t pin_len,
    enum piv_pin pin_type, const char *old_pin)
{
	errf_t *ret = ERRF_OK;
	size_t i;

	VERIFY(piv_token_in_txn(pk));

	(void) bunyan_trace(tlog, "Setting PIV pin",
	    BUNYAN_T_STRING, "guid", piv_token_guid_hex(pk),
	    BUNYAN_T_STRING, "pin_type", piv_pin_str(pin_type),
	    BUNYAN_T_END);

	/*
	 * For reasons described in arc4random_uniform(3C), we use it to
	 * generate our PIN.
	 *
	 * XXX: Yubikeys can support non-numeric pins -- should we use more
	 * than digits when creating a yk pin?
	 */
	for (i = 0; i < pin_len; i++)
		pin[i] = arc4random_uniform(10) + '0';
	pin[i] = '\0';

	if ((ret = piv_change_pin(pk, pin_type, old_pin, pin)) != ERRF_OK) {
		ret = funcerrf(ret, "failure to set %s", piv_pin_str(pin_type));
		return (ret);
	}

	(void) bunyan_debug(tlog, "PIV pin set",
	    BUNYAN_T_STRING, "guid", piv_token_guid_hex(pk),
	    BUNYAN_T_STRING, "pin_type", piv_pin_str(pin_type),
	    BUNYAN_T_END);

	return (ERRF_OK);
}

static errf_t *
set_pins(struct piv_token *restrict pk, char pin[restrict PIN_MAX_LENGTH + 1])
{
	errf_t *ret = ERRF_OK;
	char puk[PIN_MAX_LENGTH + 1] = { 0 };

	if ((ret = set_pin(pk, pin, PIN_MAX_LENGTH, PIV_PIN,
	    DEFAULT_PIN)) != ERRF_OK)
		return (ret);

	/*
	 * We discard the PUK value to seal the PIV token (i.e. prevent
	 * modification or replacement of any of the generated keys without
	 * doing a re-initialization of the token).
	 */
	ret = set_pin(pk, puk, PIN_MAX_LENGTH, PIV_PUK, DEFAULT_PUK);
	explicit_bzero(puk, sizeof (puk));
	return (ret);
}

static errf_t *
set_admin_key(struct piv_token *pk)
{
	errf_t	*ret = ERRF_OK;
	uint8_t admin_key[ADMIN_KEY_LENGTH] = { 0 };

	ASSERT(piv_token_in_txn(pk));

	/*
	 * The administrative key is a concept currently exclusive to
	 * yubikeys.  We silently ignore non-yubikeys since we immediately
	 * discard the generated value after generating the keys and certs
	 * in order to seal the yubikey.  Other PIV tokens will need to
	 * be handled as a separate case if they include similar functionality.
	 */
	if (!piv_token_is_ykpiv(pk))
		return (ERRF_OK);

	arc4random_buf(admin_key, sizeof (admin_key));
	ret = ykpiv_set_admin(pk, admin_key, sizeof (admin_key),
	    YKPIV_TOUCH_NEVER);
	explicit_bzero(admin_key, sizeof (admin_key));
	return (ret);
}

static errf_t *
set_serial(X509 *cert)
{
	errf_t *ret = ERRF_OK;
	BIGNUM *serial = NULL;
	ASN1_INTEGER *serial_asn1 = NULL;

	if ((serial = BN_new()) == NULL) {
		make_sslerrf(ret, "BN_new", "setting certificate serial");
		goto done;
	}

	if ((serial_asn1 = ASN1_INTEGER_new()) == NULL) {
		make_sslerrf(ret, "ASN1_INTEGER_new",
		    "setting certificate serial");
		goto done;
	}

	if (BN_pseudo_rand(serial, 64, 0, 0) != 1) {
		make_sslerrf(ret, "BN_pseudo_rand",
		    "setting certificate serial");
		goto done;
	}

	if (BN_to_ASN1_INTEGER(serial, serial_asn1) == NULL) {
		make_sslerrf(ret, "BN_to_ASN1_INTEGER",
		    "setting certificate serial");
		goto done;
	}

	if (X509_set_serialNumber(cert, serial_asn1) != 1) {
		make_sslerrf(ret, "X509_set_serialNumber",
		    "setting certificate serial");
	}

done:
	BN_free(serial);
	ASN1_INTEGER_free(serial_asn1);
	return (ret);
}

static errf_t *
set_subj_and_issuer(struct piv_token *restrict pk, X509 *restrict cert,
    const char *name)
{
	errf_t *ret = ERRF_OK;
	X509_NAME *subj = NULL;
	const char *guidhex = piv_token_guid_hex(pk);

	if ((subj = X509_NAME_new()) == NULL) {
		make_sslerrf(ret, "X509_NAME_new",
		    "setting subject and issuer");
		goto done;
	}

	if (X509_NAME_add_entry_by_NID(subj, NID_title, MBSTRING_ASC,
	    (unsigned char *)name, -1, -1, 0) != 1) {
		make_sslerrf(ret, "X509_NAME_add_entry_by_NID",
		    "setting subject and issuer");
		goto done;
	}

	if (X509_NAME_add_entry_by_NID(subj, NID_commonName, MBSTRING_ASC,
	    (unsigned char *)guidhex, -1, -1, 0) != 1) {
		make_sslerrf(ret, "X509_NAME_add_entry_by_NID",
		    "setting subject and issuer");
		goto done;
	}

	/* XXX: Set OU or organization name? */

	if (X509_set_subject_name(cert, subj) != 1) {
		make_sslerrf(ret, "X509_set_subject_name",
		    "setting subject and issuer");
		goto done;
	}

	if (X509_set_issuer_name(cert, subj) != 1) {
		make_sslerrf(ret, "X509_set_issuer_name",
		    "setting subject and issuer");
	}

done:
	X509_NAME_free(subj);
	return (ret);
}

static errf_t *
set_extensions(X509 *cert, const char *basic, const char *ku)
{
	errf_t *ret = ERRF_OK;
	X509V3_CTX x509ctx;
	X509_EXTENSION *ext = NULL;

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	if ((ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_basic_constraints,
	    (char *)basic)) == NULL) {
		make_sslerrf(ret, "X509V3_EXT_conf_nid", "setting extensions");
		goto done;
	}
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	if ((ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage,
	    (char *)ku)) == NULL) {
		make_sslerrf(ret, "X509V3_EXT_conf_nid", "setting extensions");
	}
	X509_add_ext(cert, ext, -1);

done:
	X509_EXTENSION_free(ext);
	return (ret);
}

static errf_t *
set_pubkey_rsa(EVP_PKEY *restrict pkey, struct sshkey *restrict pub,
    enum sshdigest_types *restrict algp, int *restrict nidp)
{
	errf_t *ret = ERRF_OK;
	RSA *copy = NULL;

	if ((copy = RSA_new()) == NULL) {
		make_sslerrf(ret, "RSA_new", "setting public key");
		goto done;
	}

	if ((copy->e = BN_dup(pub->rsa->e)) == NULL ||
	    (copy->n = BN_dup(pub->rsa->n)) == NULL) {
		make_sslerrf(ret, "BN_dup", "setting public key");
		goto done;
	}

	if (EVP_PKEY_assign_RSA(pkey, copy) != 1) {
		make_sslerrf(ret, "EVP_PKEY_assign_RSA", "setting public key");
		goto done;
	}

	*nidp = NID_sha256WithRSAEncryption;
	*algp = SSH_DIGEST_SHA256;

done:
	if (ret != ERRF_OK) {
		RSA_free(copy);
	}
	return (ret);
}

static errf_t *
set_pubkey_ecdsa(struct piv_token *restrict pk, EVP_PKEY *restrict pkey,
    struct sshkey *restrict pub, enum sshdigest_types *restrict algp,
    int *restrict nidp)
{
	errf_t *ret = ERRF_OK;
	EC_KEY *copy = NULL;
	boolean_t haveSha256 = B_FALSE;
	boolean_t haveSha1 = B_FALSE;

	if ((copy = EC_KEY_dup(pub->ecdsa)) == NULL) {
		make_sslerrf(ret, "EC_KEY_dup", "setting public key");
		goto done;
	}

	if (EVP_PKEY_assign_EC_KEY(pkey, copy) != 1) {
		make_sslerrf(ret, "EC_PKEY_assign_EC_KEY",
		    "setting public key");
		goto done;
	}

	for (size_t i = 0; i < piv_token_nalgs(pk); i++) {
		enum piv_alg alg = piv_token_alg(pk, i);

		switch (alg) {
		case PIV_ALG_ECCP256_SHA256:
			haveSha256 = B_TRUE;
			break;
		case PIV_ALG_ECCP256_SHA1:
			haveSha1 = B_TRUE;
			break;
		default:
			break;
		}
	}

	if (haveSha1 && !haveSha256) {
		*nidp = NID_ecdsa_with_SHA1;
		*algp = SSH_DIGEST_SHA1;
	} else {
		*nidp = NID_ecdsa_with_SHA256;
		*algp = SSH_DIGEST_SHA256;
	}

done:
	if (ret != ERRF_OK) {
		EC_KEY_free(copy);
	}

	return (ret);
}

static errf_t *
set_pubkey(struct piv_token *restrict pk, X509 *restrict cert,
    struct sshkey *restrict pub, enum sshdigest_types *restrict algp)
{
	errf_t *ret = ERRF_OK;
	EVP_PKEY *pkey = NULL;
	enum sshdigest_types wantalg;
	int nid;

	if ((pkey = EVP_PKEY_new()) == NULL) {
		make_sslerrf(ret, "EVP_PKEY_new", "setting public key");
		goto done;
	}

	switch (pub->type) {
	case KEY_RSA:
		ret = set_pubkey_rsa(pkey, pub, &wantalg, &nid);
		if (ret != ERRF_OK)
			goto done;
		break;
	case KEY_ECDSA:
		ret = set_pubkey_ecdsa(pk, pkey, pub, &wantalg, &nid);
		if (ret != ERRF_OK)
			goto done;
		break;
	default:
		ret = funcerrf(NULL, "invalid key type");
		goto done;
	}

	if (X509_set_pubkey(cert, pkey) != 1) {
		make_sslerrf(ret, "X509_set_pubkey", "setting public key");
		goto done;
	}

	cert->sig_alg->algorithm = OBJ_nid2obj(nid);
	cert->cert_info->signature->algorithm = cert->sig_alg->algorithm;
	*algp = wantalg;

done:
	EVP_PKEY_free(pkey);
	return (ret);
}

static errf_t *
null_param(ASN1_TYPE **ap)
{
	ASN1_TYPE *nullp = NULL;

	if ((nullp = ASN1_TYPE_new()) == NULL) {
		errf_t *ret;

		make_sslerrf(ret, "ASN1_TYPE_new",
		    "failed to create NULL parameter");
		return (ret);
	}

	ASN1_TYPE_set(nullp, V_ASN1_NULL, NULL);
	*ap = nullp;
	return (ERRF_OK);
}

static errf_t *
generate_cert(struct piv_token *restrict pk, struct piv_slot *restrict slot)
{
	errf_t *ret = ERRF_OK;
	X509 *cert = NULL;
	struct sshkey *pub = NULL;
	const char *name, *ku, *basic;
	uint8_t *tbs = NULL, *sig = NULL, *cdata = NULL;
	int tbslen = 0, cdlen = 0;
	size_t siglen = 0;
	enum sshdigest_types wantalg, hashalg;
	uint_t flags;
	char slotstr[9] = { 0 };

	(void) snprintf(slotstr, sizeof (slotstr), "%02x", piv_slot_id(slot));

	(void) bunyan_trace(tlog, "Generating PIV cert",
	    BUNYAN_T_STRING, "guid", piv_token_guid_hex(pk),
	    BUNYAN_T_STRING, "slot", slotstr,
	    BUNYAN_T_END);
		
	ASSERT(piv_token_in_txn(pk));

	switch (piv_slot_id(slot)) {
	case 0x9A:
		name = "piv-auth";
		basic = "critical,CA:FALSE";
		ku = "critical,digitalSignature,nonRepudiation";
		break;
	case 0x9C:
		name = "piv-sign";
		basic = "critical,CA:TRUE";
		ku = "critical,digitalSignature,nonRepudiation,"
		    "keyCertSign,cRLSign";
		break;
	case 0x9E:
		name = "piv-card-auth";
		basic = "critical,CA:FALSE";
		ku = "critical,digitalSignature,nonRepudiation";
		break;
	default:
		ret = errf("InvalidSlot", NULL, "slot 0x%02X is not supported",
		    piv_slot_id(slot));
		goto done;
	}

	if ((ret = piv_generate(pk, piv_slot_id(slot), piv_slot_alg(slot),
	    &pub)) != ERRF_OK) {
		goto done;
	}

	if ((cert = X509_new()) == NULL) {
		make_sslerrf(ret, "X509_new", "creating certificate");
		goto done;
	}

	if (X509_set_version(cert, 2) != 1) {
		make_sslerrf(ret, "X509_set_version", "creating certificate");
		goto done;
	}

	if ((ret = set_serial(cert)) != ERRF_OK)
		goto done;

	if (X509_gmtime_adj(X509_get_notBefore(cert), 0) == NULL) {
		make_sslerrf(ret, "X509_gmtime_adj", "creating certficate");
		goto done;
	}

	if (X509_gmtime_adj(X509_get_notAfter(cert), 315360000L) == NULL) {
		make_sslerrf(ret, "X509_gmtime_adj", "creating certificate");
		goto done;
	}

	if ((ret = set_subj_and_issuer(pk, cert, name)) != ERRF_OK)
		goto done;

	if ((ret = set_extensions(cert, basic, ku)) != ERRF_OK)
		goto done;

	if ((ret = set_pubkey(pk, cert, pub, &wantalg)) != ERRF_OK)
		goto done;

	if (pub->type == KEY_RSA) {
		ASN1_TYPE **cert_param = &cert->sig_alg->parameter;
		ASN1_TYPE **cert_info_param =
		    &cert->cert_info->signature->parameter;
	
		if ((ret = null_param(cert_param)) != ERRF_OK ||
		    (ret = null_param(cert_info_param)) != ERRF_OK) {
			goto done;
		}
	}

	cert->cert_info->enc.modified = 1;
	tbslen = i2d_X509_CINF(cert->cert_info, &tbs);
	if (tbs == NULL || tbslen <= 0) {
		make_sslerrf(ret, "i2d_X509_CONF", "creating certificate");
		goto done;
	}

	hashalg = wantalg;

	if ((ret = piv_auth_admin(pk, DEFAULT_ADMIN_KEY,
	    sizeof (DEFAULT_ADMIN_KEY))) != ERRF_OK) {
		goto done;
	}

	for (size_t i = 0; i < 2; i++) {
		ret = piv_sign(pk, slot, tbs, tbslen, &hashalg, &sig, &siglen);
		if (ret == ERRF_OK) {
			break;
		}

		if (!errf_caused_by(ret, "PermissionError")) {
			ret = funcerrf(ret, "failed to sign cert with key");
			goto done;
		}

		enum piv_pin pin_auth = piv_token_default_auth(pk);

		if ((ret = piv_verify_pin(pk, pin_auth, DEFAULT_PIN, NULL,
		    B_TRUE)) != ERRF_OK) {
			goto done;
		}
	}

	if (ret != ERRF_OK) {
		goto done;
	}

	if (hashalg != wantalg) {
		ret = funcerrf(NULL, "card could not sign with the requested "
		    "hash algorithm");
		goto done;
	}

	M_ASN1_BIT_STRING_set(cert->signature, sig, siglen);
	cert->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;

	cdlen = i2d_X509(cert, &cdata);
	if (cdata == NULL || cdlen <= 0) {
		make_sslerrf(ret, "i2d_X509", "creating certificate");
		goto done;
	}

	flags = PIV_COMP_NONE;

	ret = piv_write_cert(pk, piv_slot_id(slot), cdata, cdlen, flags);

done:
	if (ret != ERRF_OK) {
		ret = errf("GenerateError", ret,
		    "unable to create %02X certificate", piv_slot_id(slot));
	} else {
		(void) bunyan_debug(tlog, "Generated PIV cert",
	    	    BUNYAN_T_STRING, "guid", piv_token_guid_hex(pk),
		    BUNYAN_T_STRING, "slot", slotstr,
		    BUNYAN_T_END);
	}

	X509_free(cert);
	return (ret);
}

static errf_t *
generate_certs(struct piv_token *pk)
{
	errf_t *ret = ERRF_OK;
	struct piv_slot *slot;

	if ((ret = piv_read_cert(pk, 0x9E)) != ERRF_OK) {
		errf_free(ret);
		ret = ERRF_OK;
		slot = piv_force_slot(pk, 0x9E, PIV_ALG_ECCP256);
		if ((ret = generate_cert(pk, slot)) != ERRF_OK) {
			return (ret);
		}
	}

	slot = piv_force_slot(pk, 0x9A, PIV_ALG_ECCP256);
	if ((ret = generate_cert(pk, slot)) != ERRF_OK) {
		return (ret);
	}

	slot = piv_force_slot(pk, 0x9C, PIV_ALG_RSA2048);
	return (generate_cert(pk, slot));
}

/*
 * Largely taken from pivy/piv-tool.c cmd_init().  Initialize a piv token
 * and write the guid of the piv token to 'guid'.
 */
static errf_t *
init_token(uint8_t guid[restrict])
{
	errf_t *ret = ERRF_OK;
	struct piv_token *pk, *tokens;
	struct tlv_state *ccc, *chuid;
	uint8_t nguid[GUID_LEN];
	uint8_t fascn[25];
	uint8_t expiry[8] = { '2', '0', '5', '0', '0', '1', '0', '1' };
	uint8_t cardId[21] = {
		/* GSC-RID: GSC-IS data model */
		0xa0, 0x00, 0x00, 0x01, 0x16,
		/* Manufacturer: ff (unknown) */
		0xff,
		/* Card type: JavaCard */
		0x02,
		0x00
	};

	(void) bunyan_trace(tlog, "Initializing new PIV token",
	    BUNYAN_T_END);

	ASSERT(MUTEX_HELD(&piv_lock));

	/*
	 * Find a non-initialized piv token.  We assume a piv token with
	 * a NULL or all-zero GUID is not initialized.  Since we cannot easily
	 * distinguish between multiple uninitialized piv tokens, we require
	 * only one uninitialized token to be present.
	 */
	pk = tokens = NULL;
	if ((ret = piv_enumerate(piv_ctx, &tokens)) != ERRF_OK) {
		piv_release(tokens);
		return (ret);
	}

	bzero(nguid, sizeof (nguid));
	for (struct piv_token *tok = tokens; tok != NULL;
	    tok = piv_token_next(tok)) {
		const uint8_t *tk_guid = piv_token_guid(tok);

		if (tk_guid != NULL &&
		    bcmp(tk_guid, nguid, sizeof (nguid)) != 0) {
			continue;
		}

		if (pk != NULL) {
			piv_release(tokens);
			return (errf("SetupError", NULL,
			    "multiple uninitialzied tokens are present"));
		}
		pk = tok;
	}

	if (pk == NULL) {
		return (errf("NotFoundError", NULL,
		    "no uninitialized tokens are present"));
	}

	arc4random_buf(nguid, sizeof (nguid));
	arc4random_buf(&cardId[6], sizeof (cardId) - 6);
	bzero(fascn, sizeof (fascn));

	/* First, the CCC */
	ccc = tlv_init_write();

	/* Our card ID */
	tlv_push(ccc, 0xF0);
	tlv_write(ccc, cardId, sizeof (cardId));
	tlv_pop(ccc);

	/* Container version numbers */
	tlv_push(ccc, 0xF1);
	tlv_write_byte(ccc, 0x21);
	tlv_pop(ccc);
	tlv_push(ccc, 0xF2);
	tlv_write_byte(ccc, 0x21);
	tlv_pop(ccc);

	tlv_push(ccc, 0xF3);
	tlv_pop(ccc);
	tlv_push(ccc, 0xF4);
	tlv_pop(ccc);

	/* Data Model number */
	tlv_push(ccc, 0xF5);
	tlv_write_byte(ccc, 0x10);

	tlv_pop(ccc);

	tlv_push(ccc, 0xF6);
	tlv_pop(ccc);
	tlv_push(ccc, 0xF7);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFA);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFB);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFC);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFD);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFE);
	tlv_pop(ccc);

	/* Now, set up the CHUID file */
	chuid = tlv_init_write();

	tlv_push(chuid, 0x30);
	tlv_write(chuid, fascn, sizeof (fascn));
	tlv_pop(chuid);

	tlv_push(chuid, 0x34);
	tlv_write(chuid, nguid, sizeof (nguid));
	tlv_pop(chuid);

	tlv_push(chuid, 0x35);
	tlv_write(chuid, expiry, sizeof (expiry));
	tlv_pop(chuid);

	/*
	 * We write out the UUID of the original host where the PIV
	 * token was initialized as the owner UUID in the CHUID.
	 * kbmd does not otherwise use the owner UUID.  It's strictly there
	 * for information.
	 */
	tlv_push(chuid, 0x36);
	tlv_write(chuid, sys_uuid, sizeof (sys_uuid));
	tlv_pop(chuid);

	tlv_push(chuid, 0x3E);
	tlv_pop(chuid);
	tlv_push(chuid, 0xFE);
	tlv_pop(chuid);

	if ((ret = piv_txn_begin(pk)) != ERRF_OK) {
		piv_release(tokens);
		return (ret);
	}

	if ((ret = piv_select(pk)) != ERRF_OK)
		goto done;

	if ((ret = piv_auth_admin(pk, DEFAULT_ADMIN_KEY,
	    sizeof (DEFAULT_ADMIN_KEY))) != ERRF_OK)
		goto done;

	if ((ret = piv_write_file(pk, PIV_TAG_CARDCAP, tlv_buf(ccc),
	    tlv_len(ccc))) != ERRF_OK)
		goto done;

	ret = piv_write_file(pk, PIV_TAG_CHUID, tlv_buf(chuid), tlv_len(chuid));

done:
	piv_txn_end(pk);
	piv_release(tokens);

	tlv_free(ccc);
	tlv_free(chuid);

	if (errf_caused_by(ret, "DeviceOutOfMemoryError")) {
		ret = funcerrf(ret, "out of EEPROM to write CHUID "
		    "and CARDCAP");
		return (ret);
	} else if (errf_caused_by(ret, "PermissionError")) {
		ret = funcerrf(ret, "cannot write init data due to failed "
		    "admin authentication");
		return (ret);
	} else if (ret != ERRF_OK) {
		ret = funcerrf(ret, "failed to write to card");
		return (ret);
	}

	bcopy(nguid, guid, sizeof (nguid));

	char gstr[GUID_STR_LEN] = { 0 };

	guidtohex(nguid, gstr, sizeof (gstr));

	(void) bunyan_info(tlog, "Initialized new PIV token",
	    BUNYAN_T_STRING, "guid", gstr,
	    BUNYAN_T_END);
	    
	return (ERRF_OK);
}

errf_t *
kbmd_setup_token(kbmd_token_t **ktp)
{
	errf_t *ret = ERRF_OK;
	struct piv_token *pk = NULL;
	uint8_t guid[GUID_LEN] = { 0 };

	ASSERT(MUTEX_HELD(&piv_lock));

	(void) bunyan_trace(tlog, "kbmd_setup_token: enter",
	    BUNYAN_T_END);

	if ((ret = zalloc(sizeof (kbmd_token_t), ktp)) != ERRF_OK)
		return (ret);

	if ((ret = init_token(guid)) != ERRF_OK) {
		ret = errf("SetupError", ret,
		    "failed to initialize new PIV token");
		goto fail;
	}

	/*
	 * Once the token has been initalized, re-read all the info with
	 * the new GUID, etc.
	 */
	if ((ret = piv_find(piv_ctx, guid, sizeof (guid), &pk)) != ERRF_OK) {
		ret = errf("SetupError", ret,
		    "could not find token after initialization");
		goto fail;
	}

	if ((ret = piv_txn_begin(pk)) != ERRF_OK ||
	    (ret = piv_select(pk)) != ERRF_OK ||
	    (ret = piv_auth_admin(pk, DEFAULT_ADMIN_KEY,
	    sizeof (DEFAULT_ADMIN_KEY))) != ERRF_OK)
		goto fail;

	if ((ret = generate_certs(pk)) != ERRF_OK) {
		ret = errf("SetupError", ret,
		    "failed to generate PIV certificates");
		goto fail;
	}

	if ((ret = set_pins(pk, (*ktp)->kt_pin)) != ERRF_OK)
		goto fail;

	if ((ret = set_admin_key(pk)) != ERRF_OK)
		goto fail;

	piv_txn_end(pk);

	(*ktp)->kt_piv = pk;
	pk = NULL;

	(void) bunyan_info(tlog, "New PIV token setup",
	    BUNYAN_T_STRING, "guid", piv_token_guid_hex((*ktp)->kt_piv),
	    BUNYAN_T_END);

	/*
	 * XXX: If this fails due to network issues, it would be nice at
	 * some point to support retrying without requiring the operator
	 * to reset the token and then re-init it.
	 */
	if ((ret = kbmd_register_pivtoken(*ktp)) != ERRF_OK) {
		goto fail;
	}

	return (ERRF_OK);

fail:
	if (pk != NULL) {
		if (piv_token_in_txn(pk))
			piv_txn_end(pk);
		piv_release(pk);
	}
	kbmd_token_free(*ktp);
	*ktp = NULL;
	return (ret);
}

void
kbmd_token_free(kbmd_token_t *kt)
{
	if (kt == NULL)
		return;

	if (kt == sys_piv) {
		VERIFY(MUTEX_HELD(&piv_lock));
		if (kt == sys_piv)
			sys_piv = NULL;
	}

	explicit_bzero(kt->kt_pin, sizeof (kt->kt_pin));
	freezero(kt->kt_rtoken, kt->kt_rtoklen);
	free(kt);
}

void
kbmd_set_token(kbmd_token_t *kt)
{
	VERIFY(MUTEX_HELD(&piv_lock));

	if (kt == sys_piv)
		return;

	kbmd_token_free(sys_piv);
	sys_piv = kt;
}

/*
 * One must call piv_read_cert() to load the slot data, or else
 * piv_get_slot() returns NULL.  Since the communication channel to a
 * PIV token is relatively slow, wrap 'try + load if fail + try again'
 * in a handy function for use in kbmd.
 */
errf_t *
kbmd_get_slot(kbmd_token_t *restrict kt, enum piv_slotid slotid,
    struct piv_slot **restrict slotp)
{
	errf_t *ret;
	struct piv_token *pk = kt->kt_piv;

	if ((*slotp = piv_get_slot(pk, slotid)) != NULL) {
		return (ERRF_OK);
	}

	if ((ret = piv_read_cert(pk, slotid)) != ERRF_OK) {
		return (errf("SlotError", ret, "cannot read slot %02X",
		    slotid));
	}

	*slotp = piv_get_slot(pk, slotid);
	VERIFY3P(*slotp, !=, NULL);
	return (ERRF_OK);
}

/*
 * Make sure kt's pin is known.
 */
errf_t *
kbmd_assert_pin(kbmd_token_t *kt)
{
	errf_t *ret = ERRF_OK;
	custr_t *pin = NULL;

	VERIFY3P(kt->kt_piv, !=, NULL);

	/*
	 * The plugin will likely need to use the PIV token for authentication
	 * purposes (e.g. authenticating a KBMAPI request for the pin), so
	 * callers cannot call kbmd_assert_pin while the PIV token is in
	 * a transaction.
	 */
	VERIFY(!piv_token_in_txn(kt->kt_piv));

	if (strlen(kt->kt_pin) > 0) {
		(void) bunyan_debug(tlog, "Using cached PIN for PIV token",
		    BUNYAN_T_STRING, "piv_guid", piv_token_guid_hex(kt->kt_piv),
		    BUNYAN_T_END);
		return (ERRF_OK);
	}

	(void) bunyan_debug(tlog, "Fetching PIN from plugin",
	    BUNYAN_T_STRING, "piv_guid", piv_token_guid_hex(kt->kt_piv),
	    BUNYAN_T_END);

	if ((ret = kbmd_get_pin(piv_token_guid(kt->kt_piv), &pin)) != ERRF_OK)
		return (ret);

	if (custr_len(pin) < PIN_MIN_LENGTH) {
		ret = errf("PinError", NULL,
		    "pin length (%u digits) from plugin is too short",
		    custr_len(pin));
		custr_free(pin);
		return (ret);
	}

	if (custr_len(pin) > PIN_MAX_LENGTH) {
		ret = errf("PinError", NULL,
		    "pin length (%u digits) from plugin is too long",
		    custr_len(pin));
		custr_free(pin);
		return (ret);
	}

	/* +1 to NUL terminate pin */
	bcopy(custr_cstr(pin), kt->kt_pin, custr_len(pin) + 1);
	custr_free(pin);
	return (ERRF_OK);
}

errf_t *
kbmd_verify_pin(kbmd_token_t *kt)
{
	enum piv_pin pin_auth;
	size_t pinlen = strlen(kt->kt_pin);

	VERIFY3U(pinlen, >=, PIN_MIN_LENGTH);
	VERIFY3U(pinlen, <=, PIN_MAX_LENGTH);
	VERIFY(piv_token_in_txn(kt->kt_piv));

	pin_auth = piv_token_default_auth(kt->kt_piv);

	(void) bunyan_debug(tlog, "Verifying PIN of PIV token",
	    BUNYAN_T_STRING, "piv_guid", piv_token_guid_hex(kt->kt_piv),
	    BUNYAN_T_STRING, "auth", piv_pin_str(pin_auth),
	    BUNYAN_T_END);

	return (piv_verify_pin(kt->kt_piv, pin_auth, kt->kt_pin, NULL, B_TRUE));
}

/*
 * Verify we are communicating with the PIV token w/ the given card
 * authentication key.
 */
errf_t *
kbmd_auth_pivtoken(kbmd_token_t *restrict kt, struct sshkey *restrict cak)
{
	errf_t *ret = ERRF_OK;
	struct piv_slot *cakslot = NULL;

	VERIFY(piv_token_in_txn(kt->kt_piv));

	if (cak == NULL)
		return (ERRF_OK);

	if ((ret = kbmd_get_slot(kt, PIV_SLOT_CARD_AUTH, &cakslot)) != ERRF_OK)
		return (ret);

	return (piv_auth_key(kt->kt_piv, cakslot, cak));
}

static errf_t *
kbmd_token_alloc(struct piv_token *pt, kbmd_token_t **ktp)
{
	kbmd_token_t *kt;

	if ((kt = calloc(1, sizeof (kbmd_token_t))) == NULL)
		return (errfno("calloc", errno, ""));
	kt->kt_piv = pt;
	*ktp = kt;
	return (ERRF_OK);
}

errf_t *
kbmd_find_byguid(const uint8_t *guid, size_t guidlen, kbmd_token_t **ktp)
{
	errf_t *ret = ERRF_OK;
	struct piv_token *pt = NULL;

	VERIFY(MUTEX_HELD(&piv_lock));

	ret = piv_find(piv_ctx, guid, guidlen, &pt);

	if (ret != ERRF_OK)
		return (ret);

	if ((ret = kbmd_token_alloc(pt, ktp)) != ERRF_OK) {
		piv_release(pt);
		return (ret);
	}

	return (ERRF_OK);
}

errf_t *
kbmd_find_byslot(enum piv_slotid slotid, const struct sshkey *key,
    kbmd_token_t **ktp)
{
	errf_t *ret = ERRF_OK;
	struct piv_token *pt = NULL, *tokens = NULL;

	VERIFY(MUTEX_HELD(&piv_lock));

	if ((ret = piv_enumerate(piv_ctx, &tokens)) != ERRF_OK) {
		return (ret);
	}

	for (pt = tokens; pt != NULL; pt = piv_token_next(pt)) {
		struct piv_slot *slot = NULL;

		slot = piv_get_slot(pt, slotid);
		if (slot == NULL) {
			if ((ret = piv_txn_begin(pt)) != ERRF_OK ||
			    (ret = piv_select(pt)) != ERRF_OK ||
			    (ret = piv_read_cert(pt, slotid)) != ERRF_OK) {
				errf_free(ret);
				piv_txn_end(pt);
				continue;
			}
			piv_txn_end(pt);
			slot = piv_get_slot(pt, slotid);
			if (slot == NULL)
				continue;
		}

		/*
		 * If there are multiple tokens present on the system
		 * (i.e. tokens has more than one element in the list), we
		 * do not want to carry around the whole list in tokens.  We
		 * just want a single struct piv_token, so we free the list
		 * and then try to refind the token using the GUID.
		 */
		if (sshkey_equal_public(piv_slot_pubkey(slot), key)) {
			uint8_t guid[GUID_LEN];

			bcopy(piv_token_guid(pt), guid, GUID_LEN);
			piv_release(tokens);
			pt = NULL;

			return (kbmd_find_byguid(guid, GUID_LEN, ktp));
		}
	}
	VERIFY3P(pt, ==, NULL);

	piv_release(tokens);
	return (errf("NotFoundError", NULL,
	    "No PIV token found on system with matching %02X key", slotid));
}

errf_t *
set_piv_rtoken(kbmd_token_t *kt, const uint8_t *rtoken, size_t rtokenlen)
{
	errf_t *ret = ERRF_OK;
	void *tokcopy = NULL;

	if ((ret = zalloc(rtokenlen, &tokcopy)) != ERRF_OK)
		return (ret);

	if (kt->kt_rtoken != NULL) {
		freezero(kt->kt_rtoken, kt->kt_rtoklen);
		kt->kt_rtoken = NULL;
		kt->kt_rtoklen = 0;
	}

	bcopy(rtoken, tokcopy, rtokenlen);
	kt->kt_rtoken = tokcopy;
	kt->kt_rtoklen =  rtokenlen;
	return (ret);
}

/*
 * XXX: It might make more sense to have the pin_type->string
 * code in pivy instead of here
 */
const char *
piv_pin_str(enum piv_pin pin_type)
{
	switch (pin_type) {
	case PIV_PIN:
		return("PIN");
	case PIV_GLOBAL_PIN:
		return("global PIN");
	case PIV_PUK:
		return("PUK");
	case PIV_OCC:
		return("OCC");
	case PIV_OCC2:
		return("OCC2");
	case PIV_PAIRING:
		return("pairing PIN");
	default:
		return("unknown PIN");
	}
}
