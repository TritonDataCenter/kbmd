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
#include <libnvpair.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/types.h>
#include "common.h"
#include "ecustr.h"
#include "envlist.h"
#include "errf.h"
#include "kbm.h"
#include "kbmd.h"
#include "kspawn.h"
#include "pivy/libssh/sshbuf.h"
#include "pivy/libssh/ssherr.h"
#include "pivy/libssh/sshkey.h"
#include "pivy/tlv.h"
#include "pivy/piv.h"

/*  We need the piv_cert_comp enum */
#include "pivy/piv-internal.h"

#define funcerrf(cause, fmt, ...)       \
    errf(__func__, cause, fmt , ##__VA_ARGS__)

#define	PIN_LENGTH 8
#define	ADMIN_KEY_LENGTH 24

/*
 * The default values of an piv token that hasn't been setup.
 */
static const uint8_t DEFAULT_ADMIN_KEY[ADMIN_KEY_LENGTH] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const char DEFAULT_PIN[] = "123456";
static const char DEFAULT_PUK[] = "12345678";

static errf_t *
set_pins(struct piv_token *restrict pk, char pin[restrict PIN_LENGTH + 1])
{
	errf_t *ret = ERRF_OK;
	char puk[PIN_LENGTH + 1];
	size_t i;

	ASSERT(piv_token_in_txn(pk));

	/*
	 * For reasons described in arc4random_uniform(3C), we use it to
	 * generate our PIN.
	 *
	 * XXX: Yubikeys can support non-numeric pins -- should we use more
	 * than digits when creating a yk pin?
	 */
	for (i = 0; i < PIN_LENGTH; i++)
		pin[i] = arc4random_uniform(10) + '0';
	pin[PIN_LENGTH] = '\0';

	if ((ret = piv_change_pin(pk, PIV_PIN, DEFAULT_PIN, pin)) != ERRF_OK) {
		ret = funcerrf(ret, "failure to set PIN");
		return (ret);
	}

	for (i = 0; i < PIN_LENGTH; i++)
		puk[i] = arc4random_uniform(10) + '0';
	puk[PIN_LENGTH] = '\0';

	if ((ret = piv_change_pin(pk, PIV_PUK, DEFAULT_PUK, puk)) != ERRF_OK)
		ret = funcerrf(ret, "failure to set PUK");

	explicit_bzero(puk, sizeof (puk));
	return (ret);
}

static errf_t *
set_admin_key(struct piv_token *pk)
{
	errf_t	*ret = ERRF_OK;
	uint8_t admin_key[ADMIN_KEY_LENGTH] = { 0 };

	ASSERT(piv_token_in_txn(pk));

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
	X509_EXTENSION_free(ext);

	if ((ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage,
	    (char *)ku)) == NULL) {
		make_sslerrf(ret, "X509V3_EXT_conf_nid", "setting extensions");
	}

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
	RSA_free(copy);
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
	EC_KEY_free(copy);
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
	ASN1_TYPE null_parameter = {
		.type = V_ASN1_NULL
	};

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
		return (ret);
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
		cert->sig_alg->parameter = &null_parameter;
		cert->cert_info->signature->parameter = &null_parameter;
	}

	cert->cert_info->enc.modified = 1;
	tbslen = i2d_X509_CINF(cert->cert_info, &tbs);
	if (tbs == NULL || tbslen <= 0) {
		make_sslerrf(ret, "i2d_X509_CONF", "creating certificate");
		goto done;
	}

	hashalg = wantalg;
	ret = piv_sign(pk, slot, tbs, tbslen, &hashalg, &sig, &siglen);
	if (ret != ERRF_OK) {
		ret = funcerrf(ret, "failed to sign cert with key");
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
		ret = errf("generate", ret, "unable to create %02X certificate",
		    piv_slot_id(slot));
	}

	X509_free(cert);
	return (ERRF_OK);
}

static errf_t *
generate_certs(struct piv_token *pk)
{
	errf_t *ret = ERRF_OK;
	struct piv_slot *slot;

	if ((ret = piv_read_cert(pk, 0x9E)) != ERRF_OK) {
		erfree(ret);
		slot = piv_force_slot(pk, 0x9E, PIV_ALG_ECCP256);
		if ((ret = generate_cert(pk, slot)) != ERRF_OK)
			return (ret);
	}

	slot = piv_force_slot(pk, 0x9A, PIV_ALG_ECCP256);
	if ((ret = generate_cert(pk, slot)) != ERRF_OK)
		return (ret);

	slot = piv_force_slot(pk, 0x9C, PIV_ALG_RSA2048);
	return (generate_cert(pk, slot));
}

static errf_t *
convert_recovery_token(custr_t *restrict b64, uint8_t **restrict rawp,
    size_t *restrict lenp)
{
	errf_t *ret = ERRF_OK;
	struct sshbuf *buf = NULL;
	size_t len;
	int rc;

	if ((buf = sshbuf_new()) == NULL)
		return (errfno("sshbuf_new", errno, ""));

	rc = sshbuf_b64tod(buf, custr_cstr(b64));
	if (rc != SSH_ERR_SUCCESS) {
		sshbuf_free(buf);
		return (ssherrf("sshbuf_b64tod", rc,
		    "cannot decode recovery token"));
	}

	len = sshbuf_len(buf);
	if ((*rawp = malloc(len)) == NULL) {
		ret = errfno("malloc", errno, "");
		sshbuf_free(buf);
		return (ret);
	}

	rc = sshbuf_get(buf, *rawp, len);
	if (rc != SSH_ERR_SUCCESS) {
		ret = ssherrf("sshbuf_get", rc, "");
		sshbuf_free(buf);
		freezero(*rawp, len);
		*rawp = NULL;
		return (ret);
	}

	*lenp = len;
	sshbuf_free(buf);
	return (ERRF_OK);
}

/*
 * Largely taken from pivy/piv-tool.c cmd_init().  Initialize a piv token
 * and write the guid of the piv token to 'guid'.
 */
static errf_t *
kbmd_init_token(uint8_t guid[restrict])
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

	ASSERT(MUTEX_HELD(&piv_lcok));

	/*
	 * Find a non-initialized piv token.  We assume a piv token with
	 * an all-zero GUID is not initialized.  Since we cannot easily
	 * distinguish between multiple uninitialized piv tokens, we require
	 * that only one uninitialized piv token is present.
	 */
	pk = tokens = NULL;
	if ((ret = piv_enumerate(piv_ctx, &tokens)) != ERRF_OK) {
		piv_release(tokens);
		return (ret);
	}

	bzero(nguid, sizeof (nguid));
	for (struct piv_token *tok = tokens; tok != NULL;
	    tok = piv_token_next(tok)) {
		if (bcmp(piv_token_guid(tok), nguid, sizeof (nguid)) != 0)
			continue;

		if (pk != NULL) {
			piv_release(tokens);
			return (errf("SetupError", NULL,
			    "multiple uninitialzied tokens are present"));
		}
		pk = tok;
	}

	arc4random_buf(nguid, sizeof (nguid));
	arc4random_buf(&cardId[6], sizeof (cardId) - 6);
	bzero(fascn, sizeof (fascn));

	/* First, the CCC */
	ccc = tlv_init_write();

	/* Our card ID */
	tlv_push(ccc, 0xF0);
	tlv_write(ccc, cardId, 0, sizeof (cardId));
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
	tlv_write(chuid, fascn, 0, sizeof (fascn));
	tlv_pop(chuid);

	tlv_push(chuid, 0x34);
	tlv_write(chuid, nguid, 0, sizeof (nguid));
	tlv_pop(chuid);

	tlv_push(chuid, 0x35);
	tlv_write(chuid, expiry, 0, sizeof (expiry));
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
	return (ERRF_OK);
}

errf_t *
kbmd_setup_token(struct piv_token **restrict pkp,
    uint8_t **restrict recovery_token, size_t *restrict recovery_token_len)
{
	errf_t *ret = ERRF_OK;
	struct piv_token *pk;
	custr_t *recovery = NULL;
	char pin[PIN_LENGTH + 1] = { 0 };
	uint8_t guid[GUID_LEN] = { 0 };

	ASSERT(MUTEX_HELD(&piv_lock));

	if ((ret = kbmd_init_token(guid)) != ERRF_OK)
		return (ret);

	/*
	 * Once the token has been initalized, re-read all the info with
	 * the new GUID, etc.
	 */
	if ((ret = piv_find(piv_ctx, guid, sizeof (guid), &pk)) != ERRF_OK) {
		*pkp = NULL;
		return (errf("SetupError", ret,
		    "could not find token after initialization"));
	}

	if ((ret = piv_txn_begin(pk)) != ERRF_OK ||
	    (ret = piv_select(pk)) != ERRF_OK ||
	    (ret = piv_auth_admin(pk, DEFAULT_ADMIN_KEY,
	    sizeof (DEFAULT_ADMIN_KEY))) != ERRF_OK)
		goto fail;

	if ((ret = generate_certs(pk)) != ERRF_OK)
		goto fail;

	if ((ret = set_pins(pk, pin)) != ERRF_OK)
		goto fail;

	if ((ret = set_admin_key(pk)) != ERRF_OK)
		goto fail;

	piv_txn_end(pk);

	/*
	 * XXX: If this fails due to network issues, it would be nice at
	 * some point to support retrying without requiring the operator
	 * to reset the token and then re-init it.
	 */
	if ((ret = kbmd_register_pivtoken(pk, pin, &recovery)) != ERRF_OK)
		goto fail;

	if ((ret = convert_recovery_token(recovery, recovery_token,
	    recovery_token_len)) != ERRF_OK)
		goto fail;

	custr_free(recovery);
	*pkp = pk;
	return (ERRF_OK);

fail:
	custr_free(recovery);
	piv_txn_end(pk);
	piv_release(pk);
	explicit_bzero(pin, sizeof (pin));
	*pkp = NULL;
	return (ret);

}
