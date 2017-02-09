/*
    This file is part of sscg.

    sscg is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sscg is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sscg.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <openssl/err.h>
#include <openssl/evp.h>

#include "include/sscg.h"
#include "include/key.h"
#include "include/x509.h"
#include "include/bignum.h"

int
sscg_generate_serial(TALLOC_CTX *mem_ctx, struct sscg_bignum **serial)
{
    int ret = EOK;
    int bnret;
    struct sscg_bignum *bn;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sscg_init_bignum(tmp_ctx, 0, &bn);

    /* We'll create a random number of sizeof(unsigned long) - 1 bits
       to use as the serial. We use unsigned long to ensure that it
       could be printed by BN_get_word() later. We omit the last bit
       in order to ensure that we can't randomly get 0xffffffffL, which
       is reserved by BN_get_word() to mean "too large to represent". */
    bnret = BN_pseudo_rand(bn->bn, (sizeof(unsigned long) * CHAR_BIT) - 1,
                           BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    CHECK_SSL(bnret, BN_pseudo_rand);

    ret = EOK;

done:
    if (ret == EOK) {
        *serial = talloc_steal(mem_ctx, bn);
    }
    talloc_zfree(tmp_ctx);

    return ret;
}

static int
_sscg_certinfo_destructor(TALLOC_CTX *ctx)
{
    struct sscg_cert_info *certinfo =
        talloc_get_type_abort(ctx, struct sscg_cert_info);

    sk_X509_EXTENSION_free(certinfo->extensions);

    return 0;
}

struct sscg_cert_info *
sscg_cert_info_new(TALLOC_CTX *mem_ctx, const EVP_MD *hash_fn)
{
    int ret;
    struct sscg_cert_info *certinfo;
    X509_EXTENSION *ex = NULL;

    certinfo = talloc_zero(mem_ctx, struct sscg_cert_info);
    CHECK_MEM(certinfo);

    if (hash_fn) {
        certinfo->hash_fn = hash_fn;
    } else {
        certinfo->hash_fn = EVP_sha256();
    }

    /* Allocate space for the stack of extensions */
    certinfo->extensions = sk_X509_EXTENSION_new_null();
    CHECK_MEM(certinfo->extensions);
    talloc_set_destructor((TALLOC_CTX *)certinfo, _sscg_certinfo_destructor);

    /* TODO: add default extensions */
    ex = X509V3_EXT_conf_nid(NULL, NULL,
                             NID_key_usage,
                             "critical,digitalSignature,keyEncipherment");
    CHECK_MEM(ex);

    sk_X509_EXTENSION_push(certinfo->extensions, ex);

    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(certinfo);
        return NULL;
    }
    return certinfo;
}

static int
_sscg_csr_destructor(TALLOC_CTX *ctx)
{
    struct sscg_x509_req *csr =
        talloc_get_type_abort(ctx, struct sscg_x509_req);

    X509_REQ_free(csr->x509_req);

    return 0;
}

int
sscg_create_x509v3_csr(TALLOC_CTX *mem_ctx,
                       struct sscg_cert_info *certinfo,
                       struct sscg_evp_pkey *spkey,
                       struct sscg_x509_req **_csr)
{
    int ret, sslret;
    X509_NAME *subject;
    TALLOC_CTX *tmp_ctx;
    struct sscg_x509_req *csr;

    /* Make sure we have a key available */
    if (!talloc_get_type(spkey, struct sscg_evp_pkey)) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    CHECK_MEM(tmp_ctx);

    csr = talloc_zero(tmp_ctx, struct sscg_x509_req);
    CHECK_MEM(csr);

    csr->x509_req = X509_REQ_new();
    CHECK_MEM(csr->x509_req);

    talloc_set_destructor((TALLOC_CTX *)csr, _sscg_csr_destructor);

    /* We will generate only x509v3 certificates */
    sslret = X509_REQ_set_version(csr->x509_req, 3);
    CHECK_SSL(sslret, X509_REQ_set_version);

    subject = X509_REQ_get_subject_name(csr->x509_req);

    /* Country */
    sslret = X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_UTF8,
             (const unsigned char*)certinfo->country, -1, -1, 0);
    CHECK_SSL(sslret, X509_NAME_add_entry_by_txt(C));

    /* State or Principality */
    if (certinfo->state && certinfo->state[0]) {
        sslret = X509_NAME_add_entry_by_txt(subject, "ST", MBSTRING_UTF8,
                 (const unsigned char*)certinfo->state, -1, -1, 0);
        CHECK_SSL(sslret, X509_NAME_add_entry_by_txt(ST));
    }

    /* Locality */
    if (certinfo->locality && certinfo->locality[0]) {
        sslret = X509_NAME_add_entry_by_txt(subject, "L", MBSTRING_UTF8,
                 (const unsigned char*)certinfo->locality, -1, -1, 0);
        CHECK_SSL(sslret, X509_NAME_add_entry_by_txt(L));
    }

    /* Organization */
    if (certinfo->org && certinfo->org[0]) {
        sslret = X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_UTF8,
                 (const unsigned char*)certinfo->org, -1, -1, 0);
        CHECK_SSL(sslret, X509_NAME_add_entry_by_txt(O));
    }

    /* Organizational Unit */
    if (certinfo->org_unit && certinfo->org_unit[0]) {
        sslret = X509_NAME_add_entry_by_txt(subject, "OU", MBSTRING_UTF8,
                 (const unsigned char*)certinfo->org_unit, -1, -1, 0);
        CHECK_SSL(sslret, X509_NAME_add_entry_by_txt(OU));
    }

    /* Common Name */
    sslret = X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
             (const unsigned char*)certinfo->cn, -1, -1, 0);
    CHECK_SSL(sslret, X509_NAME_add_entry_by_txt(CN));

    /* Add extensions */
    sslret = X509_REQ_add_extensions(csr->x509_req, certinfo->extensions);
    CHECK_SSL(sslret, X509_REQ_add_extensions);

    /* Set the public key for the certificate */
    sslret = X509_REQ_set_pubkey(csr->x509_req, spkey->evp_pkey);
    CHECK_SSL(sslret, X509_REQ_set_pubkey(OU));

    /* Set the private key */
    sslret = X509_REQ_sign(csr->x509_req, spkey->evp_pkey, certinfo->hash_fn);
    if (sslret <= 0){
        /* Get information about error from OpenSSL */
        fprintf(stderr, "Error occurred in X509_REQ_sign: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    *_csr = talloc_steal(mem_ctx, csr);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int
_sscg_cert_destructor(TALLOC_CTX *ctx)
{
    struct sscg_x509_cert *cert =
        talloc_get_type_abort(ctx, struct sscg_x509_cert);

    X509_free(cert->certificate);

    return 0;
}

struct sscg_x509_cert *
sscg_x509_cert_new(TALLOC_CTX *mem_ctx)
{
    int ret, sslret;
    struct sscg_x509_cert *cert = talloc_zero(NULL, struct sscg_x509_cert);
    CHECK_MEM(cert);

    cert->certificate = X509_new();
    CHECK_MEM(cert->certificate);
    talloc_set_destructor((TALLOC_CTX *) cert, _sscg_cert_destructor);

    // set version to X509 v3 certificate
    sslret = X509_set_version(cert->certificate, 2);
    CHECK_SSL(sslret, X509_set_version);

done:
    if (ret != EOK) {
        talloc_free(cert);
        return NULL;
    }

    return talloc_steal(mem_ctx, cert);
}

int
sscg_sign_x509_csr(TALLOC_CTX *mem_ctx,
                   struct sscg_x509_req *scsr,
                   struct sscg_bignum *serial,
                   size_t days,
                   X509_NAME *issuer,
                   struct sscg_evp_pkey *signing_key,
                   const EVP_MD *hash_fn,
                   struct sscg_x509_cert **_cert)
{
    int ret, sslret;
    struct sscg_x509_cert *scert = NULL;
    X509 *cert;
    X509_REQ *csr = NULL;
    X509_NAME *subject = NULL;
    EVP_PKEY *pktmp;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    CHECK_MEM(tmp_ctx);

    scert = sscg_x509_cert_new(tmp_ctx);
    CHECK_MEM(scert);

    /* Easier shorthand */
    cert = scert->certificate;
    csr = scsr->x509_req;

    /* Set the serial number for the new certificate */
    BN_to_ASN1_INTEGER(serial->bn, X509_get_serialNumber(cert));

    /* set the issuer name */
    if (issuer) {
        X509_set_issuer_name(cert, issuer);
    } else {
        /* If unspecified, it's self-signing */
        X509_set_issuer_name(cert, X509_REQ_get_subject_name(csr));
    }

    /* set time */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days * 24 * 3650);

    /* set subject */
    subject = X509_NAME_dup(X509_REQ_get_subject_name(csr));
    sslret = X509_set_subject_name(cert, subject);
    CHECK_SSL(sslret, X509_set_subject_name);

    /* set pubkey from req */
    pktmp = X509_REQ_get_pubkey(csr);
    sslret = X509_set_pubkey(cert, pktmp);
    EVP_PKEY_free(pktmp);
    CHECK_SSL(sslret, X509_set_pubkey);

    /* Sign the new certificate */

    sslret = X509_sign(cert, signing_key->evp_pkey, hash_fn);
    if (sslret <= 0) {
        /* Get information about error from OpenSSL */
        fprintf(stderr, "Error occurred in X509_sign: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    if (ret == EOK) {
        *_cert = talloc_steal(mem_ctx, scert);
    }
    X509_NAME_free(subject);
    return ret;
}
