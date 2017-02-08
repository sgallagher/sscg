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
    if (bnret != 1) {
        fprintf(stderr, "Error occurred in BN_rand: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *serial = talloc_steal(mem_ctx, bn);
    }
    talloc_zfree(tmp_ctx);

    return ret;
}

struct sscg_cert_info *
sscg_cert_info_new(TALLOC_CTX *mem_ctx, const EVP_MD *hash_fn)
{
    int ret;
    struct sscg_cert_info *certinfo;
    certinfo = talloc_zero(mem_ctx, struct sscg_cert_info);
    CHECK_MEM(certinfo);

    if (hash_fn) {
        certinfo->hash_fn = hash_fn;
    } else {
        certinfo->hash_fn = EVP_sha256();
    }

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
    if (sslret != 1) {
        fprintf(stderr, "Error occurred in X509_REQ_set_version: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    subject = X509_REQ_get_subject_name(csr->x509_req);

    /* Country */
    sslret = X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_UTF8,
             (const unsigned char*)certinfo->country, -1, -1, 0);
    if (sslret != 1) {
        fprintf(stderr,
                "Error occurred in X509_NAME_add_entry_by_txt(C): [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    /* State or Principality */
    if (certinfo->state && certinfo->state[0]) {
        sslret = X509_NAME_add_entry_by_txt(subject, "ST", MBSTRING_UTF8,
                 (const unsigned char*)certinfo->state, -1, -1, 0);
        if (sslret != 1) {
            fprintf(stderr,
                    "Error occurred in X509_NAME_add_entry_by_txt(ST): [%s].\n",
                    ERR_error_string(ERR_get_error(), NULL));
            ret = EIO;
            goto done;
        }
    }

    /* Locality */
    if (certinfo->locality && certinfo->locality[0]) {
        sslret = X509_NAME_add_entry_by_txt(subject, "L", MBSTRING_UTF8,
                 (const unsigned char*)certinfo->locality, -1, -1, 0);
        if (sslret != 1) {
            fprintf(stderr,
                    "Error occurred in X509_NAME_add_entry_by_txt(L): [%s].\n",
                    ERR_error_string(ERR_get_error(), NULL));
            ret = EIO;
            goto done;
        }
    }

    /* Organization */
    if (certinfo->org && certinfo->org[0]) {
        sslret = X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_UTF8,
                 (const unsigned char*)certinfo->org, -1, -1, 0);
        if (sslret != 1) {
            fprintf(stderr,
                    "Error occurred in X509_NAME_add_entry_by_txt(O): [%s].\n",
                    ERR_error_string(ERR_get_error(), NULL));
            ret = EIO;
            goto done;
        }
    }

    /* Organizational Unit */
    if (certinfo->org_unit && certinfo->org_unit[0]) {
        sslret = X509_NAME_add_entry_by_txt(subject, "OU", MBSTRING_UTF8,
                 (const unsigned char*)certinfo->org_unit, -1, -1, 0);
        if (sslret != 1) {
            fprintf(stderr,
                    "Error occurred in X509_NAME_add_entry_by_txt(OU): [%s].\n",
                    ERR_error_string(ERR_get_error(), NULL));
            ret = EIO;
            goto done;
        }
    }

    /* Common Name */
    sslret = X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
             (const unsigned char*)certinfo->cn, -1, -1, 0);
    if (sslret != 1) {
        fprintf(stderr,
                "Error occurred in X509_NAME_add_entry_by_txt(CN): [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    /* TODO: Support Subject Alt Names */

    /* Set the public key for the certificate */
    sslret = X509_REQ_set_pubkey(csr->x509_req, spkey->evp_pkey);
    if (sslret != 1) {
        /* Get information about error from OpenSSL */
        fprintf(stderr, "Error occurred in X509_REQ_set_pubkey: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

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
    int ret;
    struct sscg_x509_cert *cert = talloc_zero(NULL, struct sscg_x509_cert);
    CHECK_MEM(cert);

    cert->certificate = X509_new();
    CHECK_MEM(cert->certificate);
    talloc_set_destructor((TALLOC_CTX *) cert, _sscg_cert_destructor);

    // set version to X509 v3 certificate
    if (X509_set_version(cert->certificate, 2) != 1) {
        /* Get information about error from OpenSSL */
        fprintf(stderr, "Error occurred in X509_set_version: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

done:
    if (ret != EOK) {
        talloc_free(cert);
        return NULL;
    }

    return talloc_steal(mem_ctx, cert);
}

int
sscg_sign_x509_csr(TALLOC_CTX *mem_ctx,
                   struct sscg_x509_req *csr,
                   BIGNUM *serial,
                   ASN1_TIME *not_before,
                   ASN1_TIME *not_after,
                   X509_NAME *issuer,
                   EVP_PKEY *signing_key,
                   const EVP_MD *hash_fn,
                   struct sscg_x509_cert **_cert)
{
    int ret, sslret;
    struct sscg_x509_cert *cert = NULL;
    EVP_PKEY *pkey;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    CHECK_MEM(tmp_ctx);

    cert = sscg_x509_cert_new(tmp_ctx);
    CHECK_MEM(cert);

    /* Set the public key for the signature */
    pkey = EVP_PKEY_new();
    CHECK_MEM(pkey);

    sslret = EVP_PKEY_set1_RSA(pkey, signing_key);
    if (sslret != 1) {
        /* Get information about error from OpenSSL */
        fprintf(stderr, "Error occurred in EVP_PKEY_set1_RSA: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    sslret = X509_sign(cert->certificate, pkey, hash_fn);
    if (sslret <= 0) {
        /* Get information about error from OpenSSL */
        fprintf(stderr, "Error occurred in X509_sign: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    X509_NAME_print_ex_fp(stderr, X509_get_subject_name(cert->certificate), 0, 0);

    ret = EOK;
done:
    EVP_PKEY_free(pkey);
    if (ret == EOK) {
        *_cert = talloc_steal(mem_ctx, cert);
    }
    return ret;
}
