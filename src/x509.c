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

static int
_sscg_cert_destructor(TALLOC_CTX *ctx)
{
    struct sscg_cert *cert =
        talloc_get_type_abort(ctx, struct sscg_cert);

    X509_REQ_free(cert->csr);

    return 0;
}

int
sscg_create_x509v3_csr(TALLOC_CTX *mem_ctx,
                       struct sscg_cert *cert)
{
    int ret, sslret;
    X509_NAME *subject;

    cert->csr = X509_REQ_new();
    if (!cert->csr) {
        ret = ENOMEM;
        goto done;
    }
    talloc_set_destructor((TALLOC_CTX *)cert, _sscg_cert_destructor);

    /* We will generate only x509v3 certificates */
    sslret = X509_REQ_set_version(cert->csr, 3);
    if (sslret != 1) {
        fprintf(stderr, "Error occurred in X509_REQ_set_version: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    subject = X509_REQ_get_subject_name(cert->csr);

    /* Country */
    sslret = X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_UTF8,
             (const unsigned char*)cert->country, -1, -1, 0);
    if (sslret != 1) {
        fprintf(stderr,
                "Error occurred in X509_NAME_add_entry_by_txt(C): [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    /* State or Principality */
    sslret = X509_NAME_add_entry_by_txt(subject, "ST", MBSTRING_UTF8,
             (const unsigned char*)cert->state, -1, -1, 0);
    if (sslret != 1) {
        fprintf(stderr,
                "Error occurred in X509_NAME_add_entry_by_txt(ST): [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    /* Locality */
    sslret = X509_NAME_add_entry_by_txt(subject, "L", MBSTRING_UTF8,
             (const unsigned char*)cert->locality, -1, -1, 0);
    if (sslret != 1) {
        fprintf(stderr,
                "Error occurred in X509_NAME_add_entry_by_txt(L): [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    /* Organization */
    sslret = X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_UTF8,
             (const unsigned char*)cert->org, -1, -1, 0);
    if (sslret != 1) {
        fprintf(stderr,
                "Error occurred in X509_NAME_add_entry_by_txt(O): [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    /* Organizational Unit */
    sslret = X509_NAME_add_entry_by_txt(subject, "OU", MBSTRING_UTF8,
             (const unsigned char*)cert->org_unit, -1, -1, 0);
    if (sslret != 1) {
        fprintf(stderr,
                "Error occurred in X509_NAME_add_entry_by_txt(OU): [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    /* Common Name */
    sslret = X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
             (const unsigned char*)cert->cn, -1, -1, 0);
    if (sslret != 1) {
        fprintf(stderr,
                "Error occurred in X509_NAME_add_entry_by_txt(CN): [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = EIO;
        goto done;
    }

    /* TODO: Support Subject Alt Names */

    /* TODO: Set the public key */

    /* TODO: Set the private key */

    /* TODO: Make the hash algorithm configurable */

    ret = EOK;

done:
    return ret;
}
