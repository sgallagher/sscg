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

    X509_REQ_free(cert->x509_req);

    return 0;
}

int
sscg_create_x509v3_csr(TALLOC_CTX *mem_ctx,
                       struct sscg_rsa_key *key,
                       struct sscg_cert *cert)
{
    int ret, sslret;
    X509_REQ *x509_req;
    X509_NAME *subject;

    x509_req = X509_REQ_new();
    if (!x509_req) {
        ret = ENOMEM;
        goto done;
    }
    cert->x509_req = x509_req;
    talloc_set_destructor((TALLOC_CTX *)cert, _sscg_cert_destructor);

    /* We will generate only x509v3 certificates */
    sslret = X509_REQ_set_version(cert->x509_req, 3);
    if (sslret != 1) {
        /* TODO: Get information about error from OpenSSL */
        ret = ENOTSUP;
        goto done;
    }

    subject = X509_REQ_get_subject_name(cert->x509_req);

    ret = EOK;

done:
    return ret;
}
