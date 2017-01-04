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

#include "include/sscg.h"
#include "include/key.h"
#include "include/x509.h"

int
generate_serial(TALLOC_CTX *mem_ctx, struct sscg_bignum **serial)
{
    int ret = EOK;
    int bnret;
    struct sscg_bignum *bn;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sscg_init_bignum(tmp_ctx, 0, &bn);

    /* We'll create a random number of 64 bits to use as the serial */
    bnret = BN_rand(bn->bn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    if (bnret != 0) {
        fprintf(stderr, "Error occurred in BN_rand.\n");
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
_sscg_x509_req_destructor(TALLOC_CTX *ctx)
{
    struct sscg_x509_req *req =
        talloc_get_type_abort(ctx, struct sscg_x509_req);

    X509_REQ_free(req->x509_req);

    return 0;
}

int
sscg_create_x509v3_certificate(TALLOC_CTX *mem_ctx,
                               struct sscg_rsa_key *key,
                               struct sscg_x509_req **_req)
{
    int ret, sslret;
    struct sscg_x509_req *req;
    X509_REQ *x509_req;
    X509_NAME *subject;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    req = talloc_zero(tmp_ctx, struct sscg_x509_req);
    if (!req) {
        ret = ENOMEM;
        goto done;
    }

    x509_req = X509_REQ_new();
    if (!x509_req) {
        ret = ENOMEM;
        goto done;
    }
    req->x509_req = x509_req;
    talloc_set_destructor((TALLOC_CTX *)req, _sscg_x509_req_destructor);

    /* We will generate only x509v3 certificates */
    sslret = X509_REQ_set_version(req->x509_req, 3);
    if (sslret != 1) {
        /* TODO: Get information about error from OpenSSL */
        ret = ENOTSUP;
        goto done;
    }

    subject = X509_REQ_get_subject_name(req->x509_req);

    ret = EOK;

done:
    if (ret) {
        *_req = talloc_steal(mem_ctx, req);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}