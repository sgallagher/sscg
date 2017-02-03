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

static int
_sscg_rsa_key_destructor(TALLOC_CTX *mem_ctx)
{
    struct sscg_rsa_key *key =
        talloc_get_type_abort(mem_ctx, struct sscg_rsa_key);

    RSA_free(key->rsa_key);

    return 0;
}

int
sscg_generate_rsa_key(TALLOC_CTX *mem_ctx, int bits, struct sscg_bignum *e,
                      struct sscg_rsa_key **key)
{
    int ret, sslret;
    struct sscg_rsa_key *rsa_key = NULL;
    RSA *rsa;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* Create the talloc container to hold the memory */
    rsa_key = talloc_zero(tmp_ctx, struct sscg_rsa_key);
    if (!rsa_key) {
        ret = ENOMEM;
        goto done;
    }

    /* Create memory for the actual key */
    rsa = RSA_new();
    if (!rsa) {
        ret = ENOMEM;
        goto done;
    }

    rsa_key->rsa_key = rsa;
    talloc_set_destructor((TALLOC_CTX *)rsa_key, _sscg_rsa_key_destructor);

    /* Generate a random RSA keypair */
    sslret = RSA_generate_key_ex(rsa_key->rsa_key, bits, e->bn, NULL);
    if (!sslret) {
        /* Get information about error from OpenSSL */
        fprintf(stderr, "Error occurred in RSA_generate_key_ex: [%s].\n",
                ERR_error_string(ERR_get_error(), NULL));
        ret = ENOTSUP;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *key = talloc_steal(mem_ctx, rsa_key);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}
