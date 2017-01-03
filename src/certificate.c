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

#include <openssl/bn.h>
#include <openssl/ssl.h>

#include "include/sscg.h"
#include "include/certificate.h"

int
generate_serial(TALLOC_CTX *mem_ctx, struct sscg_bignum **serial)
{
    int ret = EOK;
    int bnret;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    BIGNUM *bn = BN_new();
    if (!bn) {
        ret = ENOMEM;
        goto done;
    }

    *serial = talloc_zero(tmp_ctx, struct sscg_bignum);
    if (!serial) {
        ret = ENOMEM;
        BN_free(bn);
        goto done;
    }
    talloc_set_destructor((TALLOC_CTX *)*serial, bignum_destructor);

    bnret = BN_rand(bn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    if (bnret != 0) {
        fprintf(stderr, "Error occurred in BN_rand.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        talloc_steal(mem_ctx, serial);
    }
    talloc_zfree(tmp_ctx);

    return ret;
}

int
generate_certificate(TALLOC_CTX *mem_ctx, const struct cert_options *copts)
{

}