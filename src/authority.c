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
#include "include/authority.h"
#include "include/x509.h"
#include "include/key.h"

int
create_private_CA(TALLOC_CTX *mem_ctx, const struct sscg_options *options)
{
    int ret;
    int bits;
    struct sscg_bignum *e;
    struct sscg_rsa_key *key;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* For the private CA, we always use 4096 bits and an exponent
       value of RSA F4 aka 0x10001 (65537) */
    bits = 4096;
    ret = sscg_init_bignum(tmp_ctx, RSA_F4, &e);
    if (ret != EOK) {
        goto done;
    }

    /* Generate an RSA keypair for this CA */
    ret = sscg_generate_rsa_key(tmp_ctx, bits, e, &key);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}