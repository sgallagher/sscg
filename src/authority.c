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
    struct sscg_cert_info *ca_certinfo;
    struct sscg_x509_req *csr;
    struct sscg_rsa_key *key;


    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ca_certinfo = sscg_cert_info_new(tmp_ctx, options->hash_fn);
    CHECK_MEM(ca_certinfo);

    /* For the private CA, we always use 4096 bits and an exponent
       value of RSA F4 aka 0x10001 (65537) */
    bits = 4096;
    ret = sscg_init_bignum(tmp_ctx, RSA_F4, &e);
    CHECK_OK(ret);

    /* Generate an RSA keypair for this CA */
    ret = sscg_generate_rsa_key(ca_certinfo, bits, e, &key);
    CHECK_OK(ret);

    /* Create a certificate signing request for the private CA */
    ret = sscg_create_x509v3_csr(tmp_ctx, ca_certinfo, key, &csr);
    CHECK_OK(ret);

    /* TODO: Self-sign the private CA */

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}
