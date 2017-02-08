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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>

#include "include/bignum.h"
#include "include/key.h"

int main(int argc, char **argv)
{
    int ret, sret;
    struct sscg_bignum *e;
    struct sscg_evp_pkey *pkey;
    size_t i, j;
    unsigned long exp_list[] = {3, 7, 65537, 0};
    int bits[] = {512, 1024, 2048, 4096, 0};

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    printf("Initializing sscg_bignum. ");

    ret = sscg_init_bignum(tmp_ctx, 0, &e);
    if (ret != EOK) {
        printf("FAILED.\n");
        goto done;
    }
    printf("SUCCESS.\n");

    /* Test with exponents 3, 7 and 65537 */

    i = 0;
    while (exp_list[i] != 0) {
        printf("Setting exponent to %lu\n", exp_list[i]);
        sret = BN_set_word(e->bn, exp_list[i]);
        if (sret != 1) {
            fprintf(stderr, "Error occurred in BN_set_word: [%s].\n",
                    ERR_error_string(ERR_get_error(), NULL));
                    ret = EINVAL;
                    goto done;
        }

        j = 0;
        while (bits[j] != 0) {
            printf("\tGenerating %d-bit key. ", bits[j]);
            ret = sscg_generate_rsa_key(tmp_ctx, bits[j], e, &pkey);
            if (ret != EOK) {
                printf("FAILED.\n");
                fprintf(stderr, "Error generating key: [%s].\n",
                        strerror(ret));
                goto done;
            }
            printf("SUCCESS.\n");

            /* Inspect the created key for validity */
            if (EVP_PKEY_RSA != EVP_PKEY_base_id(pkey->evp_pkey)) {
                fprintf(stderr, "Generated key was not an RSA key.\n");
                ret = EINVAL;
                goto done;
            }

            j++;
        }
        i++;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
