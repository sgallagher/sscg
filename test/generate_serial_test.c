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

#include "include/x509.h"

int main(int argc, char **argv)
{
    int ret;
    unsigned long val;
    struct sscg_bignum *serial;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    printf("Testing sscg_generate_serial. ");

    ret = sscg_generate_serial(tmp_ctx, &serial);
    if (ret != EOK) {
        printf("FAILED.\n");
        goto done;
    }
    printf("SUCCESS.\n");

    printf("Verifying serial initialized to nonzero. ");
    val = BN_get_word(serial->bn);
    if (val == 0 || val == 0xffffffffL) {
        /* If val is zero or out of range for unsigned long,
           generation failed somewhere. */
        printf("FAILED.\n");
        ret = EINVAL;
        goto done;
    }
    printf("SUCCESS. Value is [%lu]\n", val);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}