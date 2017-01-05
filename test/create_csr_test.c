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

#include <include/sscg.h>
#include <include/x509.h>

int main(int argc, char **argv)
{
    int ret;
    struct sscg_cert *cert;
    X509_NAME *subject;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    cert = talloc_zero(tmp_ctx, struct sscg_cert);
    if (!cert) {
        ret = ENOMEM;
        goto done;
    }

    ret = sscg_generate_serial(tmp_ctx, &cert->serial);
    if (ret != EOK) {
        printf("FAILED.\n");
        goto done;
    }

    /* Create a subject matching the defaults in sscg.c
       Keep this in sync if defaults change. */
    cert->country = talloc_strdup(cert, "US");
    CHECK_MEM(cert->country);

    cert->state = talloc_strdup(cert, "");
    CHECK_MEM(cert->state);

    cert->locality = talloc_strdup(cert, "");
    CHECK_MEM(cert->locality);

    cert->org = talloc_strdup(cert, "Unspecified");
    CHECK_MEM(cert->org);

    cert->org_unit = talloc_strdup(cert, "");
    CHECK_MEM(cert->org_unit);

    cert->cn = talloc_strdup(cert, "server.example.com");
    CHECK_MEM(cert->cn);

    /* TODO: include subject alt names */

    ret = sscg_create_x509v3_csr(tmp_ctx, cert);
    CHECK_OK(ret);

    /* TODO: compare subject values */

    ret = EOK;
done:
    if (ret != EOK) {
        fprintf(stderr, "FAILURE: %s", strerror(ret));
    }
    talloc_free(tmp_ctx);
    return ret;
}