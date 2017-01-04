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

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "include/sscg.h"
#include "include/bignum.h"

#ifndef _SSCG_X509_H
# define _SSCG_X509_H

struct cert_options {
    BIGNUM *serial_number;
    const char *COUNTRY_NAME;
    const char *STATE_OR_PROVINCE_NAME;
    const char *LOCALITY_NAME;
    const char *ORGANIZATION_NAME;
    const char *ORGANIZATIONAL_UNIT_NAME;
    const char *COMMON_NAME;
    const char **SUBJECT_ALTERNATIVE_NAMES;
};

struct sscg_x509_req {
    X509_REQ *x509_req;
};

int
generate_serial(TALLOC_CTX *mem_ctx, struct sscg_bignum **serial);


#endif /* _SSCG_X509_H */