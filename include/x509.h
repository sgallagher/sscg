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
#include "include/key.h"

#ifndef _SSCG_X509_H
# define _SSCG_X509_H

struct sscg_cert_info {
    /* === Input Data === */
    struct sscg_bignum *serial;
    const EVP_MD *hash_fn;

    /* Subject information */
    const char *country;
    const char *state;
    const char *locality;
    const char *org;
    const char *org_unit;
    const char *cn;
    const char **subject_alt_names;
};

/* Initialize a certificate */
struct sscg_cert_info *
sscg_cert_info_new(TALLOC_CTX *mem_ctx, const EVP_MD *hash_fn);

struct sscg_x509_req {
    X509_REQ *x509_req;
};

/* Generate a random serial number

   The generated serial number will be the size of
   sizeof(unsigned long) in bits. This is to ensure
   that it can be returned by BN_get_word().
*/
int
sscg_generate_serial(TALLOC_CTX *mem_ctx, struct sscg_bignum **serial);


/* Create a Certificate Signing Request

   If this function succeeds, it returns 0 and _csr is allocated and populated.
   If it fails, it will return an errno code and _csr is undefined.
*/
int
sscg_create_x509v3_csr(TALLOC_CTX *mem_ctx,
                       struct sscg_cert_info *certinfo,
                       struct sscg_rsa_key *key,
                       struct sscg_x509_req **_csr);

#endif /* _SSCG_X509_H */
