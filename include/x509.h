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

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.

    Copyright 2017-2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#ifndef _SSCG_X509_H
#define _SSCG_X509_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "include/sscg.h"
#include "include/bignum.h"
#include "include/key.h"

struct sscg_cert_info
{
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
  const char *email;
  char **subject_alt_names;

  /* X509v3 Extensions */
  STACK_OF (X509_EXTENSION) * extensions;
};

/* Initialize a certificate */
struct sscg_cert_info *
sscg_cert_info_new (TALLOC_CTX *mem_ctx, const EVP_MD *hash_fn);

struct sscg_x509_req
{
  X509_REQ *x509_req;
};

struct sscg_x509_cert
{
  X509 *certificate;
};

/* Generate a random serial number

   The generated serial number will be the size of
   sizeof(unsigned long) in bits. This is to ensure
   that it can be returned by BN_get_word().
*/
int
sscg_generate_serial (TALLOC_CTX *mem_ctx, struct sscg_bignum **serial);


/* Create a Certificate Signing Request

   If this function succeeds, it returns 0 and _csr is allocated and populated.
   If it fails, it will return an errno code and _csr is undefined.
*/
int
sscg_x509v3_csr_new (TALLOC_CTX *mem_ctx,
                     struct sscg_cert_info *certinfo,
                     struct sscg_evp_pkey *pkey,
                     struct sscg_x509_req **_csr);

/* Finish creation of the CSR by adding extensions and self-signing
   the request. */
int
sscg_x509v3_csr_finalize (struct sscg_cert_info *certinfo,
                          struct sscg_evp_pkey *spkey,
                          struct sscg_x509_req *csr);

/* Sign a CSR with a private key
 * Returns a signed X509 certificate through the _cert parameter if ret == 0,
 * allocated on mem_ctx. */
int
sscg_sign_x509_csr (TALLOC_CTX *mem_ctx,
                    struct sscg_x509_req *scsr,
                    struct sscg_bignum *serial,
                    size_t days,
                    struct sscg_x509_cert *issuer,
                    struct sscg_evp_pkey *signing_key,
                    const EVP_MD *hash_fn,
                    struct sscg_x509_cert **_cert);

/* Allocate an sscg_x509_cert and set a destructor to clean up the
 * OpenSSL certificate. */
struct sscg_x509_cert *
sscg_x509_cert_new (TALLOC_CTX *mem_ctx);

#endif /* _SSCG_X509_H */
