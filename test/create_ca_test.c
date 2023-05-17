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

    Copyright 2017-2023 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <errno.h>
#include <stdio.h>
#include <talloc.h>
#include <string.h>

#include "include/sscg.h"
#include "include/x509.h"

int
main (int argc, char **argv)
{
  int ret, bits;
  struct sscg_cert_info *certinfo;
  struct sscg_bignum *serial;
  struct sscg_x509_req *csr = NULL;
  struct sscg_evp_pkey *pkey = NULL;
  struct sscg_x509_cert *cert = NULL;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  certinfo = sscg_cert_info_new (tmp_ctx, EVP_sha256 ());
  if (!certinfo)
    {
      ret = ENOMEM;
      goto done;
    }

  ret = sscg_generate_serial (tmp_ctx, &certinfo->serial);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }

  /* Create a subject matching the defaults in sscg.c
       Keep this in sync if defaults change. */
  certinfo->country = talloc_strdup (certinfo, "US");
  CHECK_MEM (certinfo->country);

  certinfo->state = talloc_strdup (certinfo, "");
  CHECK_MEM (certinfo->state);

  certinfo->locality = talloc_strdup (certinfo, "");
  CHECK_MEM (certinfo->locality);

  certinfo->org = talloc_strdup (certinfo, "Unspecified");
  CHECK_MEM (certinfo->org);

  certinfo->org_unit = talloc_strdup (certinfo, "");
  CHECK_MEM (certinfo->org_unit);

  certinfo->cn = talloc_strdup (certinfo, "server.example.com");
  CHECK_MEM (certinfo->cn);

  /* TODO: include subject alt names */

  /* Generate an RSA keypair */
  bits = 4096;

  ret = sscg_generate_rsa_key (certinfo, bits, &pkey);
  CHECK_OK (ret);

  /* Create the CSR */
  ret = sscg_x509v3_csr_new (tmp_ctx, certinfo, pkey, &csr);
  CHECK_OK (ret);

  ret = sscg_x509v3_csr_finalize (certinfo, pkey, csr);
  CHECK_OK (ret);

  /* Sign the CSR */
  ret = sscg_generate_serial (tmp_ctx, &serial);
  CHECK_OK (ret);

  ret = sscg_sign_x509_csr (
    tmp_ctx, csr, serial, 3650, NULL, pkey, EVP_sha512 (), &cert);
  CHECK_OK (ret);

  ret = EOK;
done:
  if (ret != EOK)
    {
      fprintf (stderr, "FAILURE: %s\n", strerror (ret));
    }
  talloc_free (tmp_ctx);
  return ret;
}
