/* SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception */
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


#include <string.h>
#include "include/sscg.h"
#include "include/cert.h"
#include "include/x509.h"
#include "include/key.h"

int
create_cert (TALLOC_CTX *mem_ctx,
             const struct sscg_options *options,
             struct sscg_x509_cert *ca_cert,
             struct sscg_evp_pkey *ca_key,
             enum sscg_cert_type type,
             struct sscg_x509_cert **_cert,
             struct sscg_evp_pkey **_key)
{
  int ret;
  size_t i;
  struct sscg_bignum *serial;
  struct sscg_cert_info *certinfo;
  struct sscg_x509_req *csr;
  struct sscg_evp_pkey *pkey;
  struct sscg_x509_cert *cert;
  char *dot;
  X509_EXTENSION *ex = NULL;
  EXTENDED_KEY_USAGE *extended;
  TALLOC_CTX *tmp_ctx = NULL;

  tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  /* create a serial number for this certificate */
  ret = sscg_generate_serial (tmp_ctx, &serial);
  CHECK_OK (ret);

  certinfo = sscg_cert_info_new (tmp_ctx, options->hash_fn);
  CHECK_MEM (certinfo);

  /* Populate cert_info from options */
  certinfo->country = talloc_strdup (certinfo, options->country);
  CHECK_MEM (certinfo->country);

  certinfo->state = talloc_strdup (certinfo, options->state);
  CHECK_MEM (certinfo->state);

  certinfo->locality = talloc_strdup (certinfo, options->locality);
  CHECK_MEM (certinfo->locality);

  certinfo->org = talloc_strdup (certinfo, options->org);
  CHECK_MEM (certinfo->org);

  certinfo->org_unit = talloc_strdup (certinfo, options->org_unit);
  CHECK_MEM (certinfo->org_unit);

  certinfo->email = talloc_strdup (certinfo, options->email);
  CHECK_MEM (certinfo->email);

  certinfo->cn = talloc_strdup (certinfo, options->hostname);
  CHECK_MEM (certinfo->cn);
  /* Truncate the CN at the first dot */
  if ((dot = strchr (certinfo->cn, '.')))
    *dot = '\0';

  if (options->subject_alt_names)
    {
      for (i = 0; options->subject_alt_names[i]; i++)
        {
          certinfo->subject_alt_names = talloc_realloc (
            certinfo, certinfo->subject_alt_names, char *, i + 2);
          CHECK_MEM (certinfo->subject_alt_names);

          certinfo->subject_alt_names[i] = talloc_strdup (
            certinfo->subject_alt_names, options->subject_alt_names[i]);
          CHECK_MEM (certinfo->subject_alt_names[i]);

          /* Add a NULL terminator to the end */
          certinfo->subject_alt_names[i + 1] = NULL;
        }
    }

  /* Ensure that this certificate may not sign other certificates */
  /* Add key extensions */
  ex = X509V3_EXT_conf_nid (
    NULL, NULL, NID_key_usage, "critical,digitalSignature,keyEncipherment");
  CHECK_MEM (ex);
  sk_X509_EXTENSION_push (certinfo->extensions, ex);

  extended = sk_ASN1_OBJECT_new_null ();

  switch (type)
    {
    case SSCG_CERT_TYPE_SERVER:
      sk_ASN1_OBJECT_push (extended, OBJ_nid2obj (NID_server_auth));
      break;

    case SSCG_CERT_TYPE_CLIENT:
      sk_ASN1_OBJECT_push (extended, OBJ_nid2obj (NID_client_auth));
      break;

    default:
      fprintf (stdout, "Unknown certificate type!");
      ret = EINVAL;
      goto done;
    }


  ex = X509V3_EXT_i2d (NID_ext_key_usage, 0, extended);
  sk_ASN1_OBJECT_pop_free (extended, ASN1_OBJECT_free);
  sk_X509_EXTENSION_push (certinfo->extensions, ex);

  /* Mark it as not a CA */
  ex = X509V3_EXT_conf_nid (NULL, NULL, NID_basic_constraints, "CA:FALSE");
  CHECK_MEM (ex);
  sk_X509_EXTENSION_push (certinfo->extensions, ex);

  /* Generate an RSA keypair for this CA */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, "Generating RSA key for certificate.\n");
    }

  ret = sscg_generate_rsa_key (tmp_ctx, options->key_strength, &pkey);
  CHECK_OK (ret);

  /* Create a certificate signing request for the private CA */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, "Generating CSR for certificate.\n");
    }
  ret = sscg_x509v3_csr_new (tmp_ctx, certinfo, pkey, &csr);
  CHECK_OK (ret);

  /* Finalize the CSR */
  ret = sscg_x509v3_csr_finalize (certinfo, pkey, csr);
  CHECK_OK (ret);

  if (options->verbosity >= SSCG_DEBUG)
    {
      const char *tempcert = SSCG_CERT_TYPE_SERVER ? "/tmp/debug-service.csr" :
                                                     "/tmp/debug-client.csr";

      fprintf (stderr, "DEBUG: Writing certificate CSR to %s\n", tempcert);
      BIO *csr_out = BIO_new_file (tempcert, "w");
      int sslret = PEM_write_bio_X509_REQ (csr_out, csr->x509_req);
      CHECK_SSL (sslret, PEM_write_bio_X509_REQ);
    }

  /* Sign the certificate */

  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, "Signing CSR for certificate. \n");
    }

  ret = sscg_sign_x509_csr (tmp_ctx,
                            csr,
                            serial,
                            options->lifetime,
                            ca_cert,
                            ca_key,
                            options->hash_fn,
                            &cert);
  CHECK_OK (ret);

  *_cert = talloc_steal (mem_ctx, cert);
  *_key = talloc_steal (mem_ctx, pkey);

  ret = EOK;
done:
  talloc_free (tmp_ctx);
  return ret;
}
