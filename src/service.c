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
#include "include/service.h"
#include "include/x509.h"
#include "include/key.h"

int
create_service_cert (TALLOC_CTX *mem_ctx,
                     const struct sscg_options *options,
                     struct sscg_x509_cert *ca_cert,
                     struct sscg_evp_pkey *ca_key,
                     struct sscg_x509_cert **_svc_cert,
                     struct sscg_evp_pkey **_svc_key)
{
  int ret;
  size_t i;
  struct sscg_bignum *e;
  struct sscg_bignum *serial;
  struct sscg_cert_info *svc_certinfo;
  struct sscg_x509_req *csr;
  struct sscg_evp_pkey *pkey;
  struct sscg_x509_cert *cert;
  X509_EXTENSION *ex = NULL;
  TALLOC_CTX *tmp_ctx = NULL;

  tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  /* create a serial number for this certificate */
  ret = sscg_generate_serial (tmp_ctx, &serial);
  CHECK_OK (ret);

  svc_certinfo = sscg_cert_info_new (tmp_ctx, options->hash_fn);
  CHECK_MEM (svc_certinfo);

  /* Populate cert_info from options */
  svc_certinfo->country = talloc_strdup (svc_certinfo, options->country);
  CHECK_MEM (svc_certinfo->country);

  svc_certinfo->state = talloc_strdup (svc_certinfo, options->state);
  CHECK_MEM (svc_certinfo->state);

  svc_certinfo->locality = talloc_strdup (svc_certinfo, options->locality);
  CHECK_MEM (svc_certinfo->locality);

  svc_certinfo->org = talloc_strdup (svc_certinfo, options->org);
  CHECK_MEM (svc_certinfo->org);

  svc_certinfo->org_unit = talloc_strdup (svc_certinfo, options->org_unit);
  CHECK_MEM (svc_certinfo->org_unit);

  svc_certinfo->email = talloc_strdup (svc_certinfo, options->email);
  CHECK_MEM (svc_certinfo->email);

  svc_certinfo->cn = talloc_strdup (svc_certinfo, options->hostname);
  CHECK_MEM (svc_certinfo->cn);

  if (options->subject_alt_names)
    {
      for (i = 0; options->subject_alt_names[i]; i++)
        {
          svc_certinfo->subject_alt_names = talloc_realloc (
            svc_certinfo, svc_certinfo->subject_alt_names, char *, i + 2);
          CHECK_MEM (svc_certinfo->subject_alt_names);

          svc_certinfo->subject_alt_names[i] = talloc_strdup (
            svc_certinfo->subject_alt_names, options->subject_alt_names[i]);
          CHECK_MEM (svc_certinfo->subject_alt_names[i]);

          /* Add a NULL terminator to the end */
          svc_certinfo->subject_alt_names[i + 1] = NULL;
        }
    }

  /* Ensure that this certificate may not sign other certificates */
  /* Add key extensions */
  ex = X509V3_EXT_conf_nid (
    NULL, NULL, NID_key_usage, "critical,digitalSignature,keyEncipherment");
  CHECK_MEM (ex);
  sk_X509_EXTENSION_push (svc_certinfo->extensions, ex);

  /* Mark it as not a CA */
  ex = X509V3_EXT_conf_nid (NULL, NULL, NID_basic_constraints, "CA:FALSE");
  CHECK_MEM (ex);
  sk_X509_EXTENSION_push (svc_certinfo->extensions, ex);

  /* Use an exponent value of RSA F4 aka 0x10001 (65537) */
  ret = sscg_init_bignum (tmp_ctx, RSA_F4, &e);
  CHECK_OK (ret);

  /* Generate an RSA keypair for this CA */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, "Generating RSA key for service certificate.\n");
    }
  /* TODO: support DSA keys as well */
  ret = sscg_generate_rsa_key (tmp_ctx, options->key_strength, e, &pkey);
  CHECK_OK (ret);

  /* Create a certificate signing request for the private CA */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, "Generating CSR for service certificate.\n");
    }
  ret = sscg_x509v3_csr_new (tmp_ctx, svc_certinfo, pkey, &csr);
  CHECK_OK (ret);

  /* Finalize the CSR */
  ret = sscg_x509v3_csr_finalize (svc_certinfo, pkey, csr);
  CHECK_OK (ret);

  if (options->verbosity >= SSCG_DEBUG)
    {
      fprintf (stderr,
               "DEBUG: Writing service certificate CSR to ./debug-svc.csr\n");
      BIO *svc_csr_out = BIO_new_file ("./debug-svc.csr", "w");
      int sslret = PEM_write_bio_X509_REQ (svc_csr_out, csr->x509_req);
      CHECK_SSL (sslret, PEM_write_bio_X509_REQ);
    }

  /* Sign the certificate */

  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, "Signing CSR for service certificate. \n");
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

  *_svc_cert = talloc_steal (mem_ctx, cert);
  *_svc_key = talloc_steal (mem_ctx, pkey);

  ret = EOK;
done:
  talloc_free (tmp_ctx);
  return ret;
}
