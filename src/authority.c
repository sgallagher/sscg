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

#include "config.h"
#ifdef HAVE_GETTEXT
#include <libintl.h>
#endif

#include "include/sscg.h"
#include "include/authority.h"
#include "include/x509.h"
#include "include/key.h"

int
create_private_CA (TALLOC_CTX *mem_ctx,
                   const struct sscg_options *options,
                   struct sscg_x509_cert **_cacert,
                   struct sscg_evp_pkey **_cakey)
{
  int ret;
  int bits;
  size_t i;
  TALLOC_CTX *tmp_ctx = NULL;
  struct sscg_bignum *serial;
  struct sscg_cert_info *ca_certinfo;
  struct sscg_x509_req *csr;
  struct sscg_evp_pkey *pkey;
  struct sscg_x509_cert *cert;
  X509_EXTENSION *ex = NULL;
  X509V3_CTX xctx;
  char *name_constraint;
  char *san;
  char *tmp;
  char *dot;

  tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  /* create a serial number for this certificate */
  ret = sscg_generate_serial (tmp_ctx, &serial);
  CHECK_OK (ret);

  ca_certinfo = sscg_cert_info_new (tmp_ctx, options->hash_fn);
  CHECK_MEM (ca_certinfo);

  /* Populate cert_info from options */
  ca_certinfo->country = talloc_strdup (ca_certinfo, options->country);
  CHECK_MEM (ca_certinfo->country);

  ca_certinfo->state = talloc_strdup (ca_certinfo, options->state);
  CHECK_MEM (ca_certinfo->state);

  ca_certinfo->locality = talloc_strdup (ca_certinfo, options->locality);
  CHECK_MEM (ca_certinfo->locality);

  ca_certinfo->org = talloc_strdup (ca_certinfo, options->org);
  CHECK_MEM (ca_certinfo->org);

  ca_certinfo->org_unit =
    talloc_asprintf (ca_certinfo, "ca-%lu", BN_get_word (serial->bn));


  ca_certinfo->email = talloc_strdup (ca_certinfo, options->email);
  CHECK_MEM (ca_certinfo->email);

  ca_certinfo->cn = talloc_strdup (ca_certinfo, options->hostname);
  CHECK_MEM (ca_certinfo->cn);
  /* Truncate the CN at the first dot */
  if ((dot = strchr (ca_certinfo->cn, '.')))
    *dot = '\0';

  if (options->subject_alt_names)
    {
      for (i = 0; options->subject_alt_names[i]; i++)
        {
          ca_certinfo->subject_alt_names = talloc_realloc (
            ca_certinfo, ca_certinfo->subject_alt_names, char *, i + 2);
          CHECK_MEM (ca_certinfo->subject_alt_names);

          ca_certinfo->subject_alt_names[i] = talloc_strdup (
            ca_certinfo->subject_alt_names, options->subject_alt_names[i]);
          CHECK_MEM (ca_certinfo->subject_alt_names[i]);

          /* Add a NULL terminator to the end */
          ca_certinfo->subject_alt_names[i + 1] = NULL;
        }
    }

  /* Make this a CA certificate */

  /* Add key extensions */
  ex = X509V3_EXT_conf_nid (
    NULL,
    NULL,
    NID_key_usage,
    "critical,digitalSignature,keyEncipherment,keyCertSign");
  CHECK_MEM (ex);
  sk_X509_EXTENSION_push (ca_certinfo->extensions, ex);

  /* Mark it as a CA */
  ex = X509V3_EXT_conf_nid (
    NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
  CHECK_MEM (ex);
  sk_X509_EXTENSION_push (ca_certinfo->extensions, ex);

  /* Restrict signing to the CN and subjectAltNames of the service certificate */
  name_constraint =
    talloc_asprintf (tmp_ctx, "permitted;DNS:%s", ca_certinfo->cn);
  CHECK_MEM (name_constraint);

  if (options->subject_alt_names)
    {
      for (i = 0; options->subject_alt_names[i]; i++)
        {
          if (!strchr (options->subject_alt_names[i], ':'))
            {
              san = talloc_asprintf (
                tmp_ctx, "DNS:%s", options->subject_alt_names[i]);
            }
          else if (strncmp (options->subject_alt_names[i], "IP:", 3) == 0)
            {
              char *ip_addr = options->subject_alt_names[i] + 3;
              char *slash = strchr (ip_addr, '/');
              char *clean_ip = ip_addr;
              const char *netmask_str = NULL;

              if (slash)
                {
                  /* Extract IP and netmask parts */
                  clean_ip =
                    talloc_strndup (tmp_ctx, ip_addr, slash - ip_addr);
                  char *cidr_str = slash + 1;
                  int cidr_bits = atoi (cidr_str);

                  /* Convert CIDR to appropriate netmask format */
                  if (strchr (clean_ip, ':'))
                    {
                      /* IPv6 - convert CIDR to hex netmask */
                      if (cidr_bits == 128)
                        {
                          netmask_str =
                            "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF";
                        }
                      else if (cidr_bits == 64)
                        {
                          netmask_str = "FFFF:FFFF:FFFF:FFFF:0:0:0:0";
                        }
                      else
                        {
                          /* For other values, default to /128 */
                          netmask_str =
                            "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF";
                        }
                    }
                  else
                    {
                      /* IPv4 - convert CIDR to dotted decimal */
                      if (cidr_bits == 32)
                        {
                          netmask_str = "255.255.255.255";
                        }
                      else if (cidr_bits == 24)
                        {
                          netmask_str = "255.255.255.0";
                        }
                      else if (cidr_bits == 16)
                        {
                          netmask_str = "255.255.0.0";
                        }
                      else if (cidr_bits == 8)
                        {
                          netmask_str = "255.0.0.0";
                        }
                      else
                        {
                          /* For other values, default to /32 */
                          netmask_str = "255.255.255.255";
                        }
                    }
                }
              else
                {
                  /* No netmask provided - add single host netmask */
                  if (strchr (clean_ip, ':'))
                    {
                      /* IPv6 - use /128 netmask */
                      netmask_str = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF";
                    }
                  else
                    {
                      /* IPv4 - use /32 netmask */
                      netmask_str = "255.255.255.255";
                    }
                }

              san =
                talloc_asprintf (tmp_ctx, "IP:%s/%s", clean_ip, netmask_str);

              if (slash && clean_ip != ip_addr)
                {
                  talloc_free (clean_ip);
                }
            }
          else
            {
              san = talloc_strdup (tmp_ctx, options->subject_alt_names[i]);
            }
          CHECK_MEM (san);

          tmp = talloc_asprintf (
            tmp_ctx, "%s, permitted;%s", name_constraint, san);
          talloc_zfree (san);
          CHECK_MEM (tmp);
          talloc_free (name_constraint);
          name_constraint = tmp;
        }
    }

  ex = X509V3_EXT_conf_nid (NULL, NULL, NID_name_constraints, name_constraint);
  if (!ex)
    {
      ret = EINVAL;
      fprintf (stderr, _ ("Invalid name constraint: %s\n"), name_constraint);
      goto done;
    }
  sk_X509_EXTENSION_push (ca_certinfo->extensions, ex);
  talloc_free (name_constraint);

  /* For the private CA, we always use 4096 bits and an exponent
       value of RSA F4 aka 0x10001 (65537) */
  bits = 4096;

  /* Generate an RSA keypair for this CA */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, _ ("Generating RSA key for private CA.\n"));
    }

  ret = sscg_generate_rsa_key (tmp_ctx, bits, &pkey);
  CHECK_OK (ret);

  /* Create a certificate signing request for the private CA */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, _ ("Generating CSR for private CA.\n"));
    }
  ret = sscg_x509v3_csr_new (tmp_ctx, ca_certinfo, pkey, &csr);
  CHECK_OK (ret);

  X509V3_set_ctx_nodb (&xctx);
  X509V3_set_ctx (&xctx, NULL, NULL, csr->x509_req, NULL, 0);

  /* Set the Subject Key Identifier extension */
  if (options->verbosity >= SSCG_DEBUG)
    {
      fprintf (stderr, "DEBUG: Creating SubjectKeyIdentifier\n");
    }
  ex = X509V3_EXT_conf_nid (NULL, &xctx, NID_subject_key_identifier, "hash");
  if (!ex)
    {
      /* Get information about error from OpenSSL */
      fprintf (stderr,
               _ ("Error occurred in "
                  "X509V3_EXT_conf_nid(SubjectKeyIdentifier): [%s].\n"),
               ERR_error_string (ERR_get_error (), NULL));
      ret = EIO;
      goto done;
    }
  sk_X509_EXTENSION_push (ca_certinfo->extensions, ex);

  /* Finalize the CSR */
  ret = sscg_x509v3_csr_finalize (ca_certinfo, pkey, csr);
  CHECK_OK (ret);

  if (options->verbosity >= SSCG_DEBUG)
    {
      fprintf (stderr, "DEBUG: Writing CA CSR to /tmp/debug-ca.csr\n");
      BIO *ca_csr_out = BIO_new_file ("/tmp/debug-ca.csr", "w");
      int sslret = PEM_write_bio_X509_REQ (ca_csr_out, csr->x509_req);
      CHECK_SSL (sslret, PEM_write_bio_X509_REQ);
    }

  /* Self-sign the private CA */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, _ ("Signing CSR for private CA.\n"));
    }
  ret = sscg_sign_x509_csr (tmp_ctx,
                            csr,
                            serial,
                            options->lifetime,
                            NULL,
                            pkey,
                            options->hash_fn,
                            &cert);
  CHECK_OK (ret);

  *_cacert = talloc_steal (mem_ctx, cert);
  *_cakey = talloc_steal (mem_ctx, pkey);

  ret = EOK;

done:
  talloc_zfree (tmp_ctx);
  return ret;
}
