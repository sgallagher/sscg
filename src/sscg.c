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

#define _GNU_SOURCE
#include <assert.h>
#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "config.h"
#ifdef HAVE_GETTEXT
#include <libintl.h>
#endif
#include "include/sscg.h"
#include "include/authority.h"
#include "include/cert.h"
#include "include/dhparams.h"
#include "include/io_utils.h"


const char *
sscg_get_file_type_name (enum sscg_file_type type)
{
  switch (type)
    {
    case SSCG_FILE_TYPE_CA: return "CA certificate";

    case SSCG_FILE_TYPE_CA_KEY: return "CA certificate key";

    case SSCG_FILE_TYPE_SVC: return "service certificate";

    case SSCG_FILE_TYPE_SVC_KEY: return "service certificate key";

    case SSCG_FILE_TYPE_CLIENT: return "client auth certificate";

    case SSCG_FILE_TYPE_CLIENT_KEY: return "client auth certificate key";

    case SSCG_FILE_TYPE_CRL: return "certificate revocation list";

    case SSCG_FILE_TYPE_DHPARAMS: return "Diffie-Hellman parameters";

    default: break;
    }

  /* If it wasn't one of these, we have a bug */
  return "Unknown (bug)";
}


int
main (int argc, const char **argv)
{
  int ret, sret;
  struct sscg_options *options;
  bool build_client_cert = false;
  char *dhparams_file = NULL;

  struct sscg_x509_cert *cacert;
  struct sscg_evp_pkey *cakey;
  struct sscg_x509_cert *svc_cert;
  struct sscg_evp_pkey *svc_key;
  struct sscg_x509_cert *client_cert = NULL;
  struct sscg_evp_pkey *client_key = NULL;

  BIO *bp;
  EVP_PKEY *dhparams = NULL;

  struct sscg_stream *stream = NULL;

  /* Always use umask 0577 for generating certificates and keys
       This means that it's opened as write-only by the effective
       user. */
  umask (0577);

#ifdef HAVE_GETTEXT
  /* Initialize internationalization */
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE_NAME, LOCALEDIR);
  textdomain (PACKAGE_NAME);
#endif

  if (getenv ("SSCG_TALLOC_REPORT"))
    talloc_enable_null_tracking ();

  TALLOC_CTX *main_ctx = talloc_new (NULL);
  if (!main_ctx)
    {
      fprintf (stderr, _ ("Could not allocate memory."));
      return ENOMEM;
    }

  ret = sscg_handle_arguments (main_ctx, argc, argv, &options);
  CHECK_OK (ret);

  /* Prepare the output files */
  ret = sscg_io_utils_add_output_file (options->streams,
                                       SSCG_FILE_TYPE_CA,
                                       options->ca_file ? options->ca_file :
                                                          "./ca.crt",
                                       options->ca_mode);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_key (options->streams,
                                      SSCG_FILE_TYPE_CA_KEY,
                                      options->ca_key_file,
                                      options->ca_key_mode,
                                      options->ca_key_pass_prompt,
                                      options->ca_key_password,
                                      options->ca_key_passfile);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_file (
    options->streams,
    SSCG_FILE_TYPE_SVC,
    options->cert_file ? options->cert_file : "./service.pem",
    options->cert_mode);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_key (
    options->streams,
    SSCG_FILE_TYPE_SVC_KEY,
    options->cert_key_file ? options->cert_key_file : "./service-key.pem",
    options->cert_key_mode,
    options->cert_key_pass_prompt,
    options->cert_key_password,
    options->cert_key_passfile);
  CHECK_OK (ret);


  ret = sscg_io_utils_add_output_file (options->streams,
                                       SSCG_FILE_TYPE_CLIENT,
                                       options->client_file,
                                       options->client_mode);
  CHECK_OK (ret);


  ret = sscg_io_utils_add_output_key (
    options->streams,
    SSCG_FILE_TYPE_CLIENT_KEY,
    options->client_key_file ? options->client_key_file : options->client_file,
    options->client_key_mode,
    options->client_key_pass_prompt,
    options->client_key_password,
    options->client_key_passfile);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_file (options->streams,
                                       SSCG_FILE_TYPE_CRL,
                                       options->crl_file,
                                       options->crl_mode);
  CHECK_OK (ret);

  if (!options->skip_dhparams)
    {
      if (options->dhparams_file)
        {
          dhparams_file = talloc_strdup (main_ctx, options->dhparams_file);
        }
      else
        {
          dhparams_file = talloc_strdup (main_ctx, "./dhparams.pem");
        }
      CHECK_MEM (dhparams_file);

      ret = sscg_io_utils_add_output_file (options->streams,
                                           SSCG_FILE_TYPE_DHPARAMS,
                                           dhparams_file,
                                           options->dhparams_mode);
      CHECK_OK (ret);
    }
  /* Validate and open the file paths */
  ret = sscg_io_utils_open_output_files (options->streams, options->overwrite);
  CHECK_OK (ret);


  /* Generate the private CA for the certificate */

  /* First generate the private CA key */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, _ ("Generating keypair for private CA.\n"));
    }
  ret = sscg_generate_keypair (main_ctx, options, &cakey);
  CHECK_OK (ret);


  ret = create_private_CA (main_ctx, options, cakey, &cacert);
  CHECK_OK (ret);


  /* Generate a keypair for this certificate */
  if (options->verbosity >= SSCG_VERBOSE)
    {
      fprintf (stdout, "Generating keypair for certificate.\n");
    }

  ret = sscg_generate_keypair (main_ctx, options, &svc_key);
  CHECK_OK (ret);

  /* Generate the service certificate and sign it with the private CA */
  ret = create_cert (main_ctx,
                     options,
                     cacert,
                     cakey,
                     svc_key,
                     SSCG_CERT_TYPE_SERVER,
                     &svc_cert);
  CHECK_OK (ret);

  /* If requested, generate the client auth certificate and sign it with the
   * private CA.
   */
  build_client_cert = !!(GET_BIO (SSCG_FILE_TYPE_CLIENT));
  if (build_client_cert)
    {
      ret = sscg_generate_keypair (main_ctx, options, &client_key);
      CHECK_OK (ret);

      ret = create_cert (main_ctx,
                         options,
                         cacert,
                         cakey,
                         client_key,
                         SSCG_CERT_TYPE_CLIENT,
                         &client_cert);
      CHECK_OK (ret);
    }


  /* ==== Output the final files ==== */


  /* Write private keys first */

  ret = sscg_io_utils_write_privatekey (
    options->streams, SSCG_FILE_TYPE_CLIENT_KEY, client_key, options);
  CHECK_OK (ret);

  ret = sscg_io_utils_write_privatekey (
    options->streams, SSCG_FILE_TYPE_SVC_KEY, svc_key, options);
  CHECK_OK (ret);

  ret = sscg_io_utils_write_privatekey (
    options->streams, SSCG_FILE_TYPE_CA_KEY, cakey, options);
  CHECK_OK (ret);

  /* Public keys come next, in chain order */

  /* Start with the client certificate */
  if (build_client_cert)
    {
      sret = PEM_write_bio_X509 (GET_BIO (SSCG_FILE_TYPE_CLIENT),
                                 client_cert->certificate);
      CHECK_SSL (sret, PEM_write_bio_X509 (client));
      ANNOUNCE_WRITE (SSCG_FILE_TYPE_CLIENT);
    }

  /* Create service public certificate */
  sret =
    PEM_write_bio_X509 (GET_BIO (SSCG_FILE_TYPE_SVC), svc_cert->certificate);
  CHECK_SSL (sret, PEM_write_bio_X509 (svc));
  ANNOUNCE_WRITE (SSCG_FILE_TYPE_SVC);


  /* Create CA public certificate */
  stream =
    sscg_io_utils_get_stream_by_type (options->streams, SSCG_FILE_TYPE_CA);
  sret = PEM_write_bio_X509 (stream->bio, cacert->certificate);
  CHECK_SSL (sret, PEM_write_bio_X509 (CA));
  ANNOUNCE_WRITE (SSCG_FILE_TYPE_CA);


  /* Then write any non-certificate files */

  /* Create CRL file */
  if (GET_BIO (SSCG_FILE_TYPE_CRL))
    {
      /* The CRL file is left intentionally blank, so do nothing here. The
       * file was created as empty, so it will just be closed and have its
       * permissions set later.
       */
      ANNOUNCE_WRITE (SSCG_FILE_TYPE_CRL);
    }


  /* Create DH parameters file */
  if ((bp = GET_BIO (SSCG_FILE_TYPE_DHPARAMS)))
    {
      if (options->dhparams_prime_len > 0)
        {
          ret = create_dhparams (options->verbosity,
                                 options->dhparams_prime_len,
                                 options->dhparams_generator,
                                 &dhparams);
          CHECK_OK (ret);
        }
      else
        {
          ret = get_params_by_named_group (options->dhparams_group, &dhparams);
          CHECK_OK (ret);
        }

      /* Export the DH parameters to the file */
      sret = PEM_write_bio_Parameters (bp, dhparams);
      CHECK_SSL (sret, PEM_write_bio_Parameters ());
      ANNOUNCE_WRITE (SSCG_FILE_TYPE_DHPARAMS);
      EVP_PKEY_free (dhparams);
    }
  else if (options->dhparams_file)
    {
      /* A filename was explicitly passed, but it couldn't be created */
      ret = EPERM;
      fprintf (stderr, _ ("Could not write to %s: "), options->dhparams_file);
      goto done;
    }

  /* Set the final file permissions */
  sscg_io_utils_finalize_output_files (options->streams);

  ret = EOK;

done:
  talloc_zfree (main_ctx);
  if (ret != EOK)
    {
      SSCG_ERROR ("%s\n", strerror (ret));
    }
  if (getenv ("SSCG_TALLOC_REPORT"))
    talloc_report_full (NULL, stderr);

  return ret;
}
