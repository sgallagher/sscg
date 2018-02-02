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

#include <popt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <path_utils.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/param.h>

#include "config.h"
#include "include/sscg.h"
#include "include/authority.h"
#include "include/service.h"

static int
set_default_options (struct sscg_options *opts)
{
  opts->lifetime = 3650;
  opts->key_strength = 2048;
  return 0;
}

static void
print_options (struct sscg_options *opts)
{
  size_t i = 0;
  fprintf (stdout, "==== Options ====\n");
  fprintf (stdout, "Certificate lifetime: %d\n", opts->lifetime);
  fprintf (stdout, "Country: \"%s\"\n", opts->country);
  fprintf (stdout, "State or Principality: \"%s\"\n", opts->state);
  fprintf (stdout, "Locality: \"%s\"\n", opts->locality);
  fprintf (stdout, "Organization: \"%s\"\n", opts->org);
  fprintf (stdout, "Organizational Unit: \"%s\"\n", opts->org_unit);
  fprintf (stdout, "Email Address: \"%s\"\n", opts->email);
  fprintf (stdout, "Hostname: \"%s\"\n", opts->hostname);
  if (opts->subject_alt_names)
    {
      for (i = 0; opts->subject_alt_names[i]; i++)
        {
          fprintf (stdout,
                   "Subject Alternative Name: \"%s\"\n",
                   opts->subject_alt_names[i]);
        }
    }
  fprintf (stdout, "=================\n");
}

static int
_sscg_normalize_path (TALLOC_CTX *mem_ctx,
                      const char *path,
                      const char *path_default,
                      char **_normalized_path)
{
  int ret;
  char *orig_path = NULL;
  char *normalized_path = NULL;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  if (path)
    {
      orig_path = talloc_strdup (tmp_ctx, path);
    }
  else
    {
      if (!path_default)
        {
          /* If no default is set and no path was provided,
             * return NULL */
          *_normalized_path = NULL;
          ret = EOK;
          goto done;
        }
      orig_path = talloc_strdup (tmp_ctx, path_default);
      CHECK_MEM (orig_path);
    }

  normalized_path = talloc_zero_array (tmp_ctx, char, PATH_MAX);
  CHECK_MEM (normalized_path);

  ret = make_normalized_absolute_path (normalized_path, PATH_MAX, orig_path);
  CHECK_OK (ret);

  *_normalized_path = talloc_steal (mem_ctx, normalized_path);
  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}

int
main (int argc, const char **argv)
{
  int ret, sret, opt;
  size_t i;
  poptContext pc;
  struct sscg_options *options;

  char *country = NULL;
  char *state = NULL;
  char *locality = NULL;
  char *organization = NULL;
  char *organizational_unit = NULL;
  char *email = NULL;
  char *hostname = NULL;
  char *packagename;
  char *hash_alg = NULL;
  char **alternative_names = NULL;

  char *ca_file = NULL;
  char *ca_key_file = NULL;
  char *cert_file = NULL;
  char *cert_key_file = NULL;

  int ca_mode = 0644;
  int ca_key_mode = 0600;
  int cert_mode = 0644;
  int cert_key_mode = 0600;

  char *create_mode = NULL;

  struct sscg_x509_cert *cacert;
  struct sscg_evp_pkey *cakey;
  struct sscg_x509_cert *svc_cert;
  struct sscg_evp_pkey *svc_key;

  BIO *ca_out = NULL;
  BIO *ca_key_out = NULL;
  BIO *cert_out = NULL;
  BIO *cert_key_out = NULL;

  FILE *fp;

  /* Always use umask 0577 for generating certificates and keys
       This means that it's opened as write-only by the effective
       user. */
  umask (0577);

  TALLOC_CTX *main_ctx = talloc_new (NULL);
  if (!main_ctx)
    {
      fprintf (stderr, "Could not allocate memory.");
      return ENOMEM;
    }

  options = talloc_zero (main_ctx, struct sscg_options);
  CHECK_MEM (options);

  ret = set_default_options (options);
  if (ret != EOK)
    goto done;

  options->verbosity = SSCG_DEFAULT;
  struct poptOption long_options[] = {
    POPT_AUTOHELP{ "quiet",
                   'q',
                   POPT_ARG_VAL,
                   &options->verbosity,
                   SSCG_QUIET,
                   _ ("Display no output unless there is an error."),
                   NULL },
    { "verbose",
      'v',
      POPT_ARG_VAL,
      &options->verbosity,
      SSCG_VERBOSE,
      _ ("Display progress messages."),
      NULL },
    { "debug",
      'd',
      POPT_ARG_VAL,
      &options->verbosity,
      SSCG_DEBUG,
      _ ("Enable logging of debug messages. Implies verbose. Warning! "
         "This will print private key information to the screen!"),
      NULL },
    { "version",
      'V',
      POPT_ARG_NONE,
      &options->print_version,
      0,
      _ ("Display the version number and exit."),
      NULL },
    { "force",
      'f',
      POPT_ARG_NONE,
      &options->overwrite,
      0,
      _ ("Overwrite any pre-existing files in the requested locations"),
      NULL },
    { "lifetime",
      '\0',
      POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->lifetime,
      0,
      _ ("Certificate lifetime (days)."),
      _ ("1-3650") },
    { "country",
      '\0',
      POPT_ARG_STRING,
      &country,
      0,
      _ ("Certificate DN: Country (C). (default: \"US\")"),
      _ ("US, CZ, etc.") },
    { "state",
      '\0',
      POPT_ARG_STRING,
      &state,
      0,
      _ ("Certificate DN: State or Province (ST)."),
      _ ("Massachusetts, British Columbia, etc.") },
    { "locality",
      '\0',
      POPT_ARG_STRING,
      &locality,
      0,
      _ ("Certificate DN: Locality (L)."),
      _ ("Westford, Paris, etc.") },
    { "organization",
      '\0',
      POPT_ARG_STRING,
      &organization,
      0,
      _ ("Certificate DN: Organization (O). (default: \"Unspecified\")"),
      _ ("My Company") },
    { "organizational-unit",
      '\0',
      POPT_ARG_STRING,
      &organizational_unit,
      0,
      _ ("Certificate DN: Organizational Unit (OU)."),
      _ ("Engineering, etc.") },
    { "email",
      '\0',
      POPT_ARG_STRING,
      &email,
      0,
      _ ("Certificate DN: Email Address (Email)."),
      _ ("myname@example.com") },
    { "hostname",
      '\0',
      POPT_ARG_STRING,
      &hostname,
      0,
      _ ("The valid hostname of the certificate. Must be an FQDN. (default: "
         "current system FQDN)"),
      _ ("server.example.com") },
    { "subject-alt-name",
      '\0',
      POPT_ARG_ARGV,
      &alternative_names,
      0,
      _ ("Optional additional valid hostnames for the certificate. "
         "In addition to hostnames, this option also accepts explicit values "
         "supported by RFC 5280 such as "
         "IP:xxx.xxx.xxx.xxx/yyy.yyy.yyy.yyy "
         "May be specified multiple times."),
      _ ("alt.example.com") },
    {
      "package",
      '\0',
      POPT_ARG_STRING,
      &packagename,
      0,
      _ ("Unused. Retained for compatibility with earlier versions of sscg."),
      NULL,
    },
    { "key-strength",
      '\0',
      POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->key_strength,
      0,
      _ ("Strength of the certificate private keys in bits."),
      _ ("{512,1024,2048,4096}") },
    {
      "hash-alg",
      '\0',
      POPT_ARG_STRING,
      &hash_alg,
      0,
      _ ("Hashing algorithm to use for signing. (default: sha256)"),
      _ ("{sha256,sha384,sha512}"),
    },
    {
      "ca-file",
      '\0',
      POPT_ARG_STRING,
      &ca_file,
      0,
      _ ("Path where the public CA certificate will be stored. (default: "
         "\"./ca.crt\")"),
      NULL,
    },
    {
      "ca-mode",
      '\0',
      POPT_ARG_INT,
      &ca_mode,
      0,
      _ ("File mode of the created CA certificate. (default: 0644)"),
      _ ("0644"),
    },
    {
      "ca-key-file",
      '\0',
      POPT_ARG_STRING,
      &ca_key_file,
      0,
      _ ("Path where the CA's private key will be stored. If unspecified, "
         "the key will be destroyed rather than written to the disk."),
      NULL,
    },
    {
      "ca-key-mode",
      '\0',
      POPT_ARG_INT,
      &ca_key_mode,
      0,
      _ ("File mode of the created CA key. (default: 0600)"),
      _ ("0600"),
    },
    {
      "cert-file",
      '\0',
      POPT_ARG_STRING,
      &cert_file,
      0,
      _ ("Path where the public service certificate will be stored. "
         "(default \"./service.pem\")"),
      NULL,
    },
    {
      "cert-mode",
      '\0',
      POPT_ARG_INT,
      &cert_mode,
      0,
      _ ("File mode of the created certificate. (default: 0644)"),
      _ ("0644"),
    },
    {
      "cert-key-file",
      '\0',
      POPT_ARG_STRING,
      &cert_key_file,
      0,
      _ ("Path where the service's private key will be stored. "
         "(default \"service-key.pem\")"),
      NULL,
    },
    {
      "cert-key-mode",
      '\0',
      POPT_ARG_INT,
      &cert_key_mode,
      0,
      _ ("File mode of the created certificate key. (default: 0600)"),
      _ ("0600"),
    },
    POPT_TABLEEND
  };

  pc = poptGetContext (argv[0], argc, argv, long_options, 0);
  while ((opt = poptGetNextOpt (pc)) != -1)
    {
      switch (opt)
        {
        default:
          fprintf (stderr,
                   "\nInvalid option %s: %s\n\n",
                   poptBadOption (pc, 0),
                   poptStrerror (opt));
          poptPrintUsage (pc, stderr, 0);
          return 1;
        }
    }

  if (options->print_version)
    {
      /* Print the version number and exit */
      printf ("%s\n", PACKAGE_VERSION);
      return 0;
    }

  /* Process the Subject information */

  if (country)
    {
      if (strlen (country) != 2)
        {
          fprintf (stderr, "Country codes must be exactly two letters.\n");
          ret = EINVAL;
          goto done;
        }
      options->country = talloc_strdup (options, country);
    }
  else
    {
      /* Country name is mandatory. 1.0 (in Golang) defaulted to
           "US", so we'll keep it the same to avoid breaking existing
           usages. */
      options->country = talloc_strdup (options, "US");
    }
  CHECK_MEM (options->country);

  if (state)
    {
      options->state = talloc_strdup (options, state);
    }
  else
    {
      options->state = talloc_strdup (options, "");
    }
  CHECK_MEM (options->state);

  if (locality)
    {
      options->locality = talloc_strdup (options, locality);
    }
  else
    {
      options->locality = talloc_strdup (options, "");
    }
  CHECK_MEM (options->locality);

  if (organization)
    {
      options->org = talloc_strdup (options, organization);
    }
  else
    {
      /* In 1.0 (Golang), organization defaulted to "Unspecified".
           Keep it the same here to avoid breaking existing usages. */
      options->org = talloc_strdup (options, "Unspecified");
    }
  CHECK_MEM (options->org);

  if (organizational_unit)
    {
      options->org_unit = talloc_strdup (options, organizational_unit);
    }
  else
    {
      options->org_unit = talloc_strdup (options, "");
    }
  CHECK_MEM (options->org_unit);

  if (email)
    {
      options->email = talloc_strdup (options, email);
    }
  else
    {
      options->email = talloc_strdup (options, "");
    }
  CHECK_MEM (options->email);

  if (hostname)
    {
      options->hostname = talloc_strdup (options, hostname);
    }
  else
    {
      /* Get hostname from the system */
      hostname = talloc_zero_array (options, char, HOST_NAME_MAX + 1);
      CHECK_MEM (hostname);

      sret = gethostname (hostname, HOST_NAME_MAX);
      if (sret != 0)
        {
          ret = errno;
          goto done;
        }

      options->hostname = hostname;
    }
  CHECK_MEM (options->hostname);

  if (strnlen (options->hostname, MAXHOSTNAMELEN + 1) > MAXHOSTNAMELEN)
    {
      fprintf (
        stderr, "Hostnames may not exceed %d characters\n", MAXHOSTNAMELEN);
      ret = EINVAL;
      goto done;
    }

  /* Use a realloc loop to copy the names from popt into the
       options struct. It's not the most efficient approach, but
       it's only done one time, so there is no sense in optimizing
       it. */
  if (alternative_names)
    {
      i = 0;
      while (alternative_names[i] != NULL)
        {
          options->subject_alt_names = talloc_realloc (
            options, options->subject_alt_names, char *, i + 2);
          CHECK_MEM (options->subject_alt_names);

          options->subject_alt_names[i] =
            talloc_strdup (options->subject_alt_names, alternative_names[i]);
          CHECK_MEM (options->subject_alt_names[i]);

          /* Add a NULL terminator to the end */
          options->subject_alt_names[i + 1] = NULL;
          i++;
        }
    }

  if (options->key_strength != 512 && options->key_strength != 1024 &&
      options->key_strength != 2048 && options->key_strength != 4096)
    {
      fprintf (stderr,
               "Key strength must be one of {512, 1024, 2048, 4096}.\n");
      ret = EINVAL;
      goto done;
    }

  if (!hash_alg)
    {
      /* Default to SHA256 */
      options->hash_fn = EVP_sha256 ();
    }
  else
    {
      /* TODO: restrict this to approved hashes.
         * For now, we'll only list SHA[256|384|512] in the help */
      options->hash_fn = EVP_get_digestbyname (hash_alg);
    }
  if (!options->hash_fn)
    {
      fprintf (stderr, "Unsupported hashing algorithm.");
      ret = EINVAL;
      goto done;
    }

  /* On verbose logging, display all of the selected options. */
  if (options->verbosity >= SSCG_VERBOSE)
    print_options (options);

  /* Get the paths of the output files */
  ret = _sscg_normalize_path (options, ca_file, "./ca.crt", &options->ca_file);
  CHECK_OK (ret);

  ret =
    _sscg_normalize_path (options, ca_key_file, NULL, &options->ca_key_file);
  CHECK_OK (ret);
  if (options->verbosity >= SSCG_DEBUG)
    {
      fprintf (stdout,
               "DEBUG: CA Key file path: %s\n",
               options->ca_key_file ? options->ca_key_file : "(N/A)");
    }

  ret = _sscg_normalize_path (
    options, cert_file, "./service.pem", &options->cert_file);
  CHECK_OK (ret);

  ret = _sscg_normalize_path (
    options, cert_key_file, "./service-key.pem", &options->cert_key_file);
  CHECK_OK (ret);

  poptFreeContext (pc);

  /* Validate the file paths */

  /* Only one key can exist in a single file */
  if (options->ca_key_file &&
      strcmp (options->ca_key_file, options->cert_key_file) == 0)
    {
      fprintf (stderr,
               "Certificate key and CA key may not be in the same file.\n");
      ret = EINVAL;
      goto done;
    }

  /* The CA key must not be in the same file as the service cert */
  if (options->ca_key_file &&
      strcmp (options->ca_key_file, options->cert_file) == 0)
    {
      fprintf (
        stderr,
        "CA key and service certificate may not be in the same file.\n");
      ret = EINVAL;
      goto done;
    }

  /* Generate the private CA for the certificate */
  ret = create_private_CA (main_ctx, options, &cacert, &cakey);
  CHECK_OK (ret);

  /* Generate the service certificate and sign it with the private CA */
  ret = create_service_cert (
    main_ctx, options, cacert, cakey, &svc_cert, &svc_key);
  CHECK_OK (ret);


  /* ==== Output the final files ==== */

  /* Set the file-creation mode */
  if (options->overwrite)
    {
      create_mode = talloc_strdup (main_ctx, "w");
    }
  else
    {
      create_mode = talloc_strdup (main_ctx, "wx");
    }
  CHECK_MEM (create_mode);

  /* Create certificate private key file */
  if (options->verbosity >= SSCG_DEFAULT)
    {
      fprintf (
        stdout, "Writing svc private key to %s \n", options->cert_key_file);
    }

  cert_key_out = BIO_new_file (options->cert_key_file, create_mode);
  CHECK_BIO (cert_key_out, options->cert_key_file);

  sret = PEM_write_bio_PrivateKey (
    cert_key_out, svc_key->evp_pkey, NULL, NULL, 0, NULL, NULL);
  CHECK_SSL (sret, PEM_write_bio_PrivateKey (svc));
  BIO_get_fp (cert_key_out, &fp);

  if (options->verbosity >= SSCG_DEBUG)
    {
      fprintf (stdout,
               "DEBUG: Setting svc key file permissions to %o\n",
               cert_key_mode);
    }
  fchmod (fileno (fp), cert_key_mode);

  BIO_free (cert_key_out);
  cert_key_out = NULL;


  /* Create service public certificate */
  if (options->verbosity >= SSCG_DEFAULT)
    {
      fprintf (stdout,
               "Writing service public certificate to %s\n",
               options->cert_file);
    }
  if (strcmp (options->cert_key_file, options->cert_file) == 0)
    {
      cert_out = BIO_new_file (options->cert_file, "a");
    }
  else
    {
      cert_out = BIO_new_file (options->cert_file, create_mode);
    }
  CHECK_BIO (cert_out, options->cert_file);

  sret = PEM_write_bio_X509 (cert_out, svc_cert->certificate);
  CHECK_SSL (sret, PEM_write_bio_X509 (svc));
  BIO_get_fp (cert_out, &fp);

  /* If this file matches the keyfile, do not set its permissions */
  if (strcmp (options->cert_file, options->cert_key_file) == 0)
    {
      if (options->verbosity >= SSCG_DEBUG)
        {
          fprintf (stdout,
                   "DEBUG: Not setting service cert file permissions: "
                   "superseded by the key\n");
        }
    }
  else
    {
      if (options->verbosity >= SSCG_DEBUG)
        {
          fprintf (stdout,
                   "DEBUG: Setting service cert file permissions to %o\n",
                   cert_mode);
        }
      fchmod (fileno (fp), cert_mode);
    }
  BIO_free (cert_out);
  cert_out = NULL;


  /* Create CA private key, if requested */
  if (options->ca_key_file)
    {
      if (options->verbosity >= SSCG_DEFAULT)
        {
          fprintf (
            stdout, "Writing CA private key to %s\n", options->ca_key_file);
        }
      if (strcmp (options->ca_file, options->ca_key_file) == 0)
        {
          ca_key_out = BIO_new_file (options->ca_key_file, "a");
        }
      else
        {
          ca_key_out = BIO_new_file (options->ca_key_file, create_mode);
        }
      CHECK_BIO (ca_key_out, options->ca_key_file);

      sret = PEM_write_bio_PrivateKey (
        ca_key_out, cakey->evp_pkey, NULL, NULL, 0, NULL, NULL);
      CHECK_SSL (sret, PEM_write_bio_PrivateKey (CA));
      BIO_get_fp (ca_key_out, &fp);
      if (options->verbosity >= SSCG_DEBUG)
        {
          fprintf (stdout,
                   "DEBUG: Setting CA key file permissions to %o\n",
                   ca_key_mode);
        }
      fchmod (fileno (fp), ca_key_mode);
      BIO_free (ca_key_out);
      ca_key_out = NULL;
    }


  /* Create CA public certificate */
  if (options->verbosity >= SSCG_DEFAULT)
    {
      fprintf (
        stdout, "Writing CA public certificate to %s\n", options->ca_file);
    }
  if (strcmp (options->ca_file, options->cert_file) == 0)
    {
      ca_out = BIO_new_file (options->ca_file, "a");
    }
  else
    {
      ca_out = BIO_new_file (options->ca_file, create_mode);
    }
  CHECK_BIO (ca_out, options->ca_file);

  sret = PEM_write_bio_X509 (ca_out, cacert->certificate);
  CHECK_SSL (sret, PEM_write_bio_X509 (CA));
  BIO_get_fp (ca_out, &fp);
  /* If this file matches the keyfile, do not set its permissions */
  if (options->ca_key_file &&
      strcmp (options->ca_file, options->ca_key_file) == 0)
    {
      if (options->verbosity >= SSCG_DEBUG)
        {
          fprintf (
            stdout,
            "DEBUG: Not setting CA file permissions: superseded by a key\n");
        }
    }
  else
    {
      if (options->verbosity >= SSCG_DEBUG)
        {
          fprintf (
            stdout, "DEBUG: Setting CA file permissions to %o\n", ca_mode);
        }
      fchmod (fileno (fp), ca_mode);
    }
  BIO_free (cert_out);
  cert_out = NULL;


  ret = EOK;
done:
  BIO_free (cert_key_out);
  BIO_free (cert_out);
  BIO_free (ca_key_out);
  BIO_free (ca_out);

  talloc_zfree (main_ctx);
  if (ret != EOK)
    {
      fprintf (stderr, "%s\n", strerror (ret));
    }
  return ret;
}
