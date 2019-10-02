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

#define _GNU_SOURCE
#include <popt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <path_utils.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <sys/param.h>

#include "config.h"
#include "include/sscg.h"
#include "include/authority.h"
#include "include/service.h"


/* Same as OpenSSL CLI */
#define MAX_PW_LEN 1024

static int
get_security_level (void)
{
#ifdef HAVE_SSL_CTX_GET_SECURITY_LEVEL
  SSL_CTX *ssl_ctx = SSL_CTX_new (TLS_method ());
  int security_level = SSL_CTX_get_security_level (ssl_ctx);
  SSL_CTX_free (ssl_ctx);
  ssl_ctx = NULL;
  return security_level;
#else
  return 0;
#endif
}

static int
set_default_options (struct sscg_options *opts)
{
  int security_level = get_security_level ();

  opts->lifetime = 3650;

  /* Select the default key strength based on the system security level
   * See:
   * https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_get_security_level.html
   * for the specification of the minimums.
   */
  switch (security_level)
    {
    case 0:
    case 1:
    case 2:
      /* Security level 2 and below permits lower key-strengths, but SSCG
       * will set a minimum of 2048 bits and the sha256 hash algorithm.
       */
      opts->hash_alg = talloc_strdup (opts, "sha256");
      opts->key_strength = 2048;
      break;

    case 3:
      opts->hash_alg = talloc_strdup (opts, "sha256");
      opts->key_strength = 3072;
      break;

    case 4:
      opts->hash_alg = talloc_strdup (opts, "sha384");
      opts->key_strength = 7680;
      break;

    default:
      /* Unknown security level. Default to the highest we know about */
      fprintf (stderr,
               "Unknown system security level %d. Defaulting to highest-known "
               "level.\n",
               security_level);
      /* Fall through */

    case 5:
      opts->hash_alg = talloc_strdup (opts, "sha512");
      opts->key_strength = 15360;
      break;
    }

  opts->minimum_key_strength = opts->key_strength;

  opts->cipher_alg = talloc_strdup (opts, "aes-256-cbc");

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


/* This function takes a copy of a string into a talloc hierarchy and memsets
 * the original string to zeroes to avoid leaking it when that memory is freed.
 */
static char *
sscg_secure_string_steal (TALLOC_CTX *mem_ctx, char *src)
{
  char *dest = talloc_strdup (mem_ctx, src);

  memset (src, 0, strlen (src));

  return dest;
}


static int
sscg_options_destructor (TALLOC_CTX *opts)
{
  struct sscg_options *options =
    talloc_get_type_abort (opts, struct sscg_options);

  /* Zero out the memory before freeing it so we don't leak passwords */
  if (options->ca_key_pass)
    {
      memset (options->ca_key_pass, 0, strlen (options->ca_key_pass));
    }

  if (options->cert_key_pass)
    {
      memset (options->cert_key_pass, 0, strlen (options->cert_key_pass));
    }

  return 0;
}


static char *
sscg_read_pw_file (TALLOC_CTX *mem_ctx, char *path)
{
  int i;
  BIO *pwdbio = NULL;
  char tpass[MAX_PW_LEN];
  char *tmp = NULL;
  char *password = NULL;

  pwdbio = BIO_new_file (path, "r");
  if (pwdbio == NULL)
    {
      fprintf (stderr, "Can't open file %s\n", path);
      return NULL;
    }

  i = BIO_gets (pwdbio, tpass, MAX_PW_LEN);
  BIO_free_all (pwdbio);
  pwdbio = NULL;

  if (i <= 0)
    {
      fprintf (stderr, "Error reading password from BIO\n");
      return NULL;
    }

  tmp = strchr (tpass, '\n');
  if (tmp != NULL)
    *tmp = 0;

  password = talloc_strdup (mem_ctx, tpass);

  memset (tpass, 0, MAX_PW_LEN);

  return password;
}


int
main (int argc, const char **argv)
{
  int ret, sret, opt;
  size_t i;
  poptContext pc;
  struct sscg_options *options;
  char *minimum_key_strength_help = NULL;

  char *country = NULL;
  char *state = NULL;
  char *locality = NULL;
  char *organization = NULL;
  char *organizational_unit = NULL;
  char *email = NULL;
  char *hostname = NULL;
  char *packagename;
  char **alternative_names = NULL;

  char *ca_file = NULL;
  char *ca_key_file = NULL;
  char *cert_file = NULL;
  char *cert_key_file = NULL;

  int ca_mode = 0644;
  int ca_key_mode = 0600;
  char *ca_key_password = NULL;
  char *ca_key_passfile = NULL;

  int crl_mode = 0644;
  char *crl_file = NULL;

  int cert_mode = 0644;
  int cert_key_mode = 0600;
  char *cert_key_password = NULL;
  char *cert_key_passfile = NULL;

  char *create_mode = NULL;

  struct sscg_x509_cert *cacert;
  struct sscg_evp_pkey *cakey;
  struct sscg_x509_cert *svc_cert;
  struct sscg_evp_pkey *svc_key;

  BIO *ca_out = NULL;
  BIO *ca_key_out = NULL;
  BIO *cert_out = NULL;
  BIO *cert_key_out = NULL;
  BIO *crl_out = NULL;

  FILE *fp;

  /* Always use umask 0577 for generating certificates and keys
       This means that it's opened as write-only by the effective
       user. */
  umask (0577);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  /* In OpenSSL <1.1.0, we need to initialize the library. */
  OpenSSL_add_all_algorithms ();
#endif

  TALLOC_CTX *main_ctx = talloc_new (NULL);
  if (!main_ctx)
    {
      fprintf (stderr, "Could not allocate memory.");
      return ENOMEM;
    }

  options = talloc_zero (main_ctx, struct sscg_options);
  CHECK_MEM (options);
  talloc_set_destructor ((TALLOC_CTX *)options, sscg_options_destructor);

  ret = set_default_options (options);
  if (ret != EOK)
    goto done;

  minimum_key_strength_help =
    talloc_asprintf (main_ctx, "%d or larger", options->minimum_key_strength);

  options->verbosity = SSCG_DEFAULT;
  // clang-format off
  struct poptOption long_options[] = {
    POPT_AUTOHELP

    {
      "quiet",
      'q',
      POPT_ARG_VAL,
      &options->verbosity,
      SSCG_QUIET,
       ("Display no output unless there is an error."),
      NULL
    },

    {
      "verbose",
      'v',
      POPT_ARG_VAL,
      &options->verbosity,
      SSCG_VERBOSE,
      _ ("Display progress messages."),
      NULL
    },

    {
      "debug",
      'd',
      POPT_ARG_VAL,
      &options->verbosity,
      SSCG_DEBUG,
      _ ("Enable logging of debug messages. Implies verbose. Warning! "
         "This will print private key information to the screen!"),
      NULL
    },

    {
      "version",
      'V',
      POPT_ARG_NONE,
      &options->print_version,
      0,
      _ ("Display the version number and exit."),
      NULL
    },

    {
      "force",
      'f',
      POPT_ARG_NONE,
      &options->overwrite,
      0,
      _ ("Overwrite any pre-existing files in the requested locations"),
      NULL
    },

    {
      "lifetime",
      '\0',
      POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->lifetime,
      0,
      _ ("Certificate lifetime (days)."),
      _ ("1-3650")
    },

    {
      "country",
      '\0',
      POPT_ARG_STRING,
      &country,
      0,
      _ ("Certificate DN: Country (C). (default: \"US\")"),
      _ ("US, CZ, etc.")
    },

    {
      "state",
      '\0',
      POPT_ARG_STRING,
      &state,
      0,
      _ ("Certificate DN: State or Province (ST)."),
      _ ("Massachusetts, British Columbia, etc.")
    },

    {
      "locality",
      '\0',
      POPT_ARG_STRING,
      &locality,
      0,
      _ ("Certificate DN: Locality (L)."),
      _ ("Westford, Paris, etc.")
    },

    {
      "organization",
      '\0',
      POPT_ARG_STRING,
      &organization,
      0,
      _ ("Certificate DN: Organization (O). (default: \"Unspecified\")"),
      _ ("My Company")
    },

    {
      "organizational-unit",
      '\0',
      POPT_ARG_STRING,
      &organizational_unit,
      0,
      _ ("Certificate DN: Organizational Unit (OU)."),
      _ ("Engineering, etc.")
    },

    {
      "email",
      '\0',
      POPT_ARG_STRING,
      &email,
      0,
      _ ("Certificate DN: Email Address (Email)."),
      _ ("myname@example.com")
    },

    {
      "hostname",
      '\0',
      POPT_ARG_STRING,
      &hostname,
      0,
      _ ("The valid hostname of the certificate. Must be an FQDN. (default: "
         "current system FQDN)"),
      _ ("server.example.com")
    },

    {
      "subject-alt-name",
      '\0',
      POPT_ARG_ARGV,
      &alternative_names,
      0,
      _ ("Optional additional valid hostnames for the certificate. "
         "In addition to hostnames, this option also accepts explicit values "
         "supported by RFC 5280 such as "
         "IP:xxx.xxx.xxx.xxx/yyy.yyy.yyy.yyy "
         "May be specified multiple times."),
      _ ("alt.example.com")
    },

    {
      "package",
      '\0',
      POPT_ARG_STRING,
      &packagename,
      0,
      _ ("Unused. Retained for compatibility with earlier versions of sscg."),
      NULL,
    },

    {
      "key-strength",
      '\0',
      POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->key_strength,
      0,
      _ ("Strength of the certificate private keys in bits."),
      minimum_key_strength_help },
    {
      "hash-alg",
      '\0',
      POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->hash_alg,
      0,
      _ ("Hashing algorithm to use for signing."),
      _ ("{sha256,sha384,sha512}"),
    },

    {
      "cipher-alg",
      '\0',
      POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->cipher_alg,
      0,
      _ ("Cipher to use for encrypting key files."),
      _ ("{des-ede3-cbc,aes-256-cbc}"),
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
      "ca-key-password",
      '\0',
      POPT_ARG_STRING,
      &ca_key_password,
      0,
      _ ("Provide a password for the CA key file. Note that this will be "
         "visible in the process table for all users, so it should be used "
         "for testing purposes only. Use --ca-keypassfile or "
         "--ca-key-password-prompt for secure password entry."),
      NULL
    },

    {
      "ca-key-passfile",
      '\0',
      POPT_ARG_STRING,
      &ca_key_passfile,
      0,
      _ ("A file containing the password to encrypt the CA key file."),
      NULL
    },

    {
      "ca-key-password-prompt",
      'C',
      POPT_ARG_NONE,
      &options->ca_key_pass_prompt,
      0,
      _ ("Prompt to enter a password for the CA key file."),
      NULL
    },

    {
      "crl-file",
      '\0',
      POPT_ARG_STRING,
      &crl_file,
      0,
      _ ("Path where an (empty) Certificate Revocation List file will be "
         "created, for applications that expect such a file to exist. If "
         "unspecified, no such file will be created."),
      NULL
    },

    {
      "crl-mode",
      '\0',
      POPT_ARG_INT,
      &crl_mode,
      0,
      _ ("File mode of the created Certificate Revocation List. "
         "(default: 0644)"),
      _ ("0644"),
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

    {
      "cert-key-password",
      'p',
      POPT_ARG_STRING,
      &cert_key_password,
      0,
      _ ("Provide a password for the service key file. Note that this will be "
         "visible in the process table for all users, so this flag should be "
         "used for testing purposes only. Use --cert-keypassfile or "
         "--cert-key-password-prompt for secure password entry."),
      NULL
    },

    {
      "cert-key-passfile",
      '\0',
      POPT_ARG_STRING,
      &cert_key_passfile,
      0,
      _ ("A file containing the password to encrypt the service key file."),
      NULL
    },

    {
      "cert-key-password-prompt",
      'P',
      POPT_ARG_NONE,
      &options->cert_key_pass_prompt,
      0,
      _ ("Prompt to enter a password for the service key file."),
      NULL
    },

    POPT_TABLEEND
  };
  // clang-format on

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

  /* Password handling */
  if (ca_key_password)
    {
      options->ca_key_pass =
        sscg_secure_string_steal (options, ca_key_password);
    }
  else if (ca_key_passfile)
    {
      options->ca_key_pass = sscg_read_pw_file (options, ca_key_passfile);
      if (!options->ca_key_pass)
        {
          fprintf (
            stderr, "Failed to read passphrase from %s", ca_key_passfile);
          goto done;
        }
    }

  if (cert_key_password)
    {
      options->cert_key_pass =
        sscg_secure_string_steal (options, cert_key_password);
    }
  else if (cert_key_passfile)
    {
      options->cert_key_pass = sscg_read_pw_file (options, cert_key_passfile);
      if (!options->cert_key_pass)
        {
          fprintf (
            stderr, "Failed to read passphrase from %s", cert_key_passfile);
          goto done;
        }
    }


  if (options->key_strength < options->minimum_key_strength)
    {
      fprintf (stderr,
               "Key strength must be at least %d bits.\n",
               options->minimum_key_strength);
      ret = EINVAL;
      goto done;
    }

  /* Make sure we have a valid cipher */
  options->cipher = EVP_get_cipherbyname (options->cipher_alg);
  if (!options->cipher)
    {
      fprintf (stderr, "Invalid cipher specified: %s\n", options->cipher_alg);
      ret = EINVAL;
      goto done;
    }

  /* TODO: restrict this to approved hashes.
   * For now, we'll only list SHA[256|384|512] in the help */
  options->hash_fn = EVP_get_digestbyname (options->hash_alg);

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

  ret = _sscg_normalize_path (options, crl_file, NULL, &options->crl_file);
  CHECK_OK (ret);

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

  /* This function has a default mechanism for prompting for the
   * password if it is passed a cipher and gets a NULL password.
   *
   * Only pass the cipher if we have a password or were instructed
   * to prompt for one.
   */
  sret = PEM_write_bio_PrivateKey (
    cert_key_out,
    svc_key->evp_pkey,
    options->cert_key_pass_prompt || options->cert_key_pass ? options->cipher :
                                                              NULL,
    (unsigned char *)options->cert_key_pass,
    options->cert_key_pass ? strlen (options->cert_key_pass) : 0,
    NULL,
    NULL);
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

      /* This function has a default mechanism for prompting for the
       * password if it is passed a cipher and gets a NULL password.
       *
       * Only pass the cipher if we have a password or were instructed
       * to prompt for one.
       */
      sret = PEM_write_bio_PrivateKey (
        ca_key_out,
        cakey->evp_pkey,
        options->ca_key_pass_prompt || options->ca_key_pass ? options->cipher :
                                                              NULL,
        (unsigned char *)options->ca_key_pass,
        options->ca_key_pass ? strlen (options->ca_key_pass) : 0,
        NULL,
        NULL);
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

  /* Create CRL file */
  if (options->crl_file)
    {
      if (options->verbosity >= SSCG_DEFAULT)
        {
          fprintf (stdout, "Writing empty CRL to %s\n", options->crl_file);
        }
      crl_out = BIO_new_file (options->crl_file, create_mode);
      CHECK_BIO (crl_out, options->crl_file);

      BIO_get_fp (crl_out, &fp);
      if (options->verbosity >= SSCG_DEBUG)
        {
          fprintf (
            stdout, "DEBUG: Setting CRL file permissions to %o\n", crl_mode);
        }
      fchmod (fileno (fp), crl_mode);
      BIO_free (crl_out);
      crl_out = NULL;
    }


  ret = EOK;
done:
  BIO_free (cert_key_out);
  BIO_free (cert_out);
  BIO_free (ca_key_out);
  BIO_free (ca_out);
  BIO_free (crl_out);

  talloc_zfree (main_ctx);
  if (ret != EOK)
    {
      fprintf (stderr, "%s\n", strerror (ret));
    }
  return ret;
}
