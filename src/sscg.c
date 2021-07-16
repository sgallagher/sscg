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
#include <assert.h>
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
#include "include/cert.h"
#include "include/dhparams.h"
#include "include/io_utils.h"


int verbosity;


static int
get_security_level (void)
{
  SSL_CTX *ssl_ctx = SSL_CTX_new (TLS_method ());
  int security_level = SSL_CTX_get_security_level (ssl_ctx);
  SSL_CTX_free (ssl_ctx);
  ssl_ctx = NULL;
  return security_level;
}

static int
set_default_options (struct sscg_options *opts)
{
  int security_level = get_security_level ();

  opts->lifetime = 3650;
  opts->dhparams_prime_len = 2048;
  opts->dhparams_generator = 2;

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


const char *
sscg_get_verbosity_name (enum sscg_verbosity type)
{
  switch (type)
    {
    case SSCG_DEFAULT:
    case SSCG_VERBOSE: return "";

    case SSCG_DEBUG: return "DEBUG: ";

    default: break;
    }

  /* If it wasn't one of these, we have a bug */
  return "Unknown Verbosity (bug):";
}


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
  char *client_file = NULL;
  char *client_key_file = NULL;
  char *dhparams_file = NULL;

  int ca_mode = SSCG_CERT_DEFAULT_MODE;
  int ca_key_mode = SSCG_KEY_DEFAULT_MODE;
  char *ca_key_password = NULL;
  char *ca_key_passfile = NULL;

  int crl_mode = SSCG_CERT_DEFAULT_MODE;
  char *crl_file = NULL;

  int cert_mode = SSCG_CERT_DEFAULT_MODE;
  int cert_key_mode = SSCG_KEY_DEFAULT_MODE;
  char *cert_key_password = NULL;
  char *cert_key_passfile = NULL;

  bool build_client_cert = false;
  int client_mode = SSCG_CERT_DEFAULT_MODE;
  int client_key_mode = SSCG_KEY_DEFAULT_MODE;
  char *client_key_password = NULL;
  char *client_key_passfile = NULL;

  struct sscg_x509_cert *cacert;
  struct sscg_evp_pkey *cakey;
  struct sscg_x509_cert *svc_cert;
  struct sscg_evp_pkey *svc_key;
  struct sscg_x509_cert *client_cert = NULL;
  struct sscg_evp_pkey *client_key = NULL;

  int dhparams_mode = SSCG_CERT_DEFAULT_MODE;
  struct sscg_dhparams *dhparams = NULL;

  struct sscg_stream *stream = NULL;

  /* Always use umask 0577 for generating certificates and keys
       This means that it's opened as write-only by the effective
       user. */
  umask (0577);

  if (getenv ("SSCG_TALLOC_REPORT"))
    talloc_enable_null_tracking ();

  TALLOC_CTX *main_ctx = talloc_new (NULL);
  if (!main_ctx)
    {
      fprintf (stderr, "Could not allocate memory.");
      return ENOMEM;
    }

  options = talloc_zero (main_ctx, struct sscg_options);
  CHECK_MEM (options);

  options->streams =
    talloc_zero_array (options, struct sscg_stream *, SSCG_NUM_FILE_TYPES);

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
      _ ("File mode of the created CA certificate."),
      SSCG_CERT_DEFAULT_MODE_HELP,
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
      _ ("File mode of the created CA key."),
      SSCG_KEY_DEFAULT_MODE_HELP,
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
      _ ("File mode of the created Certificate Revocation List."),
      SSCG_CERT_DEFAULT_MODE_HELP,
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
      _ ("File mode of the created certificate."),
      SSCG_CERT_DEFAULT_MODE_HELP,
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
      _ ("File mode of the created certificate key."),
      SSCG_KEY_DEFAULT_MODE_HELP,
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

    {
      "client-file",
      '\0',
      POPT_ARG_STRING,
      &client_file,
      0,
      _ ("Path where a client authentication certificate will be stored."),
      NULL
    },
    {
      "client-mode",
      '\0',
      POPT_ARG_INT,
      &client_mode,
      0,
      _ ("File mode of the created certificate."),
      SSCG_CERT_DEFAULT_MODE_HELP,
    },

    {
      "client-key-file",
      '\0',
      POPT_ARG_STRING,
      &client_key_file,
      0,
      _ ("Path where the client's private key will be stored. "
         "(default is the client-file)"),
      NULL,
    },

    {
      "client-key-mode",
      '\0',
      POPT_ARG_INT,
      &client_key_mode,
      0,
      _ ("File mode of the created certificate key."),
      SSCG_KEY_DEFAULT_MODE_HELP,
    },

    {
      "client-key-password",
      '\0',
      POPT_ARG_STRING,
      &client_key_password,
      0,
      _ ("Provide a password for the client key file. Note that this will be "
         "visible in the process table for all users, so this flag should be "
         "used for testing purposes only. Use --client-keypassfile or "
         "--client-key-password-prompt for secure password entry."),
      NULL
    },

    {
      "client-key-passfile",
      '\0',
      POPT_ARG_STRING,
      &client_key_passfile,
      0,
      _ ("A file containing the password to encrypt the client key file."),
      NULL
    },

    {
      "client-key-password-prompt",
      '\0',
      POPT_ARG_NONE,
      &options->client_key_pass_prompt,
      0,
      _ ("Prompt to enter a password for the client key file."),
      NULL
    },

    {
      "dhparams-file",
      '\0',
      POPT_ARG_STRING,
      &dhparams_file,
      0,
      _("A file to contain a set of generated Diffie-Hellman parameters. "
        "If unspecified, no such file will be created."),
      NULL
    },

    {
      "dhparams-prime-len",
      '\0',
      POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->dhparams_prime_len,
      0,
      _ ("The length of the prime number to generate for dhparams, in bits."),
      NULL
    },

    {
      "dhparams-generator",
      '\0',
      POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->dhparams_generator,
      0,
      _ ("The generator value for dhparams."),
      _("{2,3,5}")
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

  verbosity = options->verbosity;

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

  /* Prepare the output files */
  ret = sscg_io_utils_add_output_file (options->streams,
                                       SSCG_FILE_TYPE_CA,
                                       ca_file ? ca_file : "./ca.crt",
                                       ca_mode);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_key (options->streams,
                                      SSCG_FILE_TYPE_CA_KEY,
                                      ca_key_file,
                                      ca_key_mode,
                                      options->ca_key_pass_prompt,
                                      ca_key_password,
                                      ca_key_passfile);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_file (options->streams,
                                       SSCG_FILE_TYPE_SVC,
                                       cert_file ? cert_file : "./service.pem",
                                       cert_mode);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_key (options->streams,
                                      SSCG_FILE_TYPE_SVC_KEY,
                                      cert_key_file ? cert_key_file :
                                                      "./service-key.pem",
                                      cert_key_mode,
                                      options->cert_key_pass_prompt,
                                      cert_key_password,
                                      cert_key_passfile);
  CHECK_OK (ret);


  ret = sscg_io_utils_add_output_file (
    options->streams, SSCG_FILE_TYPE_CLIENT, client_file, client_mode);
  CHECK_OK (ret);


  ret = sscg_io_utils_add_output_key (options->streams,
                                      SSCG_FILE_TYPE_CLIENT_KEY,
                                      client_key_file ? client_key_file :
                                                        client_file,
                                      client_key_mode,
                                      options->client_key_pass_prompt,
                                      client_key_password,
                                      client_key_passfile);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_file (
    options->streams, SSCG_FILE_TYPE_CRL, crl_file, crl_mode);
  CHECK_OK (ret);

  ret = sscg_io_utils_add_output_file (
    options->streams, SSCG_FILE_TYPE_DHPARAMS, dhparams_file, dhparams_mode);
  CHECK_OK (ret);

  poptFreeContext (pc);

  /* Validate and open the file paths */
  ret = sscg_io_utils_open_output_files (options->streams, options->overwrite);
  CHECK_OK (ret);


  /* Generate the private CA for the certificate */
  ret = create_private_CA (main_ctx, options, &cacert, &cakey);
  CHECK_OK (ret);

  /* Generate the service certificate and sign it with the private CA */
  ret = create_cert (main_ctx,
                     options,
                     cacert,
                     cakey,
                     SSCG_CERT_TYPE_SERVER,
                     &svc_cert,
                     &svc_key);
  CHECK_OK (ret);

  /* If requested, generate the client auth certificate and sign it with the
   * private CA.
   */
  build_client_cert = !!(GET_BIO (SSCG_FILE_TYPE_CLIENT));
  if (build_client_cert)
    {
      ret = create_cert (main_ctx,
                         options,
                         cacert,
                         cakey,
                         SSCG_CERT_TYPE_CLIENT,
                         &client_cert,
                         &client_key);
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
  if (GET_BIO (SSCG_FILE_TYPE_DHPARAMS))
    {
      /* Open the file before generating the parameters. This avoids wasting
       * the time to generate them if the destination is not writable.
       */

      ret = create_dhparams (main_ctx,
                             options->verbosity,
                             options->dhparams_prime_len,
                             options->dhparams_generator,
                             &dhparams);
      CHECK_OK (ret);

      /* Export the DH parameters to the file */
      sret = PEM_write_bio_DHparams (GET_BIO (SSCG_FILE_TYPE_DHPARAMS),
                                     dhparams->dh);
      CHECK_SSL (sret, PEM_write_bio_DHparams ());
      ANNOUNCE_WRITE (SSCG_FILE_TYPE_DHPARAMS);
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
