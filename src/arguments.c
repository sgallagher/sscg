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

    Copyright 2021-2023 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <popt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>


#include "include/sscg.h"
#include "include/dhparams.h"

#include "config.h"
#ifdef HAVE_GETTEXT
#include <libintl.h>
#endif

#define _GNU_SOURCE


void
print_options (struct sscg_options *opts);


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

  opts->ca_mode = SSCG_CERT_DEFAULT_MODE;
  opts->ca_key_mode = SSCG_KEY_DEFAULT_MODE;

  opts->cert_mode = SSCG_CERT_DEFAULT_MODE;
  opts->cert_key_mode = SSCG_KEY_DEFAULT_MODE;

  opts->client_mode = SSCG_CERT_DEFAULT_MODE;
  opts->client_key_mode = SSCG_KEY_DEFAULT_MODE;

  opts->crl_mode = SSCG_CERT_DEFAULT_MODE;

  opts->dhparams_mode = SSCG_CERT_DEFAULT_MODE;

  opts->lifetime = 398;

  opts->dhparams_group = talloc_strdup (opts, "ffdhe4096");
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
      fprintf (
        stderr,
        _ ("Unknown system security level %d. Defaulting to highest-known "
           "level.\n"),
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

int
sscg_handle_arguments (TALLOC_CTX *mem_ctx,
                       int argc,
                       const char **argv,
                       struct sscg_options **config)
{
  int ret, sret, opt;
  poptContext pc;
  char *minimum_key_strength_help = NULL;
  char *named_groups_help = NULL;

  char *country = NULL;
  char *state = NULL;
  char *locality = NULL;
  char *organization = NULL;
  char *organizational_unit = NULL;
  char *email = NULL;
  char *hostname = NULL;
  char *packagename;
  char **alternative_names = NULL;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  struct sscg_options *options = talloc_zero (tmp_ctx, struct sscg_options);
  CHECK_MEM (options);

  options->streams =
    talloc_zero_array (options, struct sscg_stream *, SSCG_NUM_FILE_TYPES);

  ret = set_default_options (options);
  if (ret != EOK)
    goto done;

  minimum_key_strength_help = talloc_asprintf (
    tmp_ctx, _ ("%d or larger"), options->minimum_key_strength);

  named_groups_help =
    talloc_asprintf (tmp_ctx,
                     _ ("Output well-known DH parameters. The available named "
                        "groups are: %s. (Default: \"ffdhe4096\")"),
                     valid_dh_group_names (tmp_ctx));

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
      _ ("Display no output unless there is an error."),
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
      &options->ca_file,
      0,
      _ ("Path where the public CA certificate will be stored. (default: "
         "\"./ca.crt\")"),
      NULL,
    },

    {
      "ca-mode",
      '\0',
      POPT_ARG_INT,
      &options->ca_mode,
      0,
      _ ("File mode of the created CA certificate."),
      SSCG_CERT_DEFAULT_MODE_HELP,
    },

    {
      "ca-key-file",
      '\0',
      POPT_ARG_STRING,
      &options->ca_key_file,
      0,
      _ ("Path where the CA's private key will be stored. If unspecified, "
         "the key will be destroyed rather than written to the disk."),
      NULL,
    },

    {
      "ca-key-mode",
      '\0',
      POPT_ARG_INT,
      &options->ca_key_mode,
      0,
      _ ("File mode of the created CA key."),
      SSCG_KEY_DEFAULT_MODE_HELP,
    },

    {
      "ca-key-password",
      '\0',
      POPT_ARG_STRING,
      &options->ca_key_password,
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
      &options->ca_key_passfile,
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
      &options->crl_file,
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
      &options->crl_mode,
      0,
      _ ("File mode of the created Certificate Revocation List."),
      SSCG_CERT_DEFAULT_MODE_HELP,
    },

    {
      "cert-file",
      '\0',
      POPT_ARG_STRING,
      &options->cert_file,
      0,
      _ ("Path where the public service certificate will be stored. "
         "(default \"./service.pem\")"),
      NULL,
    },

    {
      "cert-mode",
      '\0',
      POPT_ARG_INT,
      &options->cert_mode,
      0,
      _ ("File mode of the created certificate."),
      SSCG_CERT_DEFAULT_MODE_HELP,
    },

    {
      "cert-key-file",
      '\0',
      POPT_ARG_STRING,
      &options->cert_key_file,
      0,
      _ ("Path where the service's private key will be stored. "
         "(default \"service-key.pem\")"),
      NULL,
    },

    {
      "cert-key-mode",
      '\0',
      POPT_ARG_INT,
      &options->cert_key_mode,
      0,
      _ ("File mode of the created certificate key."),
      SSCG_KEY_DEFAULT_MODE_HELP,
    },

    {
      "cert-key-password",
      'p',
      POPT_ARG_STRING,
      &options->cert_key_password,
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
      &options->cert_key_passfile,
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
      &options->client_file,
      0,
      _ ("Path where a client authentication certificate will be stored."),
      NULL
    },
    {
      "client-mode",
      '\0',
      POPT_ARG_INT,
      &options->client_mode,
      0,
      _ ("File mode of the created certificate."),
      SSCG_CERT_DEFAULT_MODE_HELP,
    },

    {
      "client-key-file",
      '\0',
      POPT_ARG_STRING,
      &options->client_key_file,
      0,
      _ ("Path where the client's private key will be stored. "
         "(default is the client-file)"),
      NULL,
    },

    {
      "client-key-mode",
      '\0',
      POPT_ARG_INT,
      &options->client_key_mode,
      0,
      _ ("File mode of the created certificate key."),
      SSCG_KEY_DEFAULT_MODE_HELP,
    },

    {
      "client-key-password",
      '\0',
      POPT_ARG_STRING,
      &options->client_key_password,
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
      &options->client_key_passfile,
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
      &options->dhparams_file,
      0,
      _("A file to contain a set of Diffie-Hellman parameters. "
        "(Default: \"./dhparams.pem\")"),
      NULL
    },

    {
      "no-dhparams-file",
      '\0',
      POPT_ARG_NONE,
      &options->skip_dhparams,
      0,
      _ ("Do not create the dhparams file"),
      NULL
    },

    {
      "dhparams-named-group",
      '\0',
      POPT_ARG_STRING,
      &options->dhparams_group,
      0,
      _(named_groups_help),
      NULL
    },

    {
      "dhparams-prime-len",
      '\0',
      POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
      &options->dhparams_prime_len,
      0,
      _ ("The length of the prime number to generate for dhparams, in bits. "
         "If set to non-zero, the parameters will be generated rather than "
         "using a well-known group."),
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
                   _ ("\nInvalid option %s: %s\n\n"),
                   poptBadOption (pc, 0),
                   poptStrerror (opt));
          poptPrintUsage (pc, stderr, 0);
          ret = EINVAL;
          goto done;
        }
    }

  if (options->print_version)
    {
      /* Print the version number and exit */
      printf ("%s\n", PACKAGE_VERSION);
      exit (0);
    }

  verbosity = options->verbosity;

  /* Process the Subject information */

  if (country)
    {
      if (strlen (country) != 2)
        {
          fprintf (stderr, _ ("Country codes must be exactly two letters.\n"));
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

  if (strnlen (options->hostname, MAX_FQDN_LEN + 1) > MAX_FQDN_LEN)
    {
      fprintf (
        stderr, _ ("FQDNs may not exceed %d characters\n"), MAX_FQDN_LEN);
      ret = EINVAL;
      goto done;
    }

  if ((strchr (options->hostname, '.') - options->hostname) > MAX_HOST_LEN + 4)
    {
      fprintf (stderr,
               _ ("Hostnames may not exceed %d characters in Subject "
                  "Alternative Names\n"),
               MAX_HOST_LEN);
      ret = EINVAL;
      goto done;
    }

  /* Use a realloc loop to copy the names from popt into the
       options struct. It's not the most efficient approach, but
       it's only done one time, so there is no sense in optimizing
       it. */
  size_t i = 0;
  if (alternative_names)
    {
      while (alternative_names[i] != NULL)
        {
          options->subject_alt_names = talloc_realloc (
            options, options->subject_alt_names, char *, i + 1);
          CHECK_MEM (options->subject_alt_names);

          options->subject_alt_names[i] =
            talloc_strdup (options->subject_alt_names, alternative_names[i]);
          CHECK_MEM (options->subject_alt_names[i]);
          i++;
        }
    }

  /*
    The hostname must always be listed in SubjectAlternativeNames as well.
    Note that the realloc also adds an extra entry for the NULL terminator
  */
  options->subject_alt_names =
    talloc_realloc (options, options->subject_alt_names, char *, i + 2);
  CHECK_MEM (options->subject_alt_names);
  options->subject_alt_names[i] =
    talloc_strdup (options->subject_alt_names, options->hostname);
  CHECK_MEM (options->subject_alt_names[i]);
  /* Add a NULL terminator to the end */
  options->subject_alt_names[i + 1] = NULL;

  if (options->key_strength < options->minimum_key_strength)
    {
      fprintf (stderr,
               _ ("Key strength must be at least %d bits.\n"),
               options->minimum_key_strength);
      ret = EINVAL;
      goto done;
    }

  /* Make sure we have a valid cipher */
  options->cipher = EVP_get_cipherbyname (options->cipher_alg);
  if (!options->cipher)
    {
      fprintf (
        stderr, _ ("Invalid cipher specified: %s\n"), options->cipher_alg);
      ret = EINVAL;
      goto done;
    }

  /* TODO: restrict this to approved hashes.
   * For now, we'll only list SHA[256|384|512] in the help */
  options->hash_fn = EVP_get_digestbyname (options->hash_alg);

  if (!is_valid_named_group (options->dhparams_group))
    {
      fprintf (stderr, _ ("Unknown Diffie Hellman finite field group.\n"));
      fprintf (
        stderr, _ ("Valid groups are: %s.\n"), valid_dh_group_names (tmp_ctx));
      ret = EINVAL;
      goto done;
    }

  if (!options->hash_fn)
    {
      fprintf (stderr, _ ("Unsupported hashing algorithm."));
      ret = EINVAL;
      goto done;
    }

  /* On verbose logging, display all of the selected options. */
  if (options->verbosity >= SSCG_VERBOSE)
    print_options (options);

  poptFreeContext (pc);

  *config = talloc_steal (mem_ctx, options);

  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}


void
print_options (struct sscg_options *opts)
{
  size_t i = 0;
  fprintf (stdout, _ ("==== Options ====\n"));
  fprintf (stdout, _ ("Certificate lifetime: %d\n"), opts->lifetime);
  fprintf (stdout, _ ("Country: \"%s\"\n"), opts->country);
  fprintf (stdout, _ ("State or Principality: \"%s\"\n"), opts->state);
  fprintf (stdout, _ ("Locality: \"%s\"\n"), opts->locality);
  fprintf (stdout, _ ("Organization: \"%s\"\n"), opts->org);
  fprintf (stdout, _ ("Organizational Unit: \"%s\"\n"), opts->org_unit);
  fprintf (stdout, _ ("Email Address: \"%s\"\n"), opts->email);
  fprintf (stdout, _ ("Hostname: \"%s\"\n"), opts->hostname);
  if (opts->subject_alt_names)
    {
      for (i = 0; opts->subject_alt_names[i]; i++)
        {
          fprintf (stdout,
                   _ ("Subject Alternative Name: \"%s\"\n"),
                   opts->subject_alt_names[i]);
        }
    }
  fprintf (stdout, _ ("=================\n"));
}
