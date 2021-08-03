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

/* This is a master header file that should be included by all
   sscg source files. */


#ifndef _SSCG_H
#define _SSCG_H

#include <errno.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ui.h>
#include <stdbool.h>
#include <talloc.h>
#include <stdint.h>


/* TODO: implement internationalization */

#ifndef _
#ifdef HAVE_GETTEXT
#define _(STRING) gettext (STRING)
#else
#define _(STRING) STRING
#endif /* HAVE_GETTEXT */
#endif /* _ */

#ifndef EOK
#define EOK 0
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t) (ptr)))
#endif

#ifndef talloc_zfree
#define talloc_zfree(ptr)                                                     \
  do                                                                          \
    {                                                                         \
      talloc_free (discard_const (ptr));                                      \
      ptr = NULL;                                                             \
    }                                                                         \
  while (0)
#endif

#define CHECK_MEM(ptr)                                                        \
  do                                                                          \
    {                                                                         \
      if (!ptr)                                                               \
        {                                                                     \
          ret = ENOMEM;                                                       \
          goto done;                                                          \
        }                                                                     \
    }                                                                         \
  while (0)

#define CHECK_OK(_ret)                                                        \
  do                                                                          \
    {                                                                         \
      if (_ret != EOK)                                                        \
        {                                                                     \
          goto done;                                                          \
        }                                                                     \
    }                                                                         \
  while (0)

/* The function changed in 1.1, but the library and reason names did not */
#ifndef UI_F_UI_SET_RESULT_EX
#define UI_F_UI_SET_RESULT_EX UI_F_UI_SET_RESULT
#endif

#define CHECK_SSL(_sslret, _fn)                                               \
  do                                                                          \
    {                                                                         \
      if (_sslret != 1)                                                       \
        {                                                                     \
          /* Get information about error from OpenSSL */                      \
          unsigned long _ssl_error = ERR_get_error ();                        \
          if ((ERR_GET_LIB (_ssl_error) == ERR_LIB_UI) &&                     \
              (ERR_GET_FUNC (_ssl_error) == UI_F_UI_SET_RESULT_EX) &&         \
              ((ERR_GET_REASON (_ssl_error) == UI_R_RESULT_TOO_LARGE) ||      \
               (ERR_GET_REASON (_ssl_error) == UI_R_RESULT_TOO_SMALL)))       \
            {                                                                 \
              fprintf (                                                       \
                stderr,                                                       \
                "Passphrases must be between %d and %d characters. \n",       \
                SSCG_MIN_KEY_PASS_LEN,                                        \
                SSCG_MAX_KEY_PASS_LEN);                                       \
              ret = EINVAL;                                                   \
              goto done;                                                      \
            }                                                                 \
          fprintf (stderr,                                                    \
                   "Error occurred in " #_fn ": [%s].\n",                     \
                   ERR_error_string (_ssl_error, NULL));                      \
          ret = EIO;                                                          \
          goto done;                                                          \
        }                                                                     \
    }                                                                         \
  while (0)

#define CHECK_BIO(ptr, file)                                                  \
  do                                                                          \
    {                                                                         \
      if (!ptr)                                                               \
        {                                                                     \
          ret = errno;                                                        \
          fprintf (stderr,                                                    \
                   "Could not write to %s. Check directory permissions.\n",   \
                   file);                                                     \
          goto done;                                                          \
        }                                                                     \
    }                                                                         \
  while (0)


#define SSCG_CERT_DEFAULT_MODE 0644
#define SSCG_CERT_DEFAULT_MODE_HELP _ ("0644")
#define SSCG_KEY_DEFAULT_MODE 0600
#define SSCG_KEY_DEFAULT_MODE_HELP _ ("0600")


enum sscg_verbosity
{
  SSCG_QUIET = -1,
  SSCG_DEFAULT,
  SSCG_VERBOSE,
  SSCG_DEBUG
};

extern int verbosity;

const char *sscg_get_verbosity_name (enum sscg_verbosity);

#define SSCG_LOG(_level, _format, ...)                                        \
  do                                                                          \
    {                                                                         \
      if (verbosity >= _level)                                                \
        {                                                                     \
          printf ("%s", sscg_get_verbosity_name (_level));                    \
          printf (_format, ##__VA_ARGS__);                                    \
        }                                                                     \
    }                                                                         \
  while (0)

#define SSCG_ERROR(_format, ...)                                              \
  do                                                                          \
    {                                                                         \
      if (verbosity > SSCG_QUIET)                                             \
        {                                                                     \
          fprintf (stderr, "ERROR: ");                                        \
          fprintf (stderr, _format, ##__VA_ARGS__);                           \
        }                                                                     \
    }                                                                         \
  while (0)


enum sscg_file_type
{
  SSCG_FILE_TYPE_UNKNOWN = -1,
  SSCG_FILE_TYPE_CA,
  SSCG_FILE_TYPE_CA_KEY,
  SSCG_FILE_TYPE_SVC,
  SSCG_FILE_TYPE_SVC_KEY,
  SSCG_FILE_TYPE_CLIENT,
  SSCG_FILE_TYPE_CLIENT_KEY,
  SSCG_FILE_TYPE_CRL,
  SSCG_FILE_TYPE_DHPARAMS,

  SSCG_NUM_FILE_TYPES
};

#define SSCG_FILE_TYPE_KEYS                                                   \
  ((1 << SSCG_FILE_TYPE_CA_KEY) | (1 << SSCG_FILE_TYPE_SVC_KEY) |             \
   (1 << SSCG_FILE_TYPE_CLIENT_KEY))

#define SSCG_FILE_TYPE_SVC_TYPES                                              \
  ((1 << SSCG_FILE_TYPE_SVC) | (1 << SSCG_FILE_TYPE_SVC_KEY))

#define SSCG_FILE_TYPE_CLIENT_TYPES                                           \
  ((1 << SSCG_FILE_TYPE_CLIENT) | (1 << SSCG_FILE_TYPE_CLIENT_KEY))

#define SSCG_FILE_TYPE_CA_TYPES                                               \
  ((1 << SSCG_FILE_TYPE_CA) | (1 << SSCG_FILE_TYPE_CA_KEY))

const char *
sscg_get_file_type_name (enum sscg_file_type _type);

#define GET_BIO(_type) sscg_io_utils_get_bio_by_type (options->streams, _type)

#define GET_PATH(_type)                                                       \
  sscg_io_utils_get_path_by_type (options->streams, _type)

#define ANNOUNCE_WRITE(_type)                                                 \
  SSCG_LOG (SSCG_DEFAULT,                                                     \
            "Wrote %s to %s\n",                                               \
            sscg_get_file_type_name (_type),                                  \
            GET_PATH (_type));

struct sscg_options
{
  /* How noisy to be when printing information */
  enum sscg_verbosity verbosity;

  /* Whether to print the version and exit */
  bool print_version;

  /* How long should certificates be valid (in days) */
  int lifetime;

  /* Subject information */
  const char *country;
  const char *state;
  const char *locality;
  const char *org;
  const char *org_unit;
  const char *email;
  const char *hostname;
  char **subject_alt_names;

  /* Encryption requirements */
  int key_strength;
  int minimum_key_strength;
  char *hash_alg;
  char *cipher_alg;
  const EVP_CIPHER *cipher;
  const EVP_MD *hash_fn;

  int ca_key_pass_prompt;
  int cert_key_pass_prompt;
  int client_key_pass_prompt;

  /* Output Files */
  struct sscg_stream **streams;

  char *ca_file;
  char *ca_key_file;
  int ca_mode;
  int ca_key_mode;
  char *ca_key_password;
  char *ca_key_passfile;

  char *cert_file;
  char *cert_key_file;
  int cert_mode;
  int cert_key_mode;
  char *cert_key_password;
  char *cert_key_passfile;

  char *client_file;
  char *client_key_file;
  int client_mode;
  int client_key_mode;
  char *client_key_password;
  char *client_key_passfile;

  char *crl_file;
  int crl_mode;

  char *dhparams_file;
  int dhparams_mode;

  /* Diffie-Hellman Parameters */
  char *dhparams_group;
  int dhparams_prime_len;
  int dhparams_generator;

  /* Overwrite the output files */
  bool overwrite;
};


enum sscg_cert_type
{
  SSCG_CERT_TYPE_UNKNOWN = -1,
  SSCG_CERT_TYPE_SERVER,
  SSCG_CERT_TYPE_CLIENT,

  SSCG_NUM_CERT_TYPES
};

#define SSCG_MIN_KEY_PASS_LEN 4
#define SSCG_MAX_KEY_PASS_LEN 1023


int
sscg_handle_arguments (TALLOC_CTX *mem_ctx,
                       int argc,
                       const char **argv,
                       struct sscg_options **config);

#endif /* _SSCG_H */
