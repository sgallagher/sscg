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

    Copyright 2019-2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/evp.h>

#include "config.h"
#include "include/sscg.h"
#include "include/dhparams.h"

// clang-format off

#if OPENSSL_VERSION_NUMBER < 0x30000000L
const char *dh_fips_groups[] = {
  "ffdhe2048",
  "ffdhe3072",
  "ffdhe4096",
  "ffdhe6144",
  "ffdhe8192",
  NULL,
};

const char *dh_nonfips_groups[] = {
  NULL
};
#else //OPENSSL_VERSION_NUMBER
const char *dh_fips_groups[] = {
  "ffdhe2048",
  "ffdhe3072",
  "ffdhe4096",
  "ffdhe6144",
  "ffdhe8192",
  "modp_2048",
  "modp_3072",
  "modp_4096",
  "modp_6144",
  "modp_8192",
  NULL,
};

const char *dh_nonfips_groups[] = {
  "modp_1536",
  "dh_1024_160",
  "dh_2048_224",
  "dh_2048_256",
  NULL
};
#endif //OPENSSL_VERSION_NUMBER
// clang-format on


char *
valid_dh_group_names (TALLOC_CTX *mem_ctx)
{
  size_t i;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  char *names = NULL;
  bool first = true;

  i = 0;
  while (dh_fips_groups[i])
    {
      if (first)
        {
          names = talloc_strdup (tmp_ctx, dh_fips_groups[i]);
          first = false;
        }
      else
        {
          names = talloc_asprintf_append (names, ", %s", dh_fips_groups[i]);
        }

      if (!names)
        goto done;

      i++;
    }

  i = 0;
  while (dh_nonfips_groups[i])
    {
      if (first)
        {
          /* This should never be reached, since dh_fips_groups should always
           * have at least one entry, but for safety we will include it.
          */
          names = talloc_strdup (tmp_ctx, dh_nonfips_groups[i]);
          first = false;
        }
      else
        {
          names = talloc_asprintf_append (names, ", %s", dh_nonfips_groups[i]);
        }
      if (!names)
        goto done;

      i++;
    }

  talloc_steal (mem_ctx, names);

done:
  talloc_free (tmp_ctx);
  return names;
}


static int
evp_cb (EVP_PKEY_CTX *ctx);

int
create_dhparams (enum sscg_verbosity verbosity,
                 int prime_len,
                 int generator,
                 EVP_PKEY **dhparams)
{
  int ret;
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *params = NULL;


  /* First validate the input */
  assert (dhparams && !*dhparams);

  if (prime_len <= 0)
    {
      fprintf (stderr, "Prime length must be a positive integer");
      ret = ERANGE;
      goto done;
    }

  if (generator <= 0)
    {
      fprintf (stderr, "Generator must be a positive integer");
      ret = ERANGE;
      goto done;
    }


  if (verbosity >= SSCG_DEFAULT)
    {
      fprintf (stdout,
               "Generating DH parameters of length %d and generator %d. "
               "This will take a long time.\n",
               prime_len,
               generator);
    }

  /* Create the context for generating the parameters */
  if (!(pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_DH, NULL)))
    {
      ERR_print_errors_fp (stderr);
      ret = ENOMEM;
      goto done;
    }

  if (!EVP_PKEY_paramgen_init (pctx))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  /* Set up a callback to display progress */
  EVP_PKEY_CTX_set_cb (pctx, evp_cb);

  /* Set the parameter values */
  if (!EVP_PKEY_CTX_set_dh_paramgen_prime_len (pctx, prime_len))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  if (!EVP_PKEY_CTX_set_dh_paramgen_generator (pctx, generator))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  /* Generate parameters */
  if (!EVP_PKEY_paramgen (pctx, &params))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  ret = EOK;
  *dhparams = params;
  params = NULL;

done:
  EVP_PKEY_free (params);
  EVP_PKEY_CTX_free (pctx);

  return ret;
}


static int
evp_cb (EVP_PKEY_CTX *ctx)
{
  char c = '*';
  int p = EVP_PKEY_CTX_get_keygen_info (ctx, 0);

  // clang-format off
  if (p == 0) c = '.';
  if (p == 1) c = '+';
  if (p == 2) c = '*';
  if (p == 3) c = '\n';
  // clang-format on

  fprintf (stdout, "%c", c);

  return 1;
}


bool
is_valid_named_group (const char *group_name)
{
  size_t i = 0;

  /* Check FIPS groups */
  while (dh_fips_groups[i])
    {
      if (strcmp (dh_fips_groups[i], group_name) == 0)
        return true;
      i++;
    }

    /* Check non-FIPS groups */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  if (!FIPS_mode ())
#else
  if (!EVP_default_properties_is_fips_enabled (NULL))
#endif
    {
      i = 0;
      while (dh_nonfips_groups[i])
        {
          if (strcmp (dh_nonfips_groups[i], group_name) == 0)
            return true;
          i++;
        }
    }

  return false;
}


#ifdef HAVE_OSSL_PARAM
int
get_params_by_named_group (const char *group_name, EVP_PKEY **dhparams)
{
  int ret;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name (NULL, "DH", NULL);
  OSSL_PARAM ossl_params[2];
  EVP_PKEY *params = NULL;
  char *name = NULL;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);

  if (!is_valid_named_group (group_name))
    {
      fprintf (stderr, "Unknown Diffie Hellman finite field group.\n");
      fprintf (
        stderr, "Valid groups are: %s.\n", valid_dh_group_names (tmp_ctx));
      ret = EINVAL;
      goto done;
    }

  name = talloc_strdup (NULL, group_name);

  ossl_params[0] = OSSL_PARAM_construct_utf8_string ("group", name, 0);
  ossl_params[1] = OSSL_PARAM_construct_end ();

  if (!EVP_PKEY_keygen_init (pctx))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  if (!EVP_PKEY_CTX_set_params (pctx, ossl_params))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  if (!EVP_PKEY_generate (pctx, &params))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  *dhparams = params;
  params = NULL;

  ret = EOK;

done:
  EVP_PKEY_free (params);
  EVP_PKEY_CTX_free (pctx);
  talloc_free (tmp_ctx);
  return ret;
}

#else //HAVE_OSSL_PARAM

static int
get_group_nid (const char *group_name)
{
  if (strcmp ("ffdhe2048", group_name) == 0)
    {
      return NID_ffdhe2048;
    }
  else if (strcmp ("ffdhe3072", group_name) == 0)
    {
      return NID_ffdhe3072;
    }
  else if (strcmp ("ffdhe4096", group_name) == 0)
    {
      return NID_ffdhe4096;
    }
  else if (strcmp ("ffdhe6144", group_name) == 0)
    {
      return NID_ffdhe6144;
    }
  else if (strcmp ("ffdhe8192", group_name) == 0)
    {
      return NID_ffdhe8192;
    }
  return NID_undef;
}

int
get_params_by_named_group (const char *group_name, EVP_PKEY **dhparams)
{
  int ret, sslret;
  DH *dh = NULL;
  EVP_PKEY *pkey = NULL;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);

  if (!is_valid_named_group (group_name))
    {
      fprintf (stderr, "Unknown Diffie Hellman finite field group.\n");
      fprintf (
        stderr, "Valid groups are: %s.\n", valid_dh_group_names (tmp_ctx));
      ret = EINVAL;
      goto done;
    }

  dh = DH_new_by_nid (get_group_nid (group_name));
  if (!dh)
    {
      fprintf (
        stderr, "Unknown Diffie Hellman finite field group %s.\n", group_name);
      ret = EINVAL;
      goto done;
    }

  pkey = EVP_PKEY_new ();
  sslret = EVP_PKEY_assign_DH (pkey, dh);
  CHECK_SSL (sslret, "EVP_PKEY_ASSIGN_DH");

  /* The dhparams are owned by the pkey now */
  dh = NULL;

  *dhparams = pkey;
  pkey = NULL;

  ret = EOK;

done:
  DH_free (dh);
  EVP_PKEY_free (pkey);
  talloc_free (tmp_ctx);
  return ret;
}

#endif //HAVE_OSSL_PARAM
