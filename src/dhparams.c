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

    Copyright 2019 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <assert.h>

#include <openssl/evp.h>

#include "config.h"
#include "include/sscg.h"
#include "include/dhparams.h"


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
