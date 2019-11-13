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

#include "include/sscg.h"
#include "include/dhparams.h"


static int
_sscg_dhparams_destructor (TALLOC_CTX *ctx);

static int
dh_cb (int p, int n, BN_GENCB *cb);

int
create_dhparams (TALLOC_CTX *mem_ctx,
                 enum sscg_verbosity verbosity,
                 int prime_len,
                 int generator,
                 struct sscg_dhparams **_dhparams)
{
  int ret;
  struct sscg_dhparams *dhparams = NULL;
  TALLOC_CTX *tmp_ctx = NULL;

  /* First validate the input */
  assert (_dhparams && !*_dhparams);

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

  tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  dhparams = talloc_zero (tmp_ctx, struct sscg_dhparams);
  CHECK_MEM (dhparams);

  dhparams->prime_len = prime_len;
  dhparams->generator = generator;
  talloc_set_destructor ((TALLOC_CTX *)dhparams, _sscg_dhparams_destructor);

  if (verbosity >= SSCG_DEFAULT)
    {
      fprintf (stdout,
               "Generating DH parameters of length %d and generator %d. "
               "This will take a long time.\n",
               dhparams->prime_len,
               dhparams->generator);
    }

  dhparams->dh = DH_new ();

  if (verbosity >= SSCG_VERBOSE)
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      dhparams->cb = talloc_zero (dhparams, BN_GENCB);
#else
      dhparams->cb = BN_GENCB_new ();
#endif
      if (dhparams->cb == NULL)
        {
          ERR_print_errors_fp (stderr);
          ret = ENOMEM;
          goto done;
        }

      BN_GENCB_set (dhparams->cb, dh_cb, NULL);
    }

  if (!DH_generate_parameters_ex (
        dhparams->dh, dhparams->prime_len, dhparams->generator, dhparams->cb))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  ret = EOK;
  *_dhparams = talloc_steal (mem_ctx, dhparams);

done:
  talloc_free (tmp_ctx);
  return ret;
}

static int
_sscg_dhparams_destructor (TALLOC_CTX *ctx)
{
  struct sscg_dhparams *params =
    talloc_get_type_abort (ctx, struct sscg_dhparams);

  if (params->dh != NULL)
    {
      DH_free (params->dh);
      params->dh = NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if (params->cb != NULL)
    {
      BN_GENCB_free (params->cb);
      params->cb = NULL;
    }
#endif

  return 0;
}

static int
dh_cb (int p, int n, BN_GENCB *cb)
{
  static const char symbols[] = ".+*\n";
  char c = (p >= 0 && (size_t)p < sizeof (symbols) - 1) ? symbols[p] : '?';

  fprintf (stdout, "%c", c);

  return 1;
}
