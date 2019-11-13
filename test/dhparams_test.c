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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <openssl/err.h>

#include "include/dhparams.h"

int
main (int argc, char **argv)
{
  int ret, sret, prime_len, generator;
  struct sscg_dhparams *params = NULL;
  TALLOC_CTX *main_ctx = NULL;

  if (getenv ("SSCG_SKIP_DHPARAMS"))
    {
      /* Skip this test */
      return 77;
    }

  errno = 0;
  prime_len = strtol (argv[1], NULL, 0);
  if (errno)
    {
      fprintf (stderr, "Prime length was not a valid integer.");
      ret = errno;
      goto done;
    }

  errno = 0;
  generator = strtol (argv[2], NULL, 0);
  if (errno)
    {
      fprintf (stderr, "Generator was not a valid integer.");
      ret = errno;
      goto done;
    }

  main_ctx = talloc_new (NULL);

  ret = create_dhparams (main_ctx, SSCG_DEBUG, prime_len, generator, &params);
  if (ret != EOK)
    {
      fprintf (stderr,
               "Could not generate DH parameters: [%s]",
               ERR_error_string (ERR_get_error (), NULL));
      goto done;
    }

  if (!DH_check (params->dh, &sret))
    {
      ERR_print_errors_fp (stderr);
      goto done;
    }
  if (sret & DH_CHECK_P_NOT_PRIME)
    fprintf (stderr, "p value is not prime\n");
  if (sret & DH_CHECK_P_NOT_SAFE_PRIME)
    fprintf (stderr, "p value is not a safe prime\n");
  if (sret & DH_CHECK_Q_NOT_PRIME)
    fprintf (stderr, "q value is not a prime\n");
  if (sret & DH_CHECK_INVALID_Q_VALUE)
    fprintf (stderr, "q value is invalid\n");
  if (sret & DH_CHECK_INVALID_J_VALUE)
    fprintf (stderr, "j value is invalid\n");
  if (sret & DH_UNABLE_TO_CHECK_GENERATOR)
    fprintf (stderr, "unable to check the generator value\n");
  if (sret & DH_NOT_SUITABLE_GENERATOR)
    fprintf (stderr, "the g value is not a generator\n");

  if (sret != 0)
    {
      /*
       * We have generated parameters but DH_check() indicates they are
       * invalid! This should never happen!
       */
      fprintf (stderr, "ERROR: Invalid parameters generated\n");
      ret = EIO;
      goto done;
    }

  ret = EOK;

done:
  talloc_free (main_ctx);
  return ret;
}
