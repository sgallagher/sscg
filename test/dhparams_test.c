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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "include/dhparams.h"

int
main (int argc, char **argv)
{
  int ret, prime_len, generator;
  EVP_PKEY *params = NULL;
  EVP_PKEY_CTX *pctx = NULL;
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

  ret = create_dhparams (SSCG_DEBUG, prime_len, generator, &params);
  if (ret != EOK)
    {
      fprintf (stderr,
               "Could not generate DH parameters: [%s]",
               ERR_error_string (ERR_get_error (), NULL));
      goto done;
    }

  pctx = EVP_PKEY_CTX_new (params, NULL);
  if (!EVP_PKEY_param_check (pctx))
    {
      ERR_print_errors_fp (stderr);
      ret = EIO;
      goto done;
    }

  ret = EOK;

done:
  talloc_free (main_ctx);
  return ret;
}
