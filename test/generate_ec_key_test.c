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
    version of the file(s), but you delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.

    Copyright 2017-2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>

#include "include/key.h"

int
main (int argc, char **argv)
{
  int ret;
  struct sscg_evp_pkey *pkey;
  size_t j;
  const char *curves[] = { "secp224r1",       "secp256k1",
                           "secp384r1",       "secp521r1",
                           "prime256v1",      "brainpoolP256r1",
                           "brainpoolP256t1", "brainpoolP320r1",
                           "brainpoolP320t1", "brainpoolP384r1",
                           "brainpoolP384t1", "brainpoolP512r1",
                           "brainpoolP512t1", NULL };

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  /* Test all available curves */
  j = 0;
  while (curves[j] != NULL)
    {
      printf ("\tGenerating EC key with curve %s. ", curves[j]);
      ret = sscg_generate_ec_key (tmp_ctx, (char *)curves[j], &pkey);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          fprintf (stderr, "Error generating key: [%s].\n", strerror (ret));
          goto done;
        }
      printf ("SUCCESS.\n");

      /* Inspect the created key for validity - check that it's an EC key */
      if (EVP_PKEY_EC != EVP_PKEY_base_id (pkey->evp_pkey))
        {
          fprintf (stderr, "Generated key was not an EC key.\n");
          ret = EINVAL;
          goto done;
        }

      j++;
    }

  /* Test invalid curve */
  printf ("\tTesting invalid curve 'invalid-curve-123'. ");
  ret = sscg_generate_ec_key (tmp_ctx, "invalid-curve-123", &pkey);
  if (ret == EOK)
    {
      printf ("FAILED - should have failed for invalid curve.\n");
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS - correctly failed for invalid curve.\n");

  /* Test NULL curve */
  printf ("\tTesting NULL curve. ");
  ret = sscg_generate_ec_key (tmp_ctx, NULL, &pkey);
  if (ret == EOK)
    {
      printf ("FAILED - should have failed for NULL curve.\n");
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS - correctly failed for NULL curve.\n");

  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}
