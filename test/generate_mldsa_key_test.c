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
  int current_nist_level;
  int nist_levels[] = { 2, 3, 5, 0 };

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  j = 0;
  while (nist_levels[j] != 0)
    {
      current_nist_level = nist_levels[j];

      printf ("\tGenerating ML-DSA key with NIST level %d. ", nist_levels[j]);
      ret = sscg_generate_mldsa_key (tmp_ctx, nist_levels[j], &pkey);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          fprintf (stderr, "Error generating key: [%s].\n", strerror (ret));
          goto done;
        }
      printf ("SUCCESS.\n");

      /* Inspect the created key for validity - just check that it's not NULL */
      switch (current_nist_level)
        {
        case 2:
          if (!EVP_PKEY_is_a (pkey->evp_pkey, "ML-DSA-44"))
            {
              fprintf (stderr,
                       "Generated key was not an ML-DSA-44 key: %s",
                       EVP_PKEY_get0_type_name (pkey->evp_pkey));
              ret = EINVAL;
              goto done;
            }
          break;
        case 3:
          if (!EVP_PKEY_is_a (pkey->evp_pkey, "ML-DSA-65"))
            {
              fprintf (stderr,
                       "Generated key was not an ML-DSA-65 key: %s",
                       EVP_PKEY_get0_type_name (pkey->evp_pkey));
              ret = EINVAL;
              goto done;
            }
          break;
        case 5:
          if (!EVP_PKEY_is_a (pkey->evp_pkey, "ML-DSA-87"))
            {
              fprintf (stderr,
                       "Generated key was not an ML-DSA-87 key: %s",
                       EVP_PKEY_get0_type_name (pkey->evp_pkey));
              ret = EINVAL;
              goto done;
            }
          break;
        default:
          fprintf (stderr, "Unknown NIST level.\n");
          ret = EINVAL;
          goto done;
        }

      j++;
    }

  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}
