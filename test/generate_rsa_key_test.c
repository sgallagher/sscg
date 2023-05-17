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

    Copyright 2017-2023 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>

#include "include/bignum.h"
#include "include/key.h"

int
main (int argc, char **argv)
{
  int ret;
  struct sscg_evp_pkey *pkey;
  size_t j;
  int bits[] = { 512, 1024, 2048, 4096, 0 };

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  j = 0;
  while (bits[j] != 0)
    {
      printf ("\tGenerating %d-bit key. ", bits[j]);
      ret = sscg_generate_rsa_key (tmp_ctx, bits[j], &pkey);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          fprintf (stderr, "Error generating key: [%s].\n", strerror (ret));
          goto done;
        }
      printf ("SUCCESS.\n");

      /* Inspect the created key for validity */
      if (EVP_PKEY_RSA != EVP_PKEY_base_id (pkey->evp_pkey))
        {
          fprintf (stderr, "Generated key was not an RSA key.\n");
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
