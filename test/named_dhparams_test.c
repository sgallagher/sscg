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
#include <openssl/evp.h>

#include "include/sscg.h"
#include "include/dhparams.h"


static int
test_group_name_list (void)
{
  int ret;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  char *names = valid_dh_group_names (tmp_ctx);
  if (!names)
    {
      ret = EINVAL;
      goto done;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  if (strcmp(names, "ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192") != 0)
    {
      ret = EINVAL;
      goto done;
    }
#else
    if (strcmp(names, "ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192, modp_2048, modp_3072, modp_4096, modp_6144, modp_8192, modp_1536, dh_1024_160, dh_2048_224, dh_2048_256") != 0)
    {
      ret = EINVAL;
      goto done;
    }
#endif


  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}


static int
test_valid_named_groups (void)
{
  int ret;
  size_t i = 0;
  EVP_PKEY *dhparams = NULL;
  EVP_PKEY_CTX *pctx = NULL;

  if (getenv ("SSCG_SKIP_DHPARAMS"))
    {
      /* Skip this test */
      return 77;
    }

  while (dh_fips_groups[i])
    {
      printf("Testing %s\n", dh_fips_groups[i]);
      ret = get_params_by_named_group (dh_fips_groups[i], &dhparams);
      if (ret != EOK) {
        fprintf (stderr,
                 "Could not retrieve named DH parameters.");
        goto done;
      }

      pctx = EVP_PKEY_CTX_new(dhparams, NULL);
      if (!EVP_PKEY_param_check(pctx))
        {
          ERR_print_errors_fp (stderr);
          ret = EIO;
          goto done;
        }

      i++;

      EVP_PKEY_CTX_free (pctx);
      pctx = NULL;

      EVP_PKEY_free (dhparams);
      dhparams = NULL;
    }

  ret = EOK;

done:
  EVP_PKEY_free (dhparams);
  EVP_PKEY_CTX_free (pctx);
  return ret;
}


static int
test_invalid_named_groups (void)
{
  int ret;
  EVP_PKEY *dhparams = NULL;
  TALLOC_CTX *tmp_ctx = NULL;
  char *name = NULL;

  if (getenv ("SSCG_SKIP_DHPARAMS"))
    {
      /* Skip this test */
      return 77;
    }

  tmp_ctx = talloc_new (NULL);

  printf("Testing empty string\n");
  ret = get_params_by_named_group ("", &dhparams);
  if (ret != EINVAL) {
    fprintf (stderr,
             "Received [%s] return code.", strerror(ret));
    ret = EINVAL;
    goto done;
  }


  printf("Testing long, unterminated string\n");
  name = talloc_array (tmp_ctx, char, 10 * 1024 * 1024 + 1);
  memset (name, 'a', 10 * 1024 * 1024);
  ret = get_params_by_named_group (name, &dhparams);
  if (ret != EINVAL) {
    fprintf (stderr,
             "Received [%s] return code.", strerror(ret));
    ret = EINVAL;
    goto done;
  }
  talloc_zfree (name);


  EVP_PKEY_free (dhparams);
  dhparams = NULL;

  ret = EOK;

done:
  EVP_PKEY_free (dhparams);
  return ret;
}


int
main (int argc, char **argv)
{
  int ret = EOK;

  ret = test_valid_named_groups ();
  if (ret != EOK) goto done;

  ret = test_invalid_named_groups ();
  if (ret != EOK) goto done;

  ret = test_group_name_list ();
  if (ret != EOK) goto done;

  ret = EOK;

done:
  return ret;
}
