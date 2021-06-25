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

#include <openssl/err.h>
#include "include/sscg.h"
#include "include/key.h"

static int
_sscg_evp_pkey_destructor (TALLOC_CTX *mem_ctx)
{
  struct sscg_evp_pkey *pkey =
    talloc_get_type_abort (mem_ctx, struct sscg_evp_pkey);

  EVP_PKEY_free (pkey->evp_pkey);

  return 0;
}

int
sscg_generate_rsa_key (TALLOC_CTX *mem_ctx,
                       int bits,
                       struct sscg_evp_pkey **_key)
{
  int ret, sslret;
  RSA *rsa = NULL;
  EVP_PKEY *pkey = NULL;
  struct sscg_bignum *e;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);

  /* Create memory for the actual key */
  rsa = RSA_new ();
  CHECK_MEM (rsa);

  /* Use an exponent value of RSA F4 aka 0x10001 (65537) */
  ret = sscg_init_bignum (tmp_ctx, RSA_F4, &e);
  CHECK_OK (ret);

  /* Generate a random RSA keypair */
  sslret = RSA_generate_key_ex (rsa, bits, e->bn, NULL);
  CHECK_SSL (sslret, RSA_generate_key_ex);

  pkey = EVP_PKEY_new ();
  CHECK_MEM (pkey);

  sslret = EVP_PKEY_assign_RSA (pkey, rsa);
  CHECK_SSL (sslret, EVP_PKEY_assign_RSA);

  /* The memory for the RSA key is now maintained by the EVP_PKEY.
       Mark this variable as NULL so we don't free() it below */
  rsa = NULL;

  /* Create the talloc container to hold the memory */
  (*_key) = talloc_zero (mem_ctx, struct sscg_evp_pkey);
  if (!(*_key))
    {
      ret = ENOMEM;
      goto done;
    }

  (*_key)->evp_pkey = pkey;
  talloc_set_destructor ((TALLOC_CTX *)(*_key), _sscg_evp_pkey_destructor);

  ret = EOK;

done:
  RSA_free (rsa);
  talloc_free (tmp_ctx);
  return ret;
}
