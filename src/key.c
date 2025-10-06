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

    Copyright 2017-2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <openssl/err.h>

#include "config.h"
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
  int ret;
  EVP_PKEY *pkey = NULL;
  TALLOC_CTX *tmp_ctx = NULL;

  pkey = EVP_PKEY_Q_keygen (NULL, NULL, "RSA", (size_t)(0 + (bits)));
  CHECK_MEM (pkey);

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
  talloc_free (tmp_ctx);
  return ret;
}


int
sscg_generate_ec_key (TALLOC_CTX *mem_ctx,
                      const char *alg,
                      struct sscg_evp_pkey **_key)
{
  int ret;
  EVP_PKEY *pkey = NULL;
  TALLOC_CTX *tmp_ctx = NULL;

  pkey = EVP_PKEY_Q_keygen (NULL, NULL, "EC", alg);
  CHECK_MEM (pkey);

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
  talloc_free (tmp_ctx);
  return ret;
}


#ifdef HAVE_ML_DSA
int
sscg_generate_mldsa_key (TALLOC_CTX *mem_ctx,
                         int nist_level,
                         struct sscg_evp_pkey **_key)
{
  int ret;
  const char *type = NULL;
  EVP_PKEY *pkey = NULL;
  TALLOC_CTX *tmp_ctx = NULL;

  switch (nist_level)
    {
    case 2: type = "ML-DSA-44"; break;
    case 3: type = "ML-DSA-65"; break;
    case 5: type = "ML-DSA-87"; break;
    default: ret = EINVAL; goto done;
    }

  pkey = EVP_PKEY_Q_keygen (NULL, NULL, type);
  CHECK_MEM (pkey);

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
  talloc_free (tmp_ctx);
  return ret;
}
#endif /* HAVE_ML_DSA */

