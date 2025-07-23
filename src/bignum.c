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
#include "include/sscg.h"
#include "include/bignum.h"

static int
_sscg_bignum_destructor (TALLOC_CTX *mem_ctx)
{
  struct sscg_bignum *bn = talloc_get_type_abort (mem_ctx, struct sscg_bignum);

  BN_free (bn->bn);

  return 0;
}

int
sscg_init_bignum (TALLOC_CTX *mem_ctx,
                  unsigned long num,
                  struct sscg_bignum **bn)
{
  int ret = EOK;
  int sslret;
  struct sscg_bignum *bignum;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  bignum = talloc_zero (tmp_ctx, struct sscg_bignum);
  if (!bignum)
    {
      ret = ENOMEM;
      goto done;
    }

  BIGNUM *sslbn = BN_new ();
  if (!sslbn)
    {
      ret = ENOMEM;
      goto done;
    }

  bignum->bn = sslbn;
  talloc_set_destructor ((TALLOC_CTX *)bignum, _sscg_bignum_destructor);

  sslret = BN_set_word (bignum->bn, num);
  CHECK_SSL (sslret, BN_set_word);

  ret = EOK;

done:
  if (ret == EOK)
    {
      *bn = talloc_steal (mem_ctx, bignum);
    }
  talloc_zfree (tmp_ctx);

  return ret;
}
