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

#ifndef _SSCG_KEY_H
#define _SSCG_KEY_H

#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

#include "include/sscg.h"
#include "include/bignum.h"

struct sscg_evp_pkey
{
  EVP_PKEY *evp_pkey;
};

int
sscg_generate_rsa_key (TALLOC_CTX *mem_ctx,
                       int bits,
                       struct sscg_evp_pkey **_key);

int
sscg_generate_mldsa_key (TALLOC_CTX *mem_ctx,
                         int nist_level,
                         struct sscg_evp_pkey **_key);

#endif /* _SSCG_KEY_H */
