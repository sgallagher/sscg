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

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include "include/sscg.h"
#include "include/bignum.h"

#ifndef _SSCG_KEY_H
# define _SSCG_KEY_H

struct sscg_evp_pkey {
    EVP_PKEY *evp_pkey;
};

int
sscg_generate_rsa_key(TALLOC_CTX *mem_ctx, int bits, struct sscg_bignum *e,
                      struct sscg_evp_pkey **_key);


#endif /* _SSCG_KEY_H */
