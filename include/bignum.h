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

#ifndef _SSCG_BIGNUM_H
# define _SSCG_BIGNUM_H

#include <openssl/bn.h>
#include "sscg.h"


/* Add definitions for some helper values added in OpenSSL 1.1.0
   when building against OpenSSL 1.0.2 */
#ifndef BN_RAND_TOP_ANY
# define BN_RAND_TOP_ANY -1
#endif

#ifndef BN_RAND_BOTTOM_ANY
# define BN_RAND_BOTTOM_ANY 0
#endif

struct sscg_bignum {
    BIGNUM *bn;
};


int
sscg_bignum_destructor(TALLOC_CTX *mem_ctx);

int
sscg_init_bignum(TALLOC_CTX *mem_ctx, unsigned long num,
                 struct sscg_bignum **bn);


#endif /* _SSCG_BIGNUM_H */
