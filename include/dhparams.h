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

#ifndef _SSCG_DHPARAMS_H
#define _SSCG_DHPARAMS_H

#include <talloc.h>

#include "include/sscg.h"

struct sscg_dhparams
{
  int prime_len;
  int generator;
  DH *dh;
  BN_GENCB *cb;
};

int
create_dhparams (TALLOC_CTX *mem_ctx,
                 enum sscg_verbosity options,
                 int prime_len,
                 int generator,
                 struct sscg_dhparams **_dhparams);

#endif /* _SSCG_DHPARAMS_H */
