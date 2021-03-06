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

#include "sscg.h"
#include "x509.h"

#ifndef _AUTHORITY_H
#define _AUTHORITY_H

int
create_private_CA (TALLOC_CTX *mem_ctx,
                   const struct sscg_options *options,
                   struct sscg_x509_cert **_cacert,
                   struct sscg_evp_pkey **_cakey);

#endif /* _AUTHORITY_H */
