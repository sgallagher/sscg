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
#include "bignum.h"

struct cert_options {
    BIGNUM *serial_number;
};

int
generate_serial(TALLOC_CTX *mem_ctx, struct sscg_bignum **serial);

int
generate_certificate(TALLOC_CTX *mem_ctx, const struct cert_options *copts);
