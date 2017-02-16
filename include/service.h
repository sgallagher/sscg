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
#include "key.h"

#ifndef _SERVICE_H
# define _SERVICE_H

int
create_service_cert(TALLOC_CTX                 *mem_ctx,
                    const struct sscg_options  *options,
                    struct sscg_x509_cert      *ca_cert,
                    struct sscg_evp_pkey       *ca_key,
                    struct sscg_x509_cert     **_svc_cert,
                    struct sscg_evp_pkey      **_svc_key);

#endif /* _SERVICE_H */
