/* SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception */
/*
    Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#ifndef _SSCG_NAMES_H
#define _SSCG_NAMES_H

#include "include/sscg.h"

int
sscg_validate_dns_hostname (const char *name);

int
sscg_validate_subject_alt_name (const char *san);

#endif /* _SSCG_NAMES_H */
