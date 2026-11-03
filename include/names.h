/* SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception */
/*
    Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#ifndef _SSCG_NAMES_H
#define _SSCG_NAMES_H

#include <stdbool.h>

#include "include/sscg.h"

int
sscg_validate_dns_hostname (const char *name);

int
sscg_validate_subject_alt_name (const char *san);

/* Parse the netmask of an IP subject alternative name (the text after
   the '/').  The netmask may be either a CIDR prefix length (0-32 for
   IPv4, 0-128 for IPv6) or, for IPv4 addresses only, a contiguous
   dotted-decimal netmask such as 255.240.0.0.  On success, the
   equivalent prefix length is stored in *_prefix_len and EOK is
   returned.  Otherwise EINVAL is returned. */
int
sscg_parse_ip_netmask (const char *mask, bool is_ipv6, int *_prefix_len);

#endif /* _SSCG_NAMES_H */
