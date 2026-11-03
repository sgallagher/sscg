/* SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception */
/*
    Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#ifdef HAVE_GETTEXT
#include <libintl.h>
#endif

#include "include/names.h"
#include "include/sscg.h"

static bool
has_injection_chars (const char *s, bool forbid_colon)
{
  for (const unsigned char *p = (const unsigned char *)s; *p; p++)
    {
      if (*p == ',' || *p == ';' || *p == '@' || *p == '\n' || *p == '\r'
          || isspace (*p) || *p > 0x7f)
        {
          return true;
        }
      if (forbid_colon && *p == ':')
        {
          return true;
        }
    }
  return false;
}

static bool
is_ldh_char (char c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
         || (c >= '0' && c <= '9') || c == '-';
}

static int
validate_dns_label (const char *label, size_t len)
{
  size_t i;

  if (len == 0 || len > MAX_HOST_LEN)
    {
      return EINVAL;
    }

  if (label[0] == '-' || label[len - 1] == '-')
    {
      return EINVAL;
    }

  for (i = 0; i < len; i++)
    {
      if (!is_ldh_char (label[i]))
        {
          return EINVAL;
        }
    }

  return EOK;
}

int
sscg_validate_dns_hostname (const char *name)
{
  const char *dot_pos;
  size_t label_len;
  const char *start;
  const char *end;

  if (!name || name[0] == '\0')
    {
      fprintf (stderr, _ ("Invalid hostname.\n"));
      return EINVAL;
    }

  if (has_injection_chars (name, true))
    {
      fprintf (stderr, _ ("Invalid hostname.\n"));
      return EINVAL;
    }

  if (strnlen (name, MAX_FQDN_LEN + 1) > MAX_FQDN_LEN)
    {
      fprintf (
        stderr, _ ("FQDNs may not exceed %d characters\n"), MAX_FQDN_LEN);
      return EINVAL;
    }

  if (name[0] == '*')
    {
      /* Wildcard: must be exactly "*." followed by at least two labels,
         e.g. "*.example.com".  "*.com" (one remaining label) is rejected
         as too broad; wildcards embedded elsewhere are also rejected. */
      if (name[1] != '.')
        {
          fprintf (stderr, _ ("Invalid hostname.\n"));
          return EINVAL;
        }

      int dots = 0;
      for (const char *p = name + 2; *p; p++)
        if (*p == '.')
          dots++;

      if (name[2] == '\0' || dots < 1)
        {
          fprintf (stderr, _ ("Invalid hostname.\n"));
          return EINVAL;
        }

      start = name + 2;
    }
  else
    {
      dot_pos = strchr (name, '.');
      if (dot_pos)
        {
          label_len = (size_t)(dot_pos - name);
        }
      else
        {
          label_len = strnlen (name, MAX_HOST_LEN + 1);
        }

      if (label_len > MAX_HOST_LEN)
        {
          fprintf (stderr,
                   _ ("Hostname labels may not exceed %d characters\n"),
                   MAX_HOST_LEN);
          return EINVAL;
        }

      if (name[0] == '.' || name[strlen (name) - 1] == '.')
        {
          fprintf (stderr, _ ("Invalid hostname.\n"));
          return EINVAL;
        }

      start = name;
    }

  while (*start)
    {
      end = strchr (start, '.');
      if (!end)
        {
          end = start + strlen (start);
        }

      label_len = (size_t)(end - start);
      if (validate_dns_label (start, label_len) != EOK)
        {
          if (label_len > MAX_HOST_LEN)
            {
              fprintf (stderr,
                       _ ("Hostname labels may not exceed %d characters\n"),
                       MAX_HOST_LEN);
            }
          else
            {
              fprintf (stderr, _ ("Invalid hostname.\n"));
            }
          return EINVAL;
        }

      if (*end == '\0')
        {
          break;
        }
      start = end + 1;
      if (*start == '\0')
        {
          fprintf (stderr, _ ("Invalid hostname.\n"));
          return EINVAL;
        }
    }

  return EOK;
}

int
sscg_parse_ip_netmask (const char *mask, bool is_ipv6, int *_prefix_len)
{
  int prefix_len;

  if (!mask || mask[0] == '\0')
    {
      return EINVAL;
    }

  if (strchr (mask, '.'))
    {
      /* Explicit dotted-decimal netmask, e.g. 255.255.255.255.  Only
         valid for IPv4 addresses and must be a contiguous (CIDR-style)
         netmask. */
      struct in_addr netmask;
      uint32_t mask_bits;

      if (is_ipv6)
        {
          return EINVAL;
        }

      if (inet_pton (AF_INET, mask, &netmask) != 1)
        {
          return EINVAL;
        }

      /* Reject non-contiguous netmasks such as 255.0.255.0 */
      mask_bits = ntohl (netmask.s_addr);
      if (mask_bits != 0 && (mask_bits | (mask_bits - 1)) != 0xFFFFFFFFu)
        {
          return EINVAL;
        }

      /* Count the leading one bits to get the prefix length */
      prefix_len = 0;
      while (mask_bits)
        {
          prefix_len++;
          mask_bits <<= 1;
        }
    }
  else
    {
      /* CIDR prefix length */
      char *end;
      long value;

      for (const char *p = mask; *p; p++)
        {
          if (!isdigit ((unsigned char)*p))
            {
              return EINVAL;
            }
        }

      /* Parse with strtol() rather than atoi() so that overlong digit
         strings are rejected instead of silently wrapping to a
         negative or otherwise out-of-range value. */
      errno = 0;
      value = strtol (mask, &end, 10);
      if (errno == ERANGE || *end != '\0' || value < 0
          || value > (is_ipv6 ? 128 : 32))
        {
          return EINVAL;
        }
      prefix_len = (int)value;
    }

  *_prefix_len = prefix_len;
  return EOK;
}

static int
validate_ip_san (const char *value)
{
  char hostbuf[INET6_ADDRSTRLEN + 1];
  const char *slash;
  size_t hostlen;
  int prefix_len;

  slash = strchr (value, '/');
  if (slash)
    {
      hostlen = (size_t)(slash - value);
      if (hostlen == 0 || hostlen >= sizeof (hostbuf))
        {
          fprintf (stderr, _ ("Invalid subject alternative name.\n"));
          return EINVAL;
        }
      memcpy (hostbuf, value, hostlen);
      hostbuf[hostlen] = '\0';

      if (*(slash + 1) == '\0')
        {
          fprintf (stderr, _ ("Invalid subject alternative name.\n"));
          return EINVAL;
        }

      if (sscg_parse_ip_netmask (
            slash + 1, strchr (hostbuf, ':') != NULL, &prefix_len)
          != EOK)
        {
          fprintf (stderr, _ ("Invalid subject alternative name.\n"));
          return EINVAL;
        }
    }
  else
    {
      if (strlen (value) >= sizeof (hostbuf))
        {
          fprintf (stderr, _ ("Invalid subject alternative name.\n"));
          return EINVAL;
        }
      memcpy (hostbuf, value, strlen (value) + 1);
    }

  if (strchr (hostbuf, ':'))
    {
      struct in6_addr addr6;

      if (inet_pton (AF_INET6, hostbuf, &addr6) != 1)
        {
          fprintf (stderr, _ ("Invalid subject alternative name.\n"));
          return EINVAL;
        }
    }
  else
    {
      struct in_addr addr4;

      if (inet_pton (AF_INET, hostbuf, &addr4) != 1)
        {
          fprintf (stderr, _ ("Invalid subject alternative name.\n"));
          return EINVAL;
        }
    }

  return EOK;
}

int
sscg_validate_subject_alt_name (const char *san)
{
  const char *colon;

  if (!san || san[0] == '\0')
    {
      fprintf (stderr, _ ("Invalid subject alternative name.\n"));
      return EINVAL;
    }

  if (has_injection_chars (san, false))
    {
      fprintf (stderr, _ ("Invalid subject alternative name.\n"));
      return EINVAL;
    }

  colon = strchr (san, ':');
  if (!colon)
    {
      return sscg_validate_dns_hostname (san);
    }

  if (strncmp (san, "DNS:", 4) == 0)
    {
      if (san[4] == '\0')
        {
          fprintf (stderr, _ ("Invalid subject alternative name.\n"));
          return EINVAL;
        }
      return sscg_validate_dns_hostname (san + 4);
    }

  if (strncmp (san, "IP:", 3) == 0)
    {
      if (san[3] == '\0')
        {
          fprintf (stderr, _ ("Invalid subject alternative name.\n"));
          return EINVAL;
        }
      return validate_ip_san (san + 3);
    }

  fprintf (stderr, _ ("Invalid subject alternative name.\n"));
  return EINVAL;
}
