/* SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception */
/*
    Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>

#include "include/names.h"
#include "include/sscg.h"

struct dns_case
{
  const char *name;
  int expected;
};

static int
run_dns_cases (const struct dns_case *cases, size_t n, const char *suite)
{
  size_t i;
  int ret = EOK;

  printf ("%s\n", suite);
  for (i = 0; i < n; i++)
    {
      int got = sscg_validate_dns_hostname (cases[i].name);

      printf ("  [%s] ", cases[i].name ? cases[i].name : "(null)");
      if (got != cases[i].expected)
        {
          printf ("FAILED (got %d, expected %d).\n", got, cases[i].expected);
          ret = EINVAL;
        }
      else
        {
          printf ("ok.\n");
        }
    }
  printf ("\n");
  return ret;
}

static int
run_san_cases (const struct dns_case *cases, size_t n, const char *suite)
{
  size_t i;
  int ret = EOK;

  printf ("%s\n", suite);
  for (i = 0; i < n; i++)
    {
      int got = sscg_validate_subject_alt_name (cases[i].name);

      printf ("  [%s] ", cases[i].name);
      if (got != cases[i].expected)
        {
          printf ("FAILED (got %d, expected %d).\n", got, cases[i].expected);
          ret = EINVAL;
        }
      else
        {
          printf ("ok.\n");
        }
    }
  printf ("\n");
  return ret;
}

struct netmask_case
{
  const char *mask;
  bool is_ipv6;
  int expected;
  int expected_prefix_len;
};

static int
run_netmask_cases (const struct netmask_case *cases,
                   size_t n,
                   const char *suite)
{
  size_t i;
  int ret = EOK;

  printf ("%s\n", suite);
  for (i = 0; i < n; i++)
    {
      int prefix_len = -1;
      int got =
        sscg_parse_ip_netmask (cases[i].mask, cases[i].is_ipv6, &prefix_len);

      printf (
        "  [%s, %s] ", cases[i].mask, cases[i].is_ipv6 ? "IPv6" : "IPv4");
      if (got != cases[i].expected)
        {
          printf ("FAILED (got %d, expected %d).\n", got, cases[i].expected);
          ret = EINVAL;
        }
      else if (got == EOK && prefix_len != cases[i].expected_prefix_len)
        {
          printf ("FAILED (prefix length %d, expected %d).\n",
                  prefix_len,
                  cases[i].expected_prefix_len);
          ret = EINVAL;
        }
      else
        {
          printf ("ok.\n");
        }
    }
  printf ("\n");
  return ret;
}

int
main (int argc, char **argv)
{
  int ret = EOK;
  char label_63[64];
  char fqdn_63[80];
  char label_64[80];

  talloc_enable_leak_report_full ();

  printf ("=== DNS name validation unit test ===\n\n");

  memset (label_63, 'a', 63);
  label_63[63] = '\0';
  snprintf (fqdn_63, sizeof (fqdn_63), "%s.example.com", label_63);

  {
    char long_label[64 + 1];

    memset (long_label, 'a', 64);
    long_label[64] = '\0';
    snprintf (label_64, sizeof (label_64), "%s.example.com", long_label);
  }

  const struct dns_case accept_dns[] = {
    { "server.example.com", EOK },
    { "localhost", EOK },
    { "a", EOK },
    { fqdn_63, EOK },
    { "*.example.com", EOK },
    { "*.apps.example.com", EOK },
  };

  const struct dns_case reject_dns[] = {
    { "a, DNS:evil.com", EINVAL },
    { "foo;bar", EINVAL },
    { "bad_label", EINVAL },
    { "..example.com", EINVAL },
    { ".example.com", EINVAL },
    { "example.com.", EINVAL },
    { label_64, EINVAL },
    { "", EINVAL },
    { "host:name", EINVAL },
    { "*.com", EINVAL },
    { "*", EINVAL },
    { "*x.example.com", EINVAL },
    { "*.*.example.com", EINVAL },
    { "foo.*.example.com", EINVAL },
  };

  ret = run_dns_cases (accept_dns,
                       sizeof (accept_dns) / sizeof (accept_dns[0]),
                       "sscg_validate_dns_hostname (accept)");
  if (ret != EOK)
    {
      return ret;
    }

  ret = run_dns_cases (reject_dns,
                       sizeof (reject_dns) / sizeof (reject_dns[0]),
                       "sscg_validate_dns_hostname (reject)");
  if (ret != EOK)
    {
      return ret;
    }

  const struct dns_case accept_san[] = {
    { "alt.example.com", EOK },
    { "DNS:alt.example.com", EOK },
    { "IP:192.0.2.1", EOK },
    { "IP:2001:db8::1", EOK },
    { "IP:203.0.113.0/24", EOK },
    /* IPv4 CIDR boundary values */
    { "IP:0.0.0.0/0", EOK },
    { "IP:10.0.0.0/12", EOK },
    { "IP:10.0.0.0/32", EOK },
    /* IPv6 CIDR boundary values */
    { "IP:2001:db8::/0", EOK },
    { "IP:2001:db8::/48", EOK },
    { "IP:::1/128", EOK },
    /* Explicit dotted-decimal netmasks (IPv4 only) */
    { "IP:127.0.0.1/255.255.255.255", EOK },
    { "IP:10.0.0.0/255.240.0.0", EOK },
    { "IP:10.0.0.5/255.255.255.0", EOK },
    { "IP:10.0.0.0/0.0.0.0", EOK },
    { "*.example.com", EOK },
    { "DNS:*.example.com", EOK },
  };

  const struct dns_case reject_san[] = {
    { "DNS:evil.com, DNS:other", EINVAL },
    { "URI:https://example.com", EINVAL },
    { "OTHER:foo", EINVAL },
    { "IP:not-an-ip", EINVAL },
    { "evil, DNS:other", EINVAL },
    /* CIDR: empty suffix */
    { "IP:10.0.0.0/", EINVAL },
    /* CIDR: prefix out of range for address family */
    { "IP:10.0.0.0/33", EINVAL },
    { "IP:::1/129", EINVAL },
    /* CIDR: overlong suffixes that would wrap with atoi() */
    { "IP:10.0.0.0/2147483648", EINVAL },
    { "IP:10.0.0.0/4294967295", EINVAL },
    { "IP:::1/99999999999999999999", EINVAL },
    /* Dotted netmask: not a valid IPv4 address */
    { "IP:10.0.0.0/255.255.255.256", EINVAL },
    { "IP:10.0.0.0/255.255.255", EINVAL },
    /* Dotted netmask: valid IPv4 address, but not a contiguous netmask */
    { "IP:10.0.0.0/255.0.255.0", EINVAL },
    { "IP:10.0.0.0/1.2.3.4", EINVAL },
    /* Dotted netmask: not valid for IPv6 addresses */
    { "IP:::1/255.255.255.255", EINVAL },
  };

  ret = run_san_cases (accept_san,
                       sizeof (accept_san) / sizeof (accept_san[0]),
                       "sscg_validate_subject_alt_name (accept)");
  if (ret != EOK)
    {
      return ret;
    }

  ret = run_san_cases (reject_san,
                       sizeof (reject_san) / sizeof (reject_san[0]),
                       "sscg_validate_subject_alt_name (reject)");
  if (ret != EOK)
    {
      return ret;
    }

  const struct netmask_case netmask_cases[] = {
    /* CIDR prefix lengths */
    { "0", false, EOK, 0 },
    { "12", false, EOK, 12 },
    { "32", false, EOK, 32 },
    { "0", true, EOK, 0 },
    { "48", true, EOK, 48 },
    { "128", true, EOK, 128 },
    /* Dotted-decimal netmasks */
    { "0.0.0.0", false, EOK, 0 },
    { "128.0.0.0", false, EOK, 1 },
    { "255.240.0.0", false, EOK, 12 },
    { "255.255.255.0", false, EOK, 24 },
    { "255.255.255.254", false, EOK, 31 },
    { "255.255.255.255", false, EOK, 32 },
    /* Out of range for the address family */
    { "33", false, EINVAL, 0 },
    { "129", true, EINVAL, 0 },
    /* Overlong prefix lengths that would wrap with atoi() */
    { "2147483648", false, EINVAL, 0 },
    { "4294967295", false, EINVAL, 0 },
    { "99999999999999999999", true, EINVAL, 0 },
    /* Not a number */
    { "", false, EINVAL, 0 },
    { "-1", false, EINVAL, 0 },
    { "+1", false, EINVAL, 0 },
    { "12x", false, EINVAL, 0 },
    /* Bad dotted-decimal netmasks */
    { "0.0.0.1", false, EINVAL, 0 },
    { "255.0.255.0", false, EINVAL, 0 },
    { "255.255.255.255", true, EINVAL, 0 },
  };

  ret = run_netmask_cases (netmask_cases,
                           sizeof (netmask_cases) / sizeof (netmask_cases[0]),
                           "sscg_parse_ip_netmask");
  return ret;
}
