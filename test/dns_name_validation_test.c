/* SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception */
/*
    Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <errno.h>
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
    { "alt.example.com", EOK },      { "DNS:alt.example.com", EOK },
    { "IP:192.0.2.1", EOK },         { "IP:2001:db8::1", EOK },
    { "IP:203.0.113.0/24", EOK },
    { "*.example.com", EOK },        { "DNS:*.example.com", EOK },
  };

  const struct dns_case reject_san[] = {
    { "DNS:evil.com, DNS:other", EINVAL },
    { "URI:https://example.com", EINVAL },
    { "OTHER:foo", EINVAL },
    { "IP:not-an-ip", EINVAL },
    { "evil, DNS:other", EINVAL },
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
  return ret;
}
