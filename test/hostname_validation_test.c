/* SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception */
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

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.

    Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <stdio.h>
#include <string.h>
#include <talloc.h>

#include "include/sscg.h"

/*
 * Regression test for NULL pointer dereference bug in hostname validation.
 *
 * Bug: arguments.c previously called strchr() to find a dot in the hostname,
 * then used pointer arithmetic without checking if strchr() returned NULL.
 * This caused a crash when hostnames lacked a dot (e.g., "localhost").
 *
 * Fix: Store strchr() result and check for NULL before pointer arithmetic.
 */

int
main (int argc, char **argv)
{
  int ret;
  TALLOC_CTX *tmp_ctx = NULL;
  struct sscg_options *options = NULL;

  /* Enable talloc leak reporting for memory leak detection */
  talloc_enable_leak_report_full ();

  tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  printf ("=== SSCG Hostname Validation Regression Test ===\n\n");

  /*
   * Test 1: Single-label hostname (no dot)
   * This is the original bug - would crash with NULL pointer dereference
   */
  printf ("Test 1: Single-label hostname 'localhost'. ");

  const char *argv_localhost[] = { "sscg", "--hostname", "localhost", NULL };
  ret = sscg_handle_arguments (tmp_ctx, 3, argv_localhost, &options);
  if (ret != EOK)
    {
      printf ("FAILED (ret=%d).\n", ret);
      goto done;
    }

  if (strcmp (options->hostname, "localhost") != 0)
    {
      printf ("FAILED. Hostname not set correctly.\n");
      ret = EINVAL;
      goto done;
    }

  printf ("SUCCESS.\n");

  /*
   * Test 2: Another single-label hostname
   */
  printf ("Test 2: Single-label hostname 'server'. ");

  const char *argv_server[] = { "sscg", "--hostname", "server", NULL };
  ret = sscg_handle_arguments (tmp_ctx, 3, argv_server, &options);
  if (ret != EOK)
    {
      printf ("FAILED (ret=%d).\n", ret);
      goto done;
    }

  if (strcmp (options->hostname, "server") != 0)
    {
      printf ("FAILED. Hostname not set correctly.\n");
      ret = EINVAL;
      goto done;
    }

  printf ("SUCCESS.\n");

  /*
   * Test 3: Valid FQDN with short hostname portion
   */
  printf ("Test 3: Valid FQDN 'web.example.com'. ");

  const char *argv_valid_fqdn[] = {
    "sscg", "--hostname", "web.example.com", NULL
  };
  ret = sscg_handle_arguments (tmp_ctx, 3, argv_valid_fqdn, &options);
  if (ret != EOK)
    {
      printf ("FAILED (ret=%d).\n", ret);
      goto done;
    }

  if (strcmp (options->hostname, "web.example.com") != 0)
    {
      printf ("FAILED. Hostname not set correctly.\n");
      ret = EINVAL;
      goto done;
    }

  printf ("SUCCESS.\n");

  /*
   * Test 4: FQDN with exactly 63-character hostname portion (MAX_HOST_LEN)
   * This should be accepted (at the limit)
   */
  printf ("Test 4: FQDN with 63-character hostname (at limit). ");

  /* Create a 63-character hostname portion */
  char hostname_63[100];
  snprintf (hostname_63,
            sizeof (hostname_63),
            "%s.example.com",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk");

  const char *argv_63chars[] = { "sscg", "--hostname", hostname_63, NULL };
  ret = sscg_handle_arguments (tmp_ctx, 3, argv_63chars, &options);
  if (ret != EOK)
    {
      printf ("FAILED (ret=%d).\n", ret);
      goto done;
    }

  printf ("SUCCESS.\n");

  /*
   * Test 5: FQDN with 64-character hostname portion (exceeds MAX_HOST_LEN)
   * This should be rejected
   */
  printf ("Test 5: FQDN with 64-character hostname (should reject). ");

  /* Create a 64-character hostname portion */
  char hostname_64[100];
  snprintf (
    hostname_64,
    sizeof (hostname_64),
    "%s.example.com",
    "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl");

  const char *argv_64chars[] = { "sscg", "--hostname", hostname_64, NULL };
  ret = sscg_handle_arguments (tmp_ctx, 3, argv_64chars, &options);
  if (ret == EOK)
    {
      printf ("FAILED. Should have rejected hostname with >63 char label.\n");
      ret = EINVAL;
      goto done;
    }

  /* Expected to fail - that's success for this test */
  printf ("SUCCESS (correctly rejected).\n");
  ret = EOK; /* Reset for next test */

  /*
   * Test 6: Long single-label hostname (>63 chars, no dot)
   * Should be REJECTED per RFC 1035 (all labels must be ≤ 63 characters)
   */
  printf ("Test 6: Long single-label hostname (>63 chars, should reject). ");

  const char *long_single[] = {
    "sscg",
    "--hostname",
    "thisisaverylonghostnamewithnodotsanditexceedsthesixtythreecharacterlimit",
    NULL
  };
  ret = sscg_handle_arguments (tmp_ctx, 3, long_single, &options);
  if (ret == EOK)
    {
      printf (
        "FAILED. Should have rejected single-label hostname >63 chars.\n");
      ret = EINVAL;
      goto done;
    }

  /* Expected to fail - that's success for this test */
  printf ("SUCCESS (correctly rejected).\n");
  ret = EOK; /* Reset for next test */

  /*
   * Test 6b: Single-label hostname at exactly 63 characters (should accept)
   */
  printf ("Test 6b: Single-label hostname at 63 chars (at limit). ");

  /* Create exactly 63 character hostname (no dot) */
  const char *hostname_63_nodot[] = {
    "sscg",
    "--hostname",
    "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
    NULL
  };
  ret = sscg_handle_arguments (tmp_ctx, 3, hostname_63_nodot, &options);
  if (ret != EOK)
    {
      printf (
        "FAILED (ret=%d). Should accept 63-char single-label hostname.\n",
        ret);
      goto done;
    }

  printf ("SUCCESS.\n");

  /*
   * Test 7: FQDN exceeding MAX_FQDN_LEN (255 characters)
   * Should be rejected
   */
  printf ("Test 7: FQDN exceeding 255 characters (should reject). ");

  /* Create a hostname longer than 255 chars */
  char long_fqdn[300];
  snprintf (long_fqdn,
            sizeof (long_fqdn),
            "verylongsubdomain.verylongsubdomain.verylongsubdomain."
            "verylongsubdomain.verylongsubdomain.verylongsubdomain."
            "verylongsubdomain.verylongsubdomain.verylongsubdomain."
            "verylongsubdomain.verylongsubdomain.verylongsubdomain."
            "verylongsubdomain.verylongsubdomain.example.com");

  const char *argv_long_fqdn[] = { "sscg", "--hostname", long_fqdn, NULL };
  ret = sscg_handle_arguments (tmp_ctx, 3, argv_long_fqdn, &options);
  if (ret == EOK)
    {
      printf ("FAILED. Should have rejected FQDN >255 chars.\n");
      ret = EINVAL;
      goto done;
    }

  /* Expected to fail - that's success for this test */
  printf ("SUCCESS (correctly rejected).\n");
  ret = EOK; /* Reset for next test */

  /*
   * Test 8: Hostname with multiple dots (subdomain)
   */
  printf ("Test 8: Hostname with subdomain 'api.staging.example.com'. ");

  const char *argv_subdomain[] = {
    "sscg", "--hostname", "api.staging.example.com", NULL
  };
  ret = sscg_handle_arguments (tmp_ctx, 3, argv_subdomain, &options);
  if (ret != EOK)
    {
      printf ("FAILED (ret=%d).\n", ret);
      goto done;
    }

  if (strcmp (options->hostname, "api.staging.example.com") != 0)
    {
      printf ("FAILED. Hostname not set correctly.\n");
      ret = EINVAL;
      goto done;
    }

  printf ("SUCCESS.\n");

  /*
   * Test 9: Edge case - hostname with dot at the end (trailing dot)
   */
  printf ("Test 9: Hostname with trailing dot 'server.example.com.'. ");

  const char *argv_trailing_dot[] = {
    "sscg", "--hostname", "server.example.com.", NULL
  };
  ret = sscg_handle_arguments (tmp_ctx, 3, argv_trailing_dot, &options);
  if (ret != EOK)
    {
      printf ("FAILED (ret=%d).\n", ret);
      goto done;
    }

  printf ("SUCCESS.\n");

  /*
   * Test 10: Regression test - ensure no crash with NULL hostname
   * This tests the original bug scenario specifically
   */
  printf ("Test 10: Memory safety check with various inputs. ");

  const char *test_hostnames[] = {
    "a",       "ab",    "localhost",  "host",
    "server",  "a.b",   "test.local", "hostname-with-dashes",
    "host123", "web01", "db-primary", "api",
    NULL
  };

  for (int i = 0; test_hostnames[i]; i++)
    {
      const char *argv_test[] = {
        "sscg", "--hostname", test_hostnames[i], NULL
      };
      ret = sscg_handle_arguments (tmp_ctx, 3, argv_test, &options);
      if (ret != EOK)
        {
          printf (
            "FAILED on hostname '%s' (ret=%d).\n", test_hostnames[i], ret);
          goto done;
        }
    }

  printf ("SUCCESS.\n");

  ret = EOK;

done:
  talloc_free (tmp_ctx);

  /* Check for memory leaks */
  printf ("\n=== Memory Leak Check ===\n");
  talloc_report_full (NULL, stderr);

  if (ret == EOK)
    {
      printf ("\n=== All Hostname Validation Tests PASSED ===\n");
    }
  else
    {
      printf ("\n=== Hostname Validation Tests FAILED ===\n");
    }

  return ret;
}
