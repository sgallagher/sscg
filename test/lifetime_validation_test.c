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

#include <errno.h>
#include <stdio.h>
#include <talloc.h>

#include "include/sscg.h"

static int
expect_lifetime_ok (TALLOC_CTX *tmp_ctx,
                    const char *label,
                    const char **argv,
                    int argc,
                    int expected_lifetime)
{
  int ret;
  struct sscg_options *options = NULL;

  printf ("%s. ", label);
  ret = sscg_handle_arguments (tmp_ctx, argc, argv, &options);
  if (ret != EOK)
    {
      printf ("FAILED (ret=%d, expected success).\n", ret);
      return ret;
    }

  if (options->lifetime != expected_lifetime)
    {
      printf ("FAILED (lifetime=%d, expected %d).\n",
              options->lifetime,
              expected_lifetime);
      return EINVAL;
    }

  printf ("SUCCESS.\n");
  return EOK;
}

static int
expect_lifetime_rejected (TALLOC_CTX *tmp_ctx,
                          const char *label,
                          const char **argv,
                          int argc)
{
  int ret;
  struct sscg_options *options = NULL;

  printf ("%s. ", label);
  ret = sscg_handle_arguments (tmp_ctx, argc, argv, &options);
  if (ret == EOK)
    {
      printf ("FAILED (should have been rejected).\n");
      return EINVAL;
    }

  if (ret != EINVAL)
    {
      printf ("FAILED (ret=%d, expected EINVAL).\n", ret);
      return ret;
    }

  printf ("SUCCESS (correctly rejected).\n");
  return EOK;
}

int
main (int argc, char **argv)
{
  int ret = EOK;
  TALLOC_CTX *tmp_ctx = NULL;

  talloc_enable_leak_report_full ();

  tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  printf ("=== SSCG Certificate Lifetime Validation Test ===\n\n");

  const char *argv_valid[] = { "sscg", "--lifetime", "365", NULL };
  ret = expect_lifetime_ok (
    tmp_ctx, "Test 1: lifetime 365 (in range)", argv_valid, 3, 365);
  if (ret != EOK)
    {
      goto done;
    }

  const char *argv_zero[] = { "sscg", "--lifetime", "0", NULL };
  ret = expect_lifetime_rejected (
    tmp_ctx, "Test 2: lifetime 0 (should reject)", argv_zero, 3);
  if (ret != EOK)
    {
      goto done;
    }

  const char *argv_negative[] = { "sscg", "--lifetime", "-1", NULL };
  ret = expect_lifetime_rejected (
    tmp_ctx, "Test 3: lifetime -1 (should reject)", argv_negative, 3);
  if (ret != EOK)
    {
      goto done;
    }

  const char *argv_too_large[] = { "sscg", "--lifetime", "3651", NULL };
  ret = expect_lifetime_rejected (
    tmp_ctx, "Test 4: lifetime 3651 (should reject)", argv_too_large, 3);
  if (ret != EOK)
    {
      goto done;
    }

  const char *argv_non_numeric[] = {
    "sscg", "--lifetime", "not-a-number", NULL
  };
  ret =
    expect_lifetime_rejected (tmp_ctx,
                              "Test 5: non-numeric lifetime (should reject)",
                              argv_non_numeric,
                              3);
  if (ret != EOK)
    {
      goto done;
    }

  const char *argv_boundary_min[] = { "sscg", "--lifetime", "1", NULL };
  ret = expect_lifetime_ok (
    tmp_ctx, "Test 6: lifetime 1 (minimum)", argv_boundary_min, 3, 1);
  if (ret != EOK)
    {
      goto done;
    }

  const char *argv_boundary_max[] = { "sscg", "--lifetime", "3650", NULL };
  ret = expect_lifetime_ok (tmp_ctx,
                            "Test 7: lifetime 3650 (maximum)",
                            argv_boundary_max,
                            3,
                            SSCG_MAX_CERT_LIFETIME);

done:
  talloc_free (tmp_ctx);
  return ret;
}
