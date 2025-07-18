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

    Copyright 2017-2023 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <errno.h>
#include <stdio.h>
#include <limits.h>

#include "include/bignum.h"

int
main (int argc, char **argv)
{
  int ret;
  unsigned long val;
  struct sscg_bignum *bn;
  size_t initial_blocks, final_blocks;

  /* Enable talloc leak reporting for memory leak detection */
  talloc_enable_leak_report_full ();

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  /* Record initial memory state for leak detection */
  initial_blocks = talloc_total_blocks (NULL);

  printf ("=== SSCG Init Bignum Test with Talloc Leak Detection ===\n");
  printf ("Initial talloc blocks: %zu\n", initial_blocks);

  /* Test 1: Initialize bignum with zero */
  printf ("Testing sscg_init_bignum with zero. ");

  ret = sscg_init_bignum (tmp_ctx, 0, &bn);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  printf ("Verifying bignum initialized to zero. ");
  val = BN_get_word (bn->bn);
  if (val != 0)
    {
      /* Bignum should always be initialized to 0 */
      printf ("FAILED.\n");
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 2: Initialize bignum with a non-zero value */
  printf ("Testing sscg_init_bignum with value 12345. ");

  ret = sscg_init_bignum (tmp_ctx, 12345, &bn);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  printf ("Verifying bignum initialized to 12345. ");
  val = BN_get_word (bn->bn);
  if (val != 12345)
    {
      printf ("FAILED. Expected 12345, got %lu.\n", val);
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 3: Initialize bignum with maximum unsigned long value */
  printf ("Testing sscg_init_bignum with ULONG_MAX. ");

  ret = sscg_init_bignum (tmp_ctx, ULONG_MAX, &bn);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  printf ("Verifying bignum initialized to ULONG_MAX. ");
  val = BN_get_word (bn->bn);
  if (val != ULONG_MAX && val != 0xffffffffL)
    {
      /* BN_get_word returns 0xffffffffL if the value is too large to fit */
      printf (
        "FAILED. Expected %lu or 0xffffffffL, got %lu.\n", ULONG_MAX, val);
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 4: Verify memory management by creating and destroying multiple bignums */
  printf ("Testing memory management with multiple bignums. ");

  struct sscg_bignum *bn1, *bn2, *bn3;

  ret = sscg_init_bignum (tmp_ctx, 100, &bn1);
  if (ret != EOK)
    goto memory_test_failed;

  ret = sscg_init_bignum (tmp_ctx, 200, &bn2);
  if (ret != EOK)
    goto memory_test_failed;

  ret = sscg_init_bignum (tmp_ctx, 300, &bn3);
  if (ret != EOK)
    goto memory_test_failed;

  /* Verify values are correct */
  if (BN_get_word (bn1->bn) != 100 || BN_get_word (bn2->bn) != 200 ||
      BN_get_word (bn3->bn) != 300)
    {
      goto memory_test_failed;
    }

  printf ("SUCCESS.\n");

  /* Test 5: Test with different value ranges */
  printf ("Testing various value ranges. ");

  struct sscg_bignum *bn_small, *bn_medium, *bn_large;

  ret = sscg_init_bignum (tmp_ctx, 1, &bn_small);
  if (ret != EOK)
    goto range_test_failed;

  ret = sscg_init_bignum (tmp_ctx, 65536, &bn_medium);
  if (ret != EOK)
    goto range_test_failed;

  ret = sscg_init_bignum (tmp_ctx, 4294967295UL, &bn_large);
  if (ret != EOK)
    goto range_test_failed;

  /* Verify values are correct */
  if (BN_get_word (bn_small->bn) != 1 ||
      BN_get_word (bn_medium->bn) != 65536 ||
      (BN_get_word (bn_large->bn) != 4294967295UL &&
       BN_get_word (bn_large->bn) != 0xffffffffL))
    {
      goto range_test_failed;
    }

  printf ("SUCCESS.\n");

  /* Test 6: Test talloc leak detection by creating isolated context */
  printf ("Testing talloc leak detection with isolated context. ");

  TALLOC_CTX *leak_test_ctx = talloc_new (NULL);
  if (!leak_test_ctx)
    {
      printf ("FAILED. Could not create leak test context.\n");
      ret = ENOMEM;
      goto done;
    }

  struct sscg_bignum *leak_test_bn;
  ret = sscg_init_bignum (leak_test_ctx, 999, &leak_test_bn);
  if (ret != EOK)
    {
      printf ("FAILED. Could not create bignum in leak test context.\n");
      talloc_free (leak_test_ctx);
      goto done;
    }

  /* Verify the value and then properly clean up */
  if (BN_get_word (leak_test_bn->bn) != 999)
    {
      printf ("FAILED. Leak test bignum has wrong value.\n");
      talloc_free (leak_test_ctx);
      ret = EINVAL;
      goto done;
    }

  /* Clean up the isolated context - this should free all associated memory */
  talloc_free (leak_test_ctx);

  printf ("SUCCESS.\n");

  ret = EOK;
  goto done;

memory_test_failed:
  printf ("FAILED.\n");
  ret = EINVAL;
  goto done;

range_test_failed:
  printf ("FAILED.\n");
  ret = EINVAL;

done:
  /* Clean up main test context */
  talloc_free (tmp_ctx);

  /* Check for memory leaks */
  final_blocks = talloc_total_blocks (NULL);
  printf ("\n=== Talloc Leak Detection Report ===\n");
  printf ("Initial talloc blocks: %zu\n", initial_blocks);
  printf ("Final talloc blocks: %zu\n", final_blocks);

  if (final_blocks > initial_blocks)
    {
      printf ("FAILED: Memory leak detected! %zu blocks leaked.\n",
              final_blocks - initial_blocks);
      printf ("Detailed leak report:\n");
      talloc_report_full (NULL, stderr);
      /* Fail the test when leaks are detected */
      ret = ENOMEM;
    }
  else
    {
      printf ("SUCCESS: No memory leaks detected.\n");
    }

  printf ("=== Test Complete ===\n");
  return ret;
}
