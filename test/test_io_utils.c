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

    Copyright 2017-2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <limits.h>
#include <string.h>

#include "include/io_utils.h"
#include "include/sscg.h"

static int
setup_test_environment (TALLOC_CTX *mem_ctx, const char *test_dir)
{
  char *path = NULL;
  char *linkpath = NULL;
  char *targetpath = NULL;

  /* test_dir is already created by mkdtemp() in main() */

  /* Create subdirectories */
  path = talloc_asprintf (mem_ctx, "%s/testdir", test_dir);
  if (!path)
    return ENOMEM;
  if (mkdir (path, 0755) != 0)
    {
      fprintf (stderr, "Failed to create testdir\n");
      return errno;
    }
  talloc_zfree (path);

  path = talloc_asprintf (mem_ctx, "%s/realdir", test_dir);
  if (!path)
    return ENOMEM;
  if (mkdir (path, 0755) != 0)
    {
      fprintf (stderr, "Failed to create realdir\n");
      return errno;
    }
  talloc_zfree (path);

  path = talloc_asprintf (mem_ctx, "%s/subdir", test_dir);
  if (!path)
    return ENOMEM;
  if (mkdir (path, 0755) != 0)
    {
      fprintf (stderr, "Failed to create subdir\n");
      return errno;
    }
  talloc_zfree (path);

  /* Create test files */
  path = talloc_asprintf (mem_ctx, "%s/testdir/testfile.txt", test_dir);
  if (!path)
    return ENOMEM;
  FILE *fp = fopen (path, "w");
  if (!fp)
    {
      fprintf (stderr, "Failed to create testfile.txt\n");
      return errno;
    }
  fprintf (fp, "test content\n");
  fclose (fp);
  talloc_zfree (path);

  path = talloc_asprintf (mem_ctx, "%s/testdir/regularfile.txt", test_dir);
  if (!path)
    return ENOMEM;
  fp = fopen (path, "w");
  if (!fp)
    {
      fprintf (stderr, "Failed to create regularfile.txt\n");
      return errno;
    }
  fprintf (fp, "regular file\n");
  fclose (fp);
  talloc_zfree (path);

  path = talloc_asprintf (mem_ctx, "%s/testdir/realfile.txt", test_dir);
  if (!path)
    return ENOMEM;
  fp = fopen (path, "w");
  if (!fp)
    {
      fprintf (stderr, "Failed to create realfile.txt\n");
      return errno;
    }
  fprintf (fp, "real file\n");
  fclose (fp);
  talloc_zfree (path);

  path = talloc_asprintf (mem_ctx, "%s/realdir/testfile.txt", test_dir);
  if (!path)
    return ENOMEM;
  fp = fopen (path, "w");
  if (!fp)
    {
      fprintf (stderr, "Failed to create realdir/testfile.txt\n");
      return errno;
    }
  fprintf (fp, "test in realdir\n");
  fclose (fp);
  talloc_zfree (path);

  /* Create symlinks */
  /* Directory symlink */
  linkpath = talloc_asprintf (mem_ctx, "%s/linkdir", test_dir);
  if (!linkpath)
    return ENOMEM;
  targetpath = talloc_asprintf (mem_ctx, "%s/realdir", test_dir);
  if (!targetpath)
    return ENOMEM;
  if (symlink (targetpath, linkpath) != 0)
    {
      fprintf (stderr, "Failed to create linkdir symlink\n");
      return errno;
    }
  talloc_zfree (linkpath);
  talloc_zfree (targetpath);

  /* File symlink to existing file */
  linkpath = talloc_asprintf (mem_ctx, "%s/testdir/linkfile", test_dir);
  if (!linkpath)
    return ENOMEM;
  if (symlink ("realfile.txt", linkpath) != 0)
    {
      fprintf (stderr, "Failed to create linkfile symlink\n");
      return errno;
    }
  talloc_zfree (linkpath);

  /* Broken symlink */
  linkpath = talloc_asprintf (mem_ctx, "%s/testdir/brokenlink", test_dir);
  if (!linkpath)
    return ENOMEM;
  if (symlink ("nonexistent.txt", linkpath) != 0)
    {
      fprintf (stderr, "Failed to create brokenlink symlink\n");
      return errno;
    }
  talloc_zfree (linkpath);

  return EOK;
}

static void
cleanup_test_environment (TALLOC_CTX *mem_ctx, const char *test_dir)
{
  char *cmd = talloc_asprintf (mem_ctx, "rm -rf %s", test_dir);
  if (cmd)
    {
      (void)system (cmd);
      talloc_zfree (cmd);
    }
}

int
main (int argc, char **argv)
{
  int ret = EOK;
  char *normalized_path = NULL;
  char original_cwd[PATH_MAX];
  char *expected_path = NULL;
  char *test_path = NULL;
  char *test_dir = NULL;
  size_t initial_blocks, final_blocks;

  (void)argc; /* Unused */
  (void)argv; /* Unused */

  /* Save current working directory */
  if (getcwd (original_cwd, PATH_MAX) == NULL)
    {
      fprintf (stderr, "Failed to get current working directory\n");
      return errno;
    }

  /* Enable talloc leak reporting */
  talloc_enable_leak_report_full ();
  initial_blocks = talloc_total_blocks (NULL);

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  printf ("=== SSCG io_utils Test Suite ===\n");
  printf ("Initial talloc blocks: %zu\n", initial_blocks);

  /* Create temporary directory */
  test_dir = talloc_strdup (tmp_ctx, "/tmp/sscg_test_io_utils.XXXXXX");
  if (!test_dir)
    {
      ret = ENOMEM;
      goto done;
    }
  if (mkdtemp (test_dir) == NULL)
    {
      fprintf (stderr,
               "Failed to create temporary directory: %s\n",
               strerror (errno));
      ret = errno;
      goto done;
    }
  printf ("Using test directory: %s\n", test_dir);

  /* Setup test environment */
  printf ("Setting up test environment... ");
  ret = setup_test_environment (tmp_ctx, test_dir);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 1: Absolute path with no symlinks in directory */
  printf ("Test 1: Absolute path with no symlinks in directory... ");
  test_path = talloc_asprintf (tmp_ctx, "%s/testdir/testfile.txt", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  ret = sscg_normalize_path (tmp_ctx, test_path, &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      goto done;
    }
  if (strcmp (normalized_path, test_path) != 0)
    {
      printf ("FAILED (expected %s, got %s).\n", test_path, normalized_path);
      ret = EINVAL;
      goto done;
    }
  talloc_zfree (test_path);
  printf ("SUCCESS.\n");

  /* Test 2: Absolute path with symlink in directory */
  printf ("Test 2: Absolute path with symlink in directory... ");
  test_path = talloc_asprintf (tmp_ctx, "%s/linkdir/testfile.txt", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  expected_path =
    talloc_asprintf (tmp_ctx, "%s/realdir/testfile.txt", test_dir);
  if (!expected_path)
    {
      ret = ENOMEM;
      goto done;
    }
  ret = sscg_normalize_path (tmp_ctx, test_path, &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      goto done;
    }
  if (strcmp (normalized_path, expected_path) != 0)
    {
      printf (
        "FAILED (expected %s, got %s).\n", expected_path, normalized_path);
      ret = EINVAL;
      goto done;
    }
  talloc_zfree (test_path);
  talloc_zfree (expected_path);
  printf ("SUCCESS.\n");

  /* Test 3: Absolute path with no symlinks in filename */
  printf ("Test 3: Absolute path with no symlinks in filename... ");
  test_path =
    talloc_asprintf (tmp_ctx, "%s/testdir/regularfile.txt", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  ret = sscg_normalize_path (tmp_ctx, test_path, &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      goto done;
    }
  if (strcmp (normalized_path, test_path) != 0)
    {
      printf ("FAILED (expected %s, got %s).\n", test_path, normalized_path);
      ret = EINVAL;
      goto done;
    }
  talloc_zfree (test_path);
  printf ("SUCCESS.\n");

  /* Test 4: Absolute path with symlink for filename (existing target) */
  printf ("Test 4: Absolute path with symlink for filename (existing)... ");
  test_path = talloc_asprintf (tmp_ctx, "%s/testdir/linkfile", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  expected_path = talloc_asprintf (tmp_ctx, "%s/testdir/linkfile", test_dir);
  if (!expected_path)
    {
      ret = ENOMEM;
      goto done;
    }
  ret = sscg_normalize_path (tmp_ctx, test_path, &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      goto done;
    }
  if (strcmp (normalized_path, expected_path) != 0)
    {
      printf (
        "FAILED (expected %s, got %s).\n", expected_path, normalized_path);
      ret = EINVAL;
      goto done;
    }
  talloc_zfree (test_path);
  talloc_zfree (expected_path);
  printf ("SUCCESS.\n");

  /* Test 5: Absolute path with symlink for filename (non-existent target) */
  printf ("Test 5: Absolute path with symlink for filename (broken)... ");
  test_path = talloc_asprintf (tmp_ctx, "%s/testdir/brokenlink", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  expected_path = talloc_asprintf (tmp_ctx, "%s/testdir/brokenlink", test_dir);
  if (!expected_path)
    {
      ret = ENOMEM;
      goto done;
    }
  ret = sscg_normalize_path (tmp_ctx, test_path, &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      goto done;
    }
  if (strcmp (normalized_path, expected_path) != 0)
    {
      printf (
        "FAILED (expected %s, got %s).\n", expected_path, normalized_path);
      ret = EINVAL;
      goto done;
    }
  talloc_zfree (test_path);
  talloc_zfree (expected_path);
  printf ("SUCCESS.\n");

  /* Test 6: Relative path (./) without symlinks */
  printf ("Test 6: Relative path (./) without symlinks... ");
  test_path = talloc_asprintf (tmp_ctx, "%s/testdir", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  if (chdir (test_path) != 0)
    {
      printf ("FAILED (could not change directory).\n");
      ret = errno;
      goto done;
    }
  talloc_zfree (test_path);
  ret = sscg_normalize_path (tmp_ctx, "./testfile.txt", &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      chdir (original_cwd);
      goto done;
    }
  expected_path =
    talloc_asprintf (tmp_ctx, "%s/testdir/testfile.txt", test_dir);
  if (!expected_path)
    {
      ret = ENOMEM;
      chdir (original_cwd);
      goto done;
    }
  if (strcmp (normalized_path, expected_path) != 0)
    {
      printf (
        "FAILED (expected %s, got %s).\n", expected_path, normalized_path);
      ret = EINVAL;
      chdir (original_cwd);
      goto done;
    }
  talloc_zfree (expected_path);
  chdir (original_cwd);
  printf ("SUCCESS.\n");

  /* Test 7: Relative path (./) with symlinks in directory */
  printf ("Test 7: Relative path (./) with symlinks in directory... ");
  test_path = talloc_asprintf (tmp_ctx, "%s/linkdir", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  if (chdir (test_path) != 0)
    {
      printf ("FAILED (could not change directory).\n");
      ret = errno;
      goto done;
    }
  talloc_zfree (test_path);
  ret = sscg_normalize_path (tmp_ctx, "./testfile.txt", &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      chdir (original_cwd);
      goto done;
    }
  expected_path =
    talloc_asprintf (tmp_ctx, "%s/realdir/testfile.txt", test_dir);
  if (!expected_path)
    {
      ret = ENOMEM;
      chdir (original_cwd);
      goto done;
    }
  if (strcmp (normalized_path, expected_path) != 0)
    {
      printf (
        "FAILED (expected %s, got %s).\n", expected_path, normalized_path);
      ret = EINVAL;
      chdir (original_cwd);
      goto done;
    }
  talloc_zfree (expected_path);
  chdir (original_cwd);
  printf ("SUCCESS.\n");

  /* Test 8: Relative path (../) without symlinks */
  printf ("Test 8: Relative path (../) without symlinks... ");
  test_path = talloc_asprintf (tmp_ctx, "%s/testdir", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  if (chdir (test_path) != 0)
    {
      printf ("FAILED (could not change directory).\n");
      ret = errno;
      goto done;
    }
  talloc_zfree (test_path);
  ret =
    sscg_normalize_path (tmp_ctx, "../realdir/testfile.txt", &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      chdir (original_cwd);
      goto done;
    }
  expected_path =
    talloc_asprintf (tmp_ctx, "%s/realdir/testfile.txt", test_dir);
  if (!expected_path)
    {
      ret = ENOMEM;
      chdir (original_cwd);
      goto done;
    }
  if (strcmp (normalized_path, expected_path) != 0)
    {
      printf (
        "FAILED (expected %s, got %s).\n", expected_path, normalized_path);
      ret = EINVAL;
      chdir (original_cwd);
      goto done;
    }
  talloc_zfree (expected_path);
  chdir (original_cwd);
  printf ("SUCCESS.\n");

  /* Test 9: Relative path (../) with symlinks in directory */
  printf ("Test 9: Relative path (../) with symlinks in directory... ");
  test_path = talloc_asprintf (tmp_ctx, "%s/linkdir", test_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  if (chdir (test_path) != 0)
    {
      printf ("FAILED (could not change directory).\n");
      ret = errno;
      goto done;
    }
  talloc_zfree (test_path);
  ret =
    sscg_normalize_path (tmp_ctx, "../testdir/testfile.txt", &normalized_path);
  if (ret != EOK)
    {
      printf ("FAILED (returned error %d).\n", ret);
      chdir (original_cwd);
      goto done;
    }
  expected_path =
    talloc_asprintf (tmp_ctx, "%s/testdir/testfile.txt", test_dir);
  if (!expected_path)
    {
      ret = ENOMEM;
      chdir (original_cwd);
      goto done;
    }
  if (strcmp (normalized_path, expected_path) != 0)
    {
      printf (
        "FAILED (expected %s, got %s).\n", expected_path, normalized_path);
      ret = EINVAL;
      chdir (original_cwd);
      goto done;
    }
  talloc_zfree (expected_path);
  chdir (original_cwd);
  printf ("SUCCESS.\n");

  /* Test 10: Path exceeding PATH_MAX in directory portion */
  printf ("Test 10: Path exceeding PATH_MAX in directory portion... ");
  /* Create a very long directory path that exceeds PATH_MAX */
  char long_dir[PATH_MAX + 100];
  memset (long_dir, 'a', PATH_MAX + 50);
  long_dir[PATH_MAX + 50] = '\0';
  test_path = talloc_asprintf (tmp_ctx, "/%s", long_dir);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  ret = sscg_normalize_path (tmp_ctx, test_path, &normalized_path);
  if (ret != ENOENT && ret != ENAMETOOLONG)
    {
      /* We expect either ENOENT (directory doesn't exist) or ENAMETOOLONG */
      printf ("FAILED (expected ENOENT or ENAMETOOLONG, got %d).\n", ret);
      ret = EINVAL;
      goto done;
    }
  talloc_zfree (test_path);
  ret = EOK;
  printf ("SUCCESS.\n");

  /* Test 11: Path exceeding PATH_MAX including filename */
  printf ("Test 11: Path exceeding PATH_MAX including filename... ");
  /* Create a path where directory + filename exceeds PATH_MAX */
  char long_filename[PATH_MAX];
  memset (long_filename, 'b', PATH_MAX - 1);
  long_filename[PATH_MAX - 1] = '\0';
  test_path = talloc_asprintf (tmp_ctx, "%s/%s", test_dir, long_filename);
  if (!test_path)
    {
      ret = ENOMEM;
      goto done;
    }
  ret = sscg_normalize_path (tmp_ctx, test_path, &normalized_path);
  if (ret != ENAMETOOLONG)
    {
      printf ("FAILED (expected ENAMETOOLONG, got %d).\n", ret);
      ret = EINVAL;
      goto done;
    }
  talloc_zfree (test_path);
  ret = EOK;
  printf ("SUCCESS.\n");

  /* Test 12: NULL path */
  printf ("Test 12: NULL path... ");
  ret = sscg_normalize_path (tmp_ctx, NULL, &normalized_path);
  if (ret != EINVAL)
    {
      printf ("FAILED (expected EINVAL, got %d).\n", ret);
      ret = EINVAL;
      goto done;
    }
  ret = EOK;
  printf ("SUCCESS.\n");

  /* Test 13: Empty string path */
  printf ("Test 13: Empty string path... ");
  ret = sscg_normalize_path (tmp_ctx, "", &normalized_path);
  if (ret != EINVAL)
    {
      printf ("FAILED (expected EINVAL, got %d).\n", ret);
      ret = EINVAL;
      goto done;
    }
  ret = EOK;
  printf ("SUCCESS.\n");

  /* Test 14: Non-existent parent directory */
  printf ("Test 14: Non-existent parent directory... ");
  ret = sscg_normalize_path (
    tmp_ctx, "/nonexistent_dir_12345/subdir/file.txt", &normalized_path);
  if (ret != ENOENT)
    {
      printf ("FAILED (expected ENOENT, got %d).\n", ret);
      ret = EINVAL;
      goto done;
    }
  ret = EOK;
  printf ("SUCCESS.\n");

  printf ("\n=== All tests passed! ===\n");

done:
  /* Cleanup */
  cleanup_test_environment (tmp_ctx, test_dir);
  talloc_free (tmp_ctx);

  /* Restore original working directory */
  chdir (original_cwd);

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
      ret = ENOMEM;
    }
  else
    {
      printf ("SUCCESS: No memory leaks detected.\n");
    }

  printf ("=== Test Complete ===\n");
  return ret;
}
