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

#include "include/io_utils.h"

static struct sscg_stream *
make_stream (TALLOC_CTX *mem_ctx, int filetypes, const char *path)
{
  struct sscg_stream *stream = talloc_zero (mem_ctx, struct sscg_stream);

  if (!stream)
    {
      return NULL;
    }

  stream->filetypes = filetypes;
  stream->path = talloc_strdup (stream, path);
  if (!stream->path)
    {
      talloc_free (stream);
      return NULL;
    }

  return stream;
}

int
main (int argc, char **argv)
{
  int ret = EOK;
  TALLOC_CTX *tmp_ctx = NULL;
  struct sscg_stream **streams = NULL;
  enum io_utils_errors validation;

  talloc_enable_leak_report_full ();

  tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  streams =
    talloc_zero_array (tmp_ctx, struct sscg_stream *, SSCG_NUM_FILE_TYPES);
  if (!streams)
    {
      ret = ENOMEM;
      goto done;
    }

  printf ("=== SSCG io_utils_validate() Regression Test ===\n\n");

  printf ("Test 1: dhparams-only output file. ");
  streams[0] = make_stream (
    tmp_ctx, (1 << SSCG_FILE_TYPE_DHPARAMS), "/tmp/dhparams-only.pem");
  if (!streams[0])
    {
      printf ("FAILED (setup).\n");
      ret = ENOMEM;
      goto done;
    }

  validation = sscg_io_utils_validate (streams);
  if (validation != IO_UTILS_OK)
    {
      printf ("FAILED (expected IO_UTILS_OK, got %d).\n", validation);
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS.\n");

  talloc_free (streams[0]);
  streams[0] = NULL;

  printf ("Test 2: dhparams combined with CA cert in one file. ");
  streams[0] =
    make_stream (tmp_ctx,
                 (1 << SSCG_FILE_TYPE_DHPARAMS) | (1 << SSCG_FILE_TYPE_CA),
                 "/tmp/dhparams-and-ca.pem");
  if (!streams[0])
    {
      printf ("FAILED (setup).\n");
      ret = ENOMEM;
      goto done;
    }

  validation = sscg_io_utils_validate (streams);
  if (validation != IO_UTILS_DHPARAMS_NON_EXCLUSIVE)
    {
      printf ("FAILED (expected IO_UTILS_DHPARAMS_NON_EXCLUSIVE, got %d).\n",
              validation);
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS.\n");

  talloc_free (streams[0]);
  streams[0] = NULL;

  printf ("Test 3: dhparams and service cert in separate files. ");
  streams[0] =
    make_stream (tmp_ctx, (1 << SSCG_FILE_TYPE_DHPARAMS), "/tmp/dhparams.pem");
  streams[1] =
    make_stream (tmp_ctx,
                 (1 << SSCG_FILE_TYPE_SVC) | (1 << SSCG_FILE_TYPE_SVC_KEY),
                 "/tmp/service.pem");
  if (!streams[0] || !streams[1])
    {
      printf ("FAILED (setup).\n");
      ret = ENOMEM;
      goto done;
    }

  validation = sscg_io_utils_validate (streams);
  if (validation != IO_UTILS_OK)
    {
      printf ("FAILED (expected IO_UTILS_OK, got %d).\n", validation);
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS.\n");

done:
  talloc_free (tmp_ctx);
  return ret;
}
