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

    Copyright 2019 by Stephen Gallagher <sgallagh@redhat.com>
*/


#include <assert.h>
#include <path_utils.h>
#include <string.h>
#include <talloc.h>

#include "include/io_utils.h"
#include "include/sscg.h"

int
sscg_normalize_path (TALLOC_CTX *mem_ctx,
                     const char *path,
                     char **_normalized_path)
{
  int ret;
  char *normalized_path = NULL;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  normalized_path = talloc_zero_array (tmp_ctx, char, PATH_MAX);
  CHECK_MEM (normalized_path);

  ret = make_normalized_absolute_path (normalized_path, PATH_MAX, path);
  CHECK_OK (ret);

  *_normalized_path = talloc_strdup (mem_ctx, normalized_path);
  CHECK_MEM (*_normalized_path);

  ret = EOK;

done:
  talloc_free (normalized_path);
  talloc_free (tmp_ctx);
  return ret;
}


static int
sscg_stream_destructor (TALLOC_CTX *ptr)
{
  struct sscg_stream *stream = talloc_get_type_abort (ptr, struct sscg_stream);

  BIO_free (stream->bio);

  return 0;
}


struct sscg_stream *
sscg_io_utils_get_stream_by_path (struct sscg_stream **streams,
                                  const char *normalized_path)
{
  struct sscg_stream *stream = NULL;

  /* First see if this path already exists in the list */
  for (int i = 0; (stream = streams[i]) && i < SSCG_NUM_FILE_TYPES; i++)
    {
      if (strcmp (normalized_path, stream->path) == 0)
        break;
    }

  return stream;
}


struct sscg_stream *
sscg_io_utils_get_stream_by_type (struct sscg_stream **streams,
                                  enum sscg_file_type filetype)
{
  struct sscg_stream *stream = NULL;

  /* First see if this path already exists in the list */
  for (int i = 0; (stream = streams[i]) && i < SSCG_NUM_FILE_TYPES; i++)
    {
      SSCG_LOG (SSCG_DEBUG,
                "Checking for 0x%.4x in 0x%.4x\n",
                (1 << filetype),
                stream->filetypes);
      if (stream->filetypes & (1 << filetype))
        {
          SSCG_LOG (SSCG_DEBUG,
                    "Found file type %s in %s\n",
                    sscg_get_file_type_name (filetype),
                    stream->path);
          break;
        }
    }

  if (!stream)
    SSCG_LOG (SSCG_DEBUG,
              "Could not locate file type: %s. Skipping.\n",
              sscg_get_file_type_name (filetype));

  return stream;
}


BIO *
sscg_io_utils_get_bio_by_type (struct sscg_stream **streams,
                               enum sscg_file_type filetype)
{
  struct sscg_stream *_tmp_stream =
    sscg_io_utils_get_stream_by_type (streams, filetype);

  if (_tmp_stream)
    {
      return _tmp_stream->bio;
    }

  return NULL;
}


const char *
sscg_io_utils_get_path_by_type (struct sscg_stream **streams,
                                enum sscg_file_type filetype)
{
  struct sscg_stream *_tmp_stream =
    sscg_io_utils_get_stream_by_type (streams, filetype);

  if (_tmp_stream)
    {
      return _tmp_stream->path;
    }

  return NULL;
}


int
sscg_io_utils_add_output_file (struct sscg_stream **streams,
                               enum sscg_file_type filetype,
                               const char *path,
                               int mode)
{
  int ret, i;
  TALLOC_CTX *tmp_ctx = NULL;
  struct sscg_stream *stream = NULL;
  char *normalized_path = NULL;

  /* If we haven't been passed a path, just return; it's probably an optional
   * output file
   */
  if (path == NULL)
    {
      SSCG_LOG (SSCG_DEBUG,
                "Got a NULL path with filetype: %s\n",
                sscg_get_file_type_name (filetype));
      return EOK;
    }

  tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  /* Get the normalized version of the path */
  ret = sscg_normalize_path (tmp_ctx, path, &normalized_path);
  CHECK_OK (ret);

  SSCG_LOG (SSCG_DEBUG,
            "%s file path: %s\n",
            sscg_get_file_type_name (filetype),
            normalized_path);

  /* First see if this path already exists in the list */
  stream = sscg_io_utils_get_stream_by_path (streams, normalized_path);

  if (stream == NULL)
    {
      /* The path wasn't found, so open it and create it */

      /* First advance the index to the end */
      for (i = 0; streams[i]; i++)
        ;

      /* This should never happen. The streams array should always be
       * sized to the maximum number of known types. If we are asked to add
       * more entries to the array than we have known file types, it must be
       * due to a bug.
       */
      assert (i < SSCG_NUM_FILE_TYPES);

      stream = talloc_zero (tmp_ctx, struct sscg_stream);
      CHECK_MEM (stream);
      talloc_set_destructor ((TALLOC_CTX *)stream, sscg_stream_destructor);

      stream->path = talloc_steal (stream, normalized_path);
      CHECK_MEM (stream->path);

      streams[i] = talloc_steal (streams, stream);
    }

  /* Always set the mode to the most-restrictive one requested */
  SSCG_LOG (SSCG_DEBUG, "Requested mode: %o\n", mode);
  if (stream->mode)
    stream->mode &= mode;
  else
    stream->mode = mode;
  SSCG_LOG (SSCG_DEBUG, "Actual mode: %o\n", stream->mode);

  /* Add the file type */
  stream->filetypes |= (1 << filetype);

  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}


enum io_utils_errors
{
  IO_UTILS_OK = 0,
  IO_UTILS_TOOMANYKEYS,
  IO_UTILS_DHPARAMS_NON_EXCLUSIVE,
  IO_UTILS_CRL_NON_EXCLUSIVE
};

static enum io_utils_errors
io_utils_validate (struct sscg_stream **streams)
{
  enum io_utils_errors ret;
  struct sscg_stream *stream = NULL;
  int keybits;

  for (int i = 0; (stream = streams[i]) && i < SSCG_NUM_FILE_TYPES; i++)
    {
      SSCG_LOG (SSCG_DEBUG, "filetypes: 0x%.4x\n", stream->filetypes);

      /* No file may contain two different private keys */
      /* First check if any private keys are in this file */
      if ((keybits = stream->filetypes & SSCG_FILE_TYPE_KEYS))
        {
          /* Next check if there is exactly one private key in the remainder.
           * The following bitwise magic checks whether the value is exactly a
           * power of two (meaning only one bit is set). If the result is
           * nonzero, more than one bit was set and we have been asked to
           * include multiple keys into the same file.
           */
          if (keybits & (keybits - 1))
            {
              ret = IO_UTILS_TOOMANYKEYS;
              goto done;
            }
        }

      /* The dhparams file may only contain dhparams */
      if ((stream->filetypes & (1 << SSCG_FILE_TYPE_DHPARAMS)) &&
          (stream->filetypes ^ (1 << SSCG_FILE_TYPE_DHPARAMS)))
        {
          ret = IO_UTILS_DHPARAMS_NON_EXCLUSIVE;
          goto done;
        }

      /* The CRL file may only contain certificate revocations */
      if ((stream->filetypes & (1 << SSCG_FILE_TYPE_CRL)) &&
          (stream->filetypes ^ (1 << SSCG_FILE_TYPE_CRL)))
        {
          ret = IO_UTILS_CRL_NON_EXCLUSIVE;
          goto done;
        }
    }

  ret = IO_UTILS_OK;

done:
  return ret;
}


int
sscg_io_utils_open_output_files (struct sscg_stream **streams, bool overwrite)
{
  int ret;
  TALLOC_CTX *tmp_ctx = NULL;
  enum io_utils_errors validation_result;
  char *create_mode = NULL;
  struct sscg_stream *stream = NULL;

  validation_result = io_utils_validate (streams);
  switch (validation_result)
    {
    case IO_UTILS_TOOMANYKEYS:
      SSCG_ERROR ("Attempted to output multiple keys to the same file.\n");
      ret = EINVAL;
      goto done;

    case IO_UTILS_CRL_NON_EXCLUSIVE:
      SSCG_ERROR ("The CRL file may not include other content.\n");
      ret = EINVAL;
      goto done;

    case IO_UTILS_DHPARAMS_NON_EXCLUSIVE:
      SSCG_ERROR ("The dhparams file may not include other content.\n");
      ret = EINVAL;
      goto done;

    default: break;
    }

  tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  if (overwrite)
    create_mode = talloc_strdup (tmp_ctx, "w");
  else
    create_mode = talloc_strdup (tmp_ctx, "wx");
  CHECK_MEM (create_mode);

  for (int i = 0; (stream = streams[i]) && i < SSCG_NUM_FILE_TYPES; i++)
    {
      SSCG_LOG (SSCG_DEBUG, "Opening %s\n", stream->path);
      stream->bio = BIO_new_file (stream->path, create_mode);
      CHECK_BIO (stream->bio, stream->path);
    }

  ret = EOK;
done:
  talloc_free (tmp_ctx);
  return ret;
}


int
sscg_io_utils_finalize_output_files (struct sscg_stream **streams)
{
  struct sscg_stream *stream = NULL;
  FILE *fp;

  for (int i = 0; (stream = streams[i]) && i < SSCG_NUM_FILE_TYPES; i++)
    {
      /* Set the final permissions mode */
      SSCG_LOG (SSCG_DEBUG,
                "Setting %s file permissions to %o\n",
                stream->path,
                stream->mode);
      BIO_get_fp (stream->bio, &fp);

      errno = 0;
      if (fchmod (fileno (fp), stream->mode) != 0)
        return errno;
    }

  return EOK;
}
