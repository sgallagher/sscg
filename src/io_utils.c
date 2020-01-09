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
#include "include/key.h"
#include "include/sscg.h"


/* Same as OpenSSL CLI */
#define MAX_PW_LEN 1024


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

  /* Zero out the memory before freeing it so we don't leak passwords */
  if (stream->passphrase)
    {
      memset (stream->passphrase, 0, strnlen (stream->passphrase, MAX_PW_LEN));
    }

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


/* This function takes a copy of a string into a talloc hierarchy and memsets
 * the original string to zeroes to avoid leaking it when that memory is freed.
 */
static char *
sscg_secure_string_steal (TALLOC_CTX *mem_ctx, char *src)
{
  char *dest = talloc_strdup (mem_ctx, src);

  memset ((void *)src, 0, strlen (src));

  return dest;
}


static int
validate_passphrase (struct sscg_stream *stream)
{
  /* Ignore non-key types */
  if (!(stream->filetypes & SSCG_FILE_TYPE_KEYS))
    return EOK;

  /* Ignore unset passwords; these will be prompted for when writing out the
   * key file
   */
  if (!stream->passphrase)
    return EOK;

  size_t pass_len = strnlen (stream->passphrase, SSCG_MAX_KEY_PASS_LEN + 1);

  if ((pass_len < SSCG_MIN_KEY_PASS_LEN) || (pass_len > SSCG_MAX_KEY_PASS_LEN))
    {
      SSCG_ERROR ("Passphrases must be between %d and %d characters. \n",
                  SSCG_MIN_KEY_PASS_LEN,
                  SSCG_MAX_KEY_PASS_LEN);
      return EINVAL;
    }
  return EOK;
}


static char *
sscg_read_pw_file (TALLOC_CTX *mem_ctx, char *path)
{
  int i;
  BIO *pwdbio = NULL;
  char tpass[MAX_PW_LEN];
  char *tmp = NULL;
  char *password = NULL;

  pwdbio = BIO_new_file (path, "r");
  if (pwdbio == NULL)
    {
      fprintf (stderr, "Can't open file %s\n", path);
      return NULL;
    }

  i = BIO_gets (pwdbio, tpass, MAX_PW_LEN);
  BIO_free_all (pwdbio);
  pwdbio = NULL;

  if (i <= 0)
    {
      fprintf (stderr, "Error reading password from BIO\n");
      return NULL;
    }

  tmp = strchr (tpass, '\n');
  if (tmp != NULL)
    *tmp = 0;

  password = talloc_strdup (mem_ctx, tpass);

  memset (tpass, 0, MAX_PW_LEN);

  return password;
}


int
sscg_io_utils_add_output_key (struct sscg_stream **streams,
                              enum sscg_file_type filetype,
                              const char *path,
                              int mode,
                              bool pass_prompt,
                              char *passphrase,
                              char *passfile)
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
      if (pass_prompt)
        {
          SSCG_ERROR (
            "Passphrase prompt requested for %s, but no file path provided.\n",
            sscg_get_file_type_name (filetype));
          return EINVAL;
        }

      if (passphrase)
        {
          SSCG_ERROR (
            "Passphrase provided for %s, but no file path provided.\n",
            sscg_get_file_type_name (filetype));
          return EINVAL;
        }

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


  /* Set the password options */
  stream->pass_prompt = pass_prompt;

  if (passphrase)
    {
      stream->passphrase = sscg_secure_string_steal (stream, passphrase);
      ret = validate_passphrase (stream);
      if (ret != EOK)
        goto done;
    }
  else if (passfile)
    {
      stream->passphrase = sscg_read_pw_file (stream, passfile);
      if (!stream->passphrase)
        {
          fprintf (stderr, "Failed to read passphrase from %s", passfile);
          ret = EIO;
          goto done;
        }
    }
  ret = validate_passphrase (stream);

  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}


int
sscg_io_utils_add_output_file (struct sscg_stream **streams,
                               enum sscg_file_type filetype,
                               const char *path,
                               int mode)
{
  return sscg_io_utils_add_output_key (
    streams, filetype, path, mode, false, NULL, NULL);
}


enum io_utils_errors
{
  IO_UTILS_OK = 0,
  IO_UTILS_TOOMANYKEYS,
  IO_UTILS_DHPARAMS_NON_EXCLUSIVE,
  IO_UTILS_CRL_NON_EXCLUSIVE,
  IO_UTILS_SVC_UNMATCHED,
  IO_UTILS_CLIENT_UNMATCHED,
  IO_UTILS_CA_UNMATCHED
};

static enum io_utils_errors
io_utils_validate (struct sscg_stream **streams)
{
  enum io_utils_errors ret;
  struct sscg_stream *stream = NULL;
  int keybits;
  int allbits = 0;

  for (int i = 0; (stream = streams[i]) && i < SSCG_NUM_FILE_TYPES; i++)
    {
      SSCG_LOG (SSCG_DEBUG, "filetypes: 0x%.4x\n", stream->filetypes);

      allbits |= stream->filetypes;

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

  SSCG_LOG (SSCG_DEBUG, "allbits: 0x%.4x\n", allbits);

  /* If the public or private key is present for the service cert, the other
   * must be present also
   */
  if ((allbits & SSCG_FILE_TYPE_SVC_TYPES) &&
      ((allbits & SSCG_FILE_TYPE_SVC_TYPES) != SSCG_FILE_TYPE_SVC_TYPES))
    {
      ret = IO_UTILS_SVC_UNMATCHED;
      goto done;
    }

  /* If the public or private key is present for the client cert, the other
   * must be present also
   */
  if ((allbits & SSCG_FILE_TYPE_CLIENT_TYPES) &&
      ((allbits & SSCG_FILE_TYPE_CLIENT_TYPES) != SSCG_FILE_TYPE_CLIENT_TYPES))
    {
      ret = IO_UTILS_CLIENT_UNMATCHED;
      goto done;
    }

  /* If the private key is present for the CA cert, the public key must be
   * present also
   */
  if ((allbits & (1 << SSCG_FILE_TYPE_CA_KEY)) &&
      !(allbits & (1 << SSCG_FILE_TYPE_CA)))
    {
      ret = IO_UTILS_CA_UNMATCHED;
      goto done;
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

    case IO_UTILS_SVC_UNMATCHED:
      SSCG_ERROR (
        "The service certificate must have both public and private key "
        "locations specified.\n");
      ret = EINVAL;
      goto done;

    case IO_UTILS_CLIENT_UNMATCHED:
      SSCG_ERROR (
        "The client certificate must have the public key location "
        "specified.\n");
      ret = EINVAL;
      goto done;

    case IO_UTILS_CA_UNMATCHED:
      SSCG_ERROR (
        "The CA certificate must have a public key location specified.\n");
      ret = EINVAL;
      goto done;

    case IO_UTILS_OK: break;
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
sscg_io_utils_write_privatekey (struct sscg_stream **streams,
                                enum sscg_file_type filetype,
                                struct sscg_evp_pkey *key,
                                struct sscg_options *options)
{
  int ret, sret;

  struct sscg_stream *stream =
    sscg_io_utils_get_stream_by_type (streams, filetype);
  if (stream)
    {
      /* This function has a default mechanism for prompting for the
       * password if it is passed a cipher and gets a NULL password.
       *
       * Only pass the cipher if we have a password or were instructed
       * to prompt for one.
       */
      sret = PEM_write_bio_PKCS8PrivateKey (
        stream->bio,
        key->evp_pkey,
        stream->pass_prompt || stream->passphrase ? options->cipher : NULL,
        stream->passphrase,
        stream->passphrase ? strlen (stream->passphrase) : 0,
        NULL,
        NULL);
      CHECK_SSL (sret, PEM_write_bio_PKCS8PrivateKey);
      ANNOUNCE_WRITE (filetype);
    }

  ret = EOK;

done:
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
