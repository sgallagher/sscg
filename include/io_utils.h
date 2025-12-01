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

    Copyright 2019-2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#ifndef _SSCG_IO_UTILS_H
#define _SSCG_IO_UTILS_H

#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <talloc.h>

#include "include/key.h"

#define CHECK_BIO(ptr, file)                                                  \
  do                                                                          \
    {                                                                         \
      if (!ptr)                                                               \
        {                                                                     \
          ret = errno;                                                        \
          fprintf (stderr,                                                    \
                   "Could not write to %s. Check directory permissions.\n",   \
                   file);                                                     \
          goto done;                                                          \
        }                                                                     \
    }                                                                         \
  while (0)


#define SSCG_CERT_DEFAULT_MODE 0644
#define SSCG_CERT_DEFAULT_MODE_HELP _ ("0644")
#define SSCG_KEY_DEFAULT_MODE 0600
#define SSCG_KEY_DEFAULT_MODE_HELP _ ("0600")

#define GET_BIO(_type) sscg_io_utils_get_bio_by_type (options->streams, _type)

#define GET_PATH(_type)                                                       \
  sscg_io_utils_get_path_by_type (options->streams, _type)

#define ANNOUNCE_WRITE(_type)                                                 \
  SSCG_LOG (SSCG_DEFAULT,                                                     \
            "Wrote %s to %s\n",                                               \
            sscg_get_file_type_name (_type),                                  \
            GET_PATH (_type));

enum sscg_file_type
{
  SSCG_FILE_TYPE_UNKNOWN = -1,
  SSCG_FILE_TYPE_CA,
  SSCG_FILE_TYPE_CA_KEY,
  SSCG_FILE_TYPE_SVC,
  SSCG_FILE_TYPE_SVC_KEY,
  SSCG_FILE_TYPE_CLIENT,
  SSCG_FILE_TYPE_CLIENT_KEY,
  SSCG_FILE_TYPE_CRL,
  SSCG_FILE_TYPE_DHPARAMS,

  SSCG_NUM_FILE_TYPES
};

#define SSCG_FILE_TYPE_KEYS                                                   \
  ((1 << SSCG_FILE_TYPE_CA_KEY) | (1 << SSCG_FILE_TYPE_SVC_KEY)               \
   | (1 << SSCG_FILE_TYPE_CLIENT_KEY))

#define SSCG_FILE_TYPE_SVC_TYPES                                              \
  ((1 << SSCG_FILE_TYPE_SVC) | (1 << SSCG_FILE_TYPE_SVC_KEY))

#define SSCG_FILE_TYPE_CLIENT_TYPES                                           \
  ((1 << SSCG_FILE_TYPE_CLIENT) | (1 << SSCG_FILE_TYPE_CLIENT_KEY))

#define SSCG_FILE_TYPE_CA_TYPES                                               \
  ((1 << SSCG_FILE_TYPE_CA) | (1 << SSCG_FILE_TYPE_CA_KEY))

#include "include/sscg.h"


struct sscg_stream
{
  BIO *bio;
  FILE *fp;
  char *path;
  int mode;
  int filetypes;

  bool pass_prompt;
  char *passphrase;
};


const char *
sscg_get_file_type_name (enum sscg_file_type _type);


int
sscg_io_utils_open_BIOs (struct sscg_stream **streams);


struct sscg_stream *
sscg_io_utils_get_stream_by_type (struct sscg_stream **streams,
                                  enum sscg_file_type filetype);


BIO *
sscg_io_utils_get_bio_by_type (struct sscg_stream **streams,
                               enum sscg_file_type filetype);


const char *
sscg_io_utils_get_path_by_type (struct sscg_stream **streams,
                                enum sscg_file_type filetype);


/**
 * sscg_io_utils_add_output_file:
 * @streams: The array of streams from the sscg_options
 * @filetype:
 * @path: The path to the file on disk.
 * @overwrite: Whether to overwrite the file if it already exists.
 * @mode: The filesystem mode this file should have when written to disk.
 * See chmod(1) for the possible values.
 *
 * Prepares the output file for the given filetype. If the file already exists,
 * and overwrite is false, the file is not opened and an error is returned.
 *
 * If the same output file is requested for multiple filetypes, the file is
 * opened once and used for all filetypes.
 */
int
sscg_io_utils_add_output_file (struct sscg_stream **streams,
                               enum sscg_file_type filetype,
                               const char *path,
                               bool overwrite,
                               int mode);


/**
 * sscg_io_utils_add_output_key:
 * @streams: The array of streams from the sscg_options
 * @filetype:
 * @path: The path to the file on disk.
 * @overwrite: Whether to overwrite the file if it already exists.
 * @mode: The filesystem mode this file should have when written to disk.
 * See chmod(1) for the possible values.
 * @pass_prompt: Whether the user should be prompted to enter a passphrase
 * interactively.
 * @passphrase: The passphrase supplied at the command line.
 * @passfile: The path to a file containing the passphrase.
 *
 * Prepares the output file for the given filetype. If the file already exists,
 * and overwrite is false, the file is not opened and an error is returned.
 *
 * If the same output file is requested for multiple filetypes, the file is
 * opened once and used for all filetypes.
 */
int
sscg_io_utils_add_output_key (struct sscg_stream **streams,
                              enum sscg_file_type filetype,
                              const char *path,
                              bool overwrite,
                              int mode,
                              bool pass_prompt,
                              char *passphrase,
                              char *passfile);


int
sscg_io_utils_write_privatekey (struct sscg_stream **streams,
                                enum sscg_file_type filetype,
                                struct sscg_evp_pkey *key,
                                struct sscg_options *options);

/* If this function fails, some of the output files may be left as 0400 */
int
sscg_io_utils_finalize_output_files (struct sscg_stream **streams);


int
sscg_io_utils_truncate_output_files (struct sscg_stream **streams);

/* Clean up output files if we are exiting early */
void
sscg_io_utils_delete_output_files (struct sscg_stream **streams);

#endif /* _SSCG_IO_UTILS_H */
