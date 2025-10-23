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
#include <talloc.h>

#include "include/key.h"
#include "include/sscg.h"


enum sscg_cert_file_format
{
  SSCG_CERT_FILE_FORMAT_PEM = 0,
  SSCG_CERT_FILE_FORMAT_DER,
  
  SSCG_NUM_CERT_FILE_FORMATS
};


struct sscg_stream
{
  BIO *bio;
  char *path;
  int mode;
  int filetypes;
  enum sscg_cert_file_format format;

  bool pass_prompt;
  char *passphrase;
};


int
sscg_normalize_path (TALLOC_CTX *mem_ctx,
                     const char *path,
                     char **_normalized_path);


struct sscg_stream *
sscg_io_utils_get_stream_by_path (struct sscg_stream **streams,
                                  const char *normalized_path);


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
 * @mode: The filesystem mode this file should have when written to disk.
 * See chmod(1) for the possible values.
 *
 * Prepares all output filenames to be opened. Files are not created until
 * sscg_io_utils_open_output_files() is called.
 */
int
sscg_io_utils_add_output_file (struct sscg_stream **streams,
                               enum sscg_file_type filetype,
                               const char *path,
                               int mode);


/**
 * sscg_io_utils_add_output_key:
 * @streams: The array of streams from the sscg_options
 * @filetype:
 * @path: The path to the file on disk.
 * @mode: The filesystem mode this file should have when written to disk.
 * See chmod(1) for the possible values.
 * @pass_prompt: Whether the user should be prompted to enter a passphrase
 * interactively.
 * @passphrase: The passphrase supplied at the command line.
 * @passfile: The path to a file containing the passphrase.
 *
 * Prepares all output filenames to be opened. Files are not created until
 * sscg_io_utils_open_output_files() is called.
 */
int
sscg_io_utils_add_output_key (struct sscg_stream **streams,
                              enum sscg_file_type filetype,
                              const char *path,
                              int mode,
                              bool pass_prompt,
                              char *passphrase,
                              char *passfile);


int
sscg_io_utils_open_output_files (struct sscg_stream **streams, bool overwrite);

int
sscg_io_utils_write_privatekey (struct sscg_stream **streams,
                                enum sscg_file_type filetype,
                                struct sscg_evp_pkey *key,
                                struct sscg_options *options);

/* If this function fails, some of the output files may be left as 0400 */
int
sscg_io_utils_finalize_output_files (struct sscg_stream **streams);


#endif /* _SSCG_IO_UTILS_H */
