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

#ifndef _SSCG_IO_UTILS_H
#define _SSCG_IO_UTILS_H

#include <openssl/ssl.h>
#include <stdbool.h>
#include <talloc.h>

#include "include/sscg.h"


struct sscg_stream
{
  BIO *bio;
  char *path;
  int mode;
  int filetypes;
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
 * @overwrite: If true, replace any existing file at @normalized_path. If
 * false, opening will fail if it already exists and return an error.
 *
 * Prepares all output filenames to be opened. Files are not created until
 * sscg_io_utils_open_output_files() is called.
 */
int
sscg_io_utils_add_output_file (struct sscg_stream **streams,
                               enum sscg_file_type filetype,
                               const char *path,
                               int mode);


int
sscg_io_utils_open_output_files (struct sscg_stream **streams, bool overwrite);

/* If this function fails, some of the output files may be left as 0400 */
int
sscg_io_utils_finalize_output_files (struct sscg_stream **streams);


#endif /* _SSCG_IO_UTILS_H */
