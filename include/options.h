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

#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <stdbool.h>
#include "openssl/evp.h"
#include <talloc.h>
#include <netinet/in.h>


#include "include/sscg.h"


struct sscg_global_options;
struct sscg_ca_options;
struct sscg_cert_options;


struct sscg4_options
{
  struct sscg_global_options *global_options;
  struct sscg_cert_options *ca_options;
  struct sscg_cert_options **cert_options;
};

struct sscg_global_options
{
  enum sscg_verbosity verbosity;
};


enum sscg_key_type
{
  SSCG_KEY_TYPE_RSA,
  SSCG_KEY_TYPE_EC,
  SSCG_KEY_TYPE_MLDSA,
};

struct sscg_subject_info
{
  char *country;
  char *state;
  char *locality;
  char *org;
  char *org_unit;
  char *email;
  char *hostname;
  char **subject_alt_names;
};

struct sscg_cert_options
{
  enum sscg_cert_type cert_type;

  char *cert_file;
  int cert_file_mode;

  char *cert_key_file;
  int cert_key_mode;

  const EVP_MD *hash_fn;

  bool key_pass_prompt;
  char *key_password;
  char *key_passfile;

  struct sscg_subject_info *subject_info;

  union
  {
    int rsa_strength;
    int mldsa_nist_level;
    char *ec_curve;
  } key_options;
};


/**
 * @brief Process command-line arguments and populate the options structure.
 *
 * This function parses the command-line arguments provided to the program,
 * validates them, and fills the given sscg_options structure with the
 * corresponding values. It handles all supported options, including certificate
 * subject information, cryptographic parameters, and operational flags.
 *
 * @param mem_ctx  TALLOC context for memory allocations.
 * @param argc     Argument count.
 * @param argv     Argument vector.
 * @param options  Output pointer to the populated sscg_options structure.
 *
 * @return 0 on success, or a negative error code on failure.
 */

int
sscg_process_arguments (TALLOC_CTX *mem_ctx,
                        int argc,
                        const char **argv,
                        struct sscg4_options **options);


/**
 * @brief Set the subject information for a certificate.
 *
 * This function populates the subject fields of the given certificate options
 * structure with the provided values. All arguments must be provided. A NULL
 * value for a field will remove it from the certificate.
 *
 * @param cert_options Pointer to the certificate options structure to update.
 * @param country      Country code (C) for the subject.
 * @param state        State or province (ST) for the subject.
 * @param locality     Locality (L) for the subject.
 * @param org          Organization (O) for the subject.
 * @param org_unit     Organizational unit (OU) for the subject.
 * @param email        Email address for the subject.
 * @param hostname     Hostname (CN) for the subject.
 *
 * @return 0 on success, or a negative error code on failure.
 */

int
sscg_set_cert_subject_info (struct sscg_cert_options *cert_options,
                            const char *country,
                            const char *state,
                            const char *locality,
                            const char *org,
                            const char *org_unit,
                            const char *email,
                            const char *hostname);


#endif /* _OPTIONS_H */
