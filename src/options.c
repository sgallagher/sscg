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

#include <popt.h>
#include <talloc.h>

#include "include/sscg.h"
#include "include/options.h"


static int
_sscg_options_new (TALLOC_CTX *mem_ctx, struct sscg4_options **options);
static int
_sscg_global_options_new (TALLOC_CTX *mem_ctx,
                          struct sscg_global_options **global_options);
static int
_sscg_cert_options_new (TALLOC_CTX *mem_ctx,
                        struct sscg_cert_options **cert_options);

int
sscg_process_arguments (TALLOC_CTX *mem_ctx,
                        int argc,
                        const char **argv,
                        struct sscg4_options **options)
{
  int ret = EOK;
  struct sscg4_options *opts;
  poptContext popt_ctx;
  int opt;
  const char *arg = NULL;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  /* For early startup prior to reading arguments, set the verbosity to the default */
  set_verbosity (SSCG_DEFAULT);

  ret = _sscg_options_new (tmp_ctx, &opts);
  CHECK_OK (ret);

  /* clang-format off */
  struct poptOption global_options_table [] =
  {
    POPT_AUTOHELP

    {
      "quiet",
      'q',
      POPT_ARG_VAL,
      &opts->global_options->verbosity,
      SSCG_QUIET,
      _ ("Display no output unless there is an error."),
      NULL
    },

    {
      "verbose",
      'v',
      POPT_ARG_VAL,
      &opts->global_options->verbosity,
      SSCG_VERBOSE,
      _ ("Display progress messages."),
      NULL
    },

    {
      "debug",
      'd',
      POPT_ARG_VAL,
      &opts->global_options->verbosity,
      SSCG_DEBUG,
      _ ("Enable logging of debug messages. Implies verbose. Warning! "
         "This will print private key information to the screen!"),
      NULL
    },

    POPT_TABLEEND
  };
  /* clang-format on */

  /* First parse the global options
   */
  popt_ctx = poptGetContext (
    argv[0], argc, (const char **)argv, global_options_table, 0);

  Try poptArgAddTable here if (!popt_ctx)
    /* poptGetNextOpt has a poorly-documented feature where it will stop
   * processing when it encounters a double-dash option ('--'), which is
   * perfect for our needs. We'll read until the first double-dash option
   * (or the end of the arguments) and treat this as the first coterie
   * of options.
   */
    while ((opt = poptGetNextOpt (popt_ctx)) > 0)
  {
    switch (opt)
      {
      default:
        fprintf (stderr,
                 _ ("\nInvalid option %s: %s\n\n"),
                 poptBadOption (popt_ctx, 0),
                 poptStrerror (opt));
        poptPrintUsage (popt_ctx, stderr, 0);
        ret = EINVAL;
        goto done;
      }
  }

  set_verbosity (opts->global_options->verbosity);

  if (!poptPeekArg (popt_ctx))
    {
      SSCG_LOG (SSCG_DEFAULT, "No certificates requested.\n");
      poptPrintUsage (popt_ctx, stderr, 0);
      ret = EINVAL;
      goto done;
    }

  SSCG_LOG (SSCG_DEBUG, "Remaining arguments to process:\n");
  while ((arg = poptGetArg (popt_ctx)))
    {
      SSCG_LOG (SSCG_DEBUG, "Argument: %s\n", arg);
    }

  *options = talloc_steal (mem_ctx, opts);

  ret = EOK;
done:
  talloc_free (tmp_ctx);
  return ret;
}


static int
_sscg_options_new (TALLOC_CTX *mem_ctx, struct sscg4_options **options)
{
  int ret = EOK;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  struct sscg4_options *opts = talloc_zero (tmp_ctx, struct sscg4_options);
  CHECK_MEM (opts);

  ret = _sscg_global_options_new (opts, &opts->global_options);
  CHECK_OK (ret);

  ret = _sscg_cert_options_new (opts, &opts->ca_options);
  CHECK_OK (ret);

  ret = _sscg_cert_options_new (opts, &opts->ca_options);
  CHECK_OK (ret);

  *options = talloc_steal (mem_ctx, opts);
  ret = EOK;

done:
  talloc_zfree (tmp_ctx);
  return ret;
}


static int
_sscg_global_options_new (TALLOC_CTX *mem_ctx,
                          struct sscg_global_options **global_options)
{
  int ret = EOK;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  struct sscg_global_options *global_opts =
    talloc_zero (tmp_ctx, struct sscg_global_options);
  CHECK_MEM (global_opts);

  global_opts->verbosity = SSCG_DEFAULT;

  *global_options = talloc_steal (mem_ctx, global_opts);

  ret = EOK;

done:
  talloc_zfree (tmp_ctx);
  return ret;
}


static int
_sscg_cert_options_new (TALLOC_CTX *mem_ctx,
                        struct sscg_cert_options **cert_options)
{
  int ret = EOK;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  struct sscg_cert_options *cert_opts =
    talloc_zero (tmp_ctx, struct sscg_cert_options);
  CHECK_MEM (cert_opts);

  /* Set the defaults */
  cert_opts->subject_info = talloc_zero (cert_opts, struct sscg_subject_info);
  CHECK_MEM (cert_opts->subject_info);

  *cert_options = talloc_steal (mem_ctx, cert_opts);
  ret = EOK;

done:
  talloc_zfree (tmp_ctx);
  return ret;
}


int
sscg_set_cert_subject_info (struct sscg_cert_options *cert_options,
                            const char *country,
                            const char *state,
                            const char *locality,
                            const char *org,
                            const char *org_unit,
                            const char *email,
                            const char *hostname)
{
  int ret = EOK;
  struct sscg_subject_info *subject_info;
  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  /* If no subject information is provided, return EINVAL. */
  if (!country && !state && !locality && !org && !org_unit && !email
      && !hostname)
    {
      ret = EINVAL;
      goto done;
    }

  subject_info = talloc_zero (tmp_ctx, struct sscg_subject_info);
  CHECK_MEM (subject_info);

  if (country)
    {
      subject_info->country = talloc_strdup (subject_info, country);
      CHECK_MEM (subject_info->country);
    }

  if (state)
    {
      subject_info->state = talloc_strdup (subject_info, state);
      CHECK_MEM (subject_info->state);
    }

  if (locality)
    {
      subject_info->locality = talloc_strdup (subject_info, locality);
      CHECK_MEM (subject_info->locality);
    }

  if (org)
    {
      subject_info->org = talloc_strdup (subject_info, org);
      CHECK_MEM (subject_info->org);
    }

  if (org_unit)
    {
      subject_info->org_unit = talloc_strdup (subject_info, org_unit);
      CHECK_MEM (subject_info->org_unit);
    }

  if (email)
    {
      subject_info->email = talloc_strdup (subject_info, email);
      CHECK_MEM (subject_info->email);
    }

  if (hostname)
    {
      subject_info->hostname = talloc_strdup (subject_info, hostname);
      CHECK_MEM (subject_info->hostname);
    }

  /* Delete any existing subject information. If it is NULL, this is a no-op. */
  talloc_free (tmp_ctx);
  cert_options->subject_info = talloc_steal (cert_options, subject_info);
  CHECK_MEM (cert_options->subject_info);

  ret = EOK;

done:
  return ret;
}
