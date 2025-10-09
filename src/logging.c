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

#include <include/logging.h>

int global_verbosity;

const char *
sscg_get_verbosity_name (enum sscg_verbosity type)
{
  switch (type)
    {
    case SSCG_DEFAULT:
    case SSCG_VERBOSE: return "";

    case SSCG_DEBUG: return "DEBUG: ";

    default: break;
    }

  /* If it wasn't one of these, we have a bug */
  return "Unknown Verbosity (bug):";
}

void
set_verbosity (int verbosity)
{
  global_verbosity = verbosity;
}
