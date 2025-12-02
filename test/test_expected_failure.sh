#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception

# This file is part of sscg.
#
# sscg is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# sscg is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with sscg.  If not, see <http://www.gnu.org/licenses/>.
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.
#
# Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>

# Wrapper script for tests that are expected to fail with a specific exit code
# Usage: test_expected_failure.sh <expected_exit_code> <script> [args...]
#
# Runs the provided script with arguments and verifies that it exits with
# the expected code. Returns 0 if the exit code matches, 1 otherwise.

if [ $# -lt 2 ]; then
    echo "Usage: test_expected_failure.sh <expected_exit_code> <script> [args...]"
    exit 1
fi

expected_exit_code="$1"
shift

"$@"
exit_code=$?

if [ $exit_code -eq $expected_exit_code ]; then
    exit 0
else
    echo "Expected exit code $expected_exit_code, got $exit_code"
    exit 1
fi

