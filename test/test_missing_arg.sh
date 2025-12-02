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

# Test that sscg returns exit code 22 (EINVAL) when options that require
# arguments are provided without their arguments.

# All options that take arguments (from sscg --help)
OPTIONS=(
    "--lifetime"
    "--country"
    "--state"
    "--locality"
    "--organization"
    "--organizational-unit"
    "--email"
    "--hostname"
    "--subject-alt-name"
    "--key-type"
    "--key-strength"
    "--ec-curve"
    "--mldsa-nist-level"
    "--hash-alg"
    "--cipher-alg"
    "--ca-file"
    "--ca-mode"
    "--ca-key-file"
    "--ca-key-mode"
    "--ca-key-password"
    "--ca-key-passfile"
    "--crl-file"
    "--crl-mode"
    "--cert-file"
    "--cert-mode"
    "--cert-key-file"
    "--cert-key-mode"
    "--cert-key-password"
    "--cert-key-passfile"
    "--client-file"
    "--client-mode"
    "--client-key-file"
    "--client-key-mode"
    "--client-key-password"
    "--client-key-passfile"
    "--dhparams-file"
    "--dhparams-named-group"
    "--dhparams-generator"
)

echo "Testing options without required arguments..."
echo "=============================================="
echo

failed_tests=0
total_tests=${#OPTIONS[@]}

for opt in "${OPTIONS[@]}"; do
    "${MESON_BUILD_ROOT}/sscg" "$opt" >/dev/null 2>&1
    exit_code=$?
    if [ $exit_code -eq 22 ]; then
        echo "PASS: $opt (exit code 22)"
    else
        echo "FAIL: $opt (expected 22, got $exit_code)"
        ((failed_tests++))
    fi
done

echo
echo "=============================================="
echo "Test Summary:"
echo "============="
echo "Total tests: $total_tests"
echo "Failed tests: $failed_tests"
echo "Passed tests: $((total_tests - failed_tests))"

if [ "$failed_tests" -gt 0 ]; then
    echo
    echo "Some tests failed!"
    exit 1
else
    echo
    echo "All tests passed!"
    exit 0
fi

