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

# Test for DH parameters file creation behavior
# When dhparams support was added, I started creating it by default when
# generating the certificates. This was considered a regression by httpd,
# because they didn't want it and didn't think it should be there unless
# requested. Just turning off the auto-creation would break anyone who had
# come to depend on that behavior. So what I did was change sscg so it would
# generate it opportunistically if the default location was writable and to
# just warn and ignore it if it was not (returning 0). However, if it is
# explicitly requested on the command-line and cannot be written to that
# location, it should fail with an error code.

set -e

# If we're running in a CI environment, use the workspace directory
# (if this variable is not set, mktemp will use /tmp)
DHPARAMS_TMPDIR=$(mktemp --directory --tmpdir=$GITHUB_WORKSPACE sscg_dhparams_test_XXXXXX)
WRITABLE_DIR="$DHPARAMS_TMPDIR/writable"
READONLY_DIR="$DHPARAMS_TMPDIR/readonly"
DHPARAMS_DIR="$DHPARAMS_TMPDIR/dhparams"

function cleanup {
    exitcode=$?
    # Make readonly dir writable again so we can remove it
    chmod -R +w "$DHPARAMS_TMPDIR" 2>/dev/null || true
    rm -Rf "$DHPARAMS_TMPDIR"
    return $exitcode
}

trap cleanup EXIT

# Set up test directories
mkdir -p "$WRITABLE_DIR"
mkdir -p "$READONLY_DIR"
mkdir -p "$DHPARAMS_DIR"

# Create a pre-existing dhparams.pem file for some tests
touch "$DHPARAMS_DIR/dhparams.pem"

# Copy pre-existing dhparams.pem to readonly directory before making it readonly
cp "$DHPARAMS_DIR/dhparams.pem" "$READONLY_DIR/dhparams.pem"
chmod 555 "$READONLY_DIR"

failed_tests=0
total_tests=8

function run_test {
    local test_num="$1"
    local description="$2"
    local work_dir="$3"
    local dhparams_output_file="$4"
    local expected_exit_code="$5"
    local expected_file="$6"
    local should_create_file="$7"
    local output_dir="$8"
    
    echo "Test $test_num: $description"
    
    pushd "$work_dir" >/dev/null

    # Check if the expected file exists before running sscg
    if [ -f "$expected_file" ]; then
        pre_existing_file=true
    else
        pre_existing_file=false
    fi

    # Use provided output directory or current directory
    if [ -z "$output_dir" ]; then
        output_dir="."
    fi
    
    # Run sscg with the specified arguments
    local cmd_args=(
        "${MESON_BUILD_ROOT}/sscg"
        --ca-file "${output_dir}/ca.crt"
        --cert-file "${output_dir}/service.pem"
        --cert-key-file "${output_dir}/service-key.pem"
    )
    
    if [ -n "$dhparams_output_file" ]; then
        cmd_args+=("--dhparams-file=$dhparams_output_file")
    fi
    
    local exit_code=0
    "${cmd_args[@]}" >/dev/null 2>&1 || exit_code=$?
    
    local test_passed=true
    
    # Check exit code
    if [ "$exit_code" -ne "$expected_exit_code" ]; then
        echo "  FAIL: Expected exit code $expected_exit_code, got $exit_code"
        test_passed=false
    fi
    
    # Check file creation
    if [ "$should_create_file" = "true" ]; then
        if [ ! -f "$expected_file" ]; then
            echo "  FAIL: Expected file $expected_file was not created"
            test_passed=false
        else
            # Verify it's a valid DH params file
            if ! openssl dhparam -noout -in "$expected_file" >/dev/null 2>&1; then
                echo "  FAIL: Created file $expected_file is not a valid DH params file"
                test_passed=false
            fi
        fi
    else
        if [ -f "$expected_file" ] && [ "$pre_existing_file" = "false" ]; then
            # Only fail if the file was created and it wasn't pre-existing
            echo "  FAIL: File $expected_file was created but shouldn't have been"
            test_passed=false
        fi
    fi
    
    if [ "$test_passed" = "true" ]; then
        echo "  PASS"
    else
        ((failed_tests++))
    fi
    
    # Clean up any created files for next test
    rm -f "${output_dir}/ca.crt" "${output_dir}/service.pem" "${output_dir}/service-key.pem"
    rm -f "$expected_file" || true # Ignore errors
    
    popd >/dev/null
    echo
}

echo "Running DH parameters creation tests..."
echo

# Test 1: No --dhparams-file, writable directory, no existing file
# Arguments: test_num description work_dir dhparams_output_file expected_exit_code expected_file should_create_file output_dir
run_test \
    1 \
    "No --dhparams-file, writable directory, no existing dhparams.pem" \
    "$WRITABLE_DIR" \
    "" \
    0 \
    "$WRITABLE_DIR/dhparams.pem" \
    "true" \
    "$WRITABLE_DIR"

# Test 2: No --dhparams-file, readonly directory, no existing file
# Arguments: test_num description work_dir dhparams_output_file expected_exit_code expected_file should_create_file output_dir
run_test \
    2 \
    "No --dhparams-file, readonly directory, no existing dhparams.pem" \
    "$READONLY_DIR" \
    "" \
    0 \
    "$READONLY_DIR/dhparams.pem" \
    "false" \
    "$WRITABLE_DIR"

# Test 3: No --dhparams-file, writable directory, existing file
cp "$DHPARAMS_DIR/dhparams.pem" "$WRITABLE_DIR/dhparams.pem"
# Arguments: test_num description work_dir dhparams_output_file expected_exit_code expected_file should_create_file output_dir
run_test \
    3 \
    "No --dhparams-file, writable directory, existing dhparams.pem" \
    "$WRITABLE_DIR" \
    "" \
    0 \
    "$WRITABLE_DIR/dhparams.pem" \
    "false" \
    "$WRITABLE_DIR"

# Test 4: No --dhparams-file, readonly directory, existing file
# Arguments: test_num description work_dir dhparams_output_file expected_exit_code expected_file should_create_file output_dir
run_test \
    4 \
    "No --dhparams-file, readonly directory, existing dhparams.pem" \
    "$READONLY_DIR" \
    "" \
    0 \
    "$READONLY_DIR/dhparams.pem" \
    "false" \
    "$WRITABLE_DIR"

# Test 5: --dhparams-file to writable path, no existing file
# Arguments: test_num description work_dir dhparams_output_file expected_exit_code expected_file should_create_file output_dir
run_test \
    5 \
    "--dhparams-file to writable path, no existing file" \
    "$WRITABLE_DIR" \
    "$DHPARAMS_DIR/new_dhparams.pem" \
    0 \
    "$DHPARAMS_DIR/new_dhparams.pem" \
    "true" \
    "$WRITABLE_DIR"

# Test 6: --dhparams-file to non-writable path, no existing file
# Arguments: test_num description work_dir dhparams_output_file expected_exit_code expected_file should_create_file output_dir
run_test \
    6 \
    "--dhparams-file to non-writable path, no existing file" \
    "$WRITABLE_DIR" \
    "$READONLY_DIR/new_dhparams.pem" \
    1 \
    "$READONLY_DIR/new_dhparams.pem" \
    "false" \
    "$WRITABLE_DIR"

# Test 7: --dhparams-file to writable path, existing file
# Arguments: test_num description work_dir dhparams_output_file expected_exit_code expected_file should_create_file output_dir
run_test \
    7 \
    "--dhparams-file to writable path, existing file" \
    "$WRITABLE_DIR" \
    "$DHPARAMS_DIR/dhparams.pem" \
    1 \
    "$DHPARAMS_DIR/dhparams.pem" \
    "false" \
    "$WRITABLE_DIR"

# Test 8: --dhparams-file to non-writable path, existing file  
# Arguments: test_num description work_dir dhparams_output_file expected_exit_code expected_file should_create_file output_dir
run_test \
    8 \
    "--dhparams-file to non-writable path, existing file" \
    "$WRITABLE_DIR" \
    "$READONLY_DIR/dhparams.pem" \
    1 \
    "$READONLY_DIR/dhparams.pem" \
    "false" \
    "$WRITABLE_DIR"

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
