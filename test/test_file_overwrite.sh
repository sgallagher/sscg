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

# Test for file overwrite behavior
# This tests that sscg correctly handles pre-existing files both with
# and without the --force flag.

# Note: We don't use 'set -e' here because we expect some commands to fail
set +e

# If we're running in a CI environment, use the workspace directory
TMPDIR=$(mktemp --directory --tmpdir=${GITHUB_WORKSPACE:-/tmp} sscg_overwrite_test_XXXXXX)

function cleanup {
    exitcode=$?
    rm -rf "$TMPDIR"
    return $exitcode
}

trap cleanup EXIT

failed_tests=0
total_tests=7

# Helper function to get file hash
function get_hash {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | cut -d' ' -f1
    else
        md5sum "$file" | cut -d' ' -f1
    fi
}

# Helper function to check if file is non-zero
function is_nonzero {
    local file="$1"
    [ -f "$file" ] && [ -s "$file" ]
}

echo "Running file overwrite behavior tests..."
echo "=========================================="
echo

# Test 1: Clean directory - files should be created
echo "Test 1: Clean directory - all files should be created"
TEST_DIR="$TMPDIR/test1"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

"${MESON_BUILD_ROOT}/sscg" --debug >/dev/null 2>&1
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo "  FAIL: sscg failed with exit code $exit_code"
    ((failed_tests++))
elif ! is_nonzero "ca.crt"; then
    echo "  FAIL: ca.crt was not created or is empty"
    ((failed_tests++))
elif ! is_nonzero "service-key.pem"; then
    echo "  FAIL: service-key.pem was not created or is empty"
    ((failed_tests++))
elif ! is_nonzero "service.pem"; then
    echo "  FAIL: service.pem was not created or is empty"
    ((failed_tests++))
else
    echo "  PASS: All files created successfully"
fi

popd >/dev/null
echo

# Test 2: Pre-existing ca.crt WITHOUT --force
echo "Test 2: Pre-existing ca.crt WITHOUT --force - should fail, file unchanged"
TEST_DIR="$TMPDIR/test2"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

echo "Original ca.crt content" > ca.crt
original_hash=$(get_hash ca.crt)

"${MESON_BUILD_ROOT}/sscg" --debug >/dev/null 2>&1
exit_code=$?

new_hash=$(get_hash ca.crt)

if [ $exit_code -ne 17 ]; then
    echo "  FAIL: Expected exit code 17 (EEXIST), got $exit_code"
    ((failed_tests++))
elif [ "$original_hash" != "$new_hash" ]; then
    echo "  FAIL: ca.crt content was modified"
    ((failed_tests++))
else
    echo "  PASS: Command failed correctly, file unchanged"
fi

popd >/dev/null
echo

# Test 3: Pre-existing service-key.pem WITHOUT --force
echo "Test 3: Pre-existing service-key.pem WITHOUT --force - should fail, file unchanged"
TEST_DIR="$TMPDIR/test3"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

echo "Original service-key.pem content" > service-key.pem
original_hash=$(get_hash service-key.pem)

"${MESON_BUILD_ROOT}/sscg" --debug >/dev/null 2>&1
exit_code=$?

new_hash=$(get_hash service-key.pem)

if [ $exit_code -ne 17 ]; then
    echo "  FAIL: Expected exit code 17 (EEXIST), got $exit_code"
    ((failed_tests++))
elif [ "$original_hash" != "$new_hash" ]; then
    echo "  FAIL: service-key.pem content was modified"
    ((failed_tests++))
else
    echo "  PASS: Command failed correctly, file unchanged"
fi

popd >/dev/null
echo

# Test 4: Pre-existing service.pem WITHOUT --force
echo "Test 4: Pre-existing service.pem WITHOUT --force - should fail, file unchanged"
TEST_DIR="$TMPDIR/test4"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

echo "Original service.pem content" > service.pem
original_hash=$(get_hash service.pem)

"${MESON_BUILD_ROOT}/sscg" --debug >/dev/null 2>&1
exit_code=$?

new_hash=$(get_hash service.pem)

if [ $exit_code -ne 17 ]; then
    echo "  FAIL: Expected exit code 17 (EEXIST), got $exit_code"
    ((failed_tests++))
elif [ "$original_hash" != "$new_hash" ]; then
    echo "  FAIL: service.pem content was modified"
    ((failed_tests++))
else
    echo "  PASS: Command failed correctly, file unchanged"
fi

popd >/dev/null
echo

# Test 5: Pre-existing ca.crt WITH --force
echo "Test 5: Pre-existing ca.crt WITH --force - should succeed, file changed"
TEST_DIR="$TMPDIR/test5"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

echo "Original ca.crt content" > ca.crt
original_hash=$(get_hash ca.crt)

"${MESON_BUILD_ROOT}/sscg" --debug --force >/dev/null 2>&1
exit_code=$?

new_hash=$(get_hash ca.crt)

if [ $exit_code -ne 0 ]; then
    echo "  FAIL: sscg failed with exit code $exit_code"
    ((failed_tests++))
elif [ "$original_hash" = "$new_hash" ]; then
    echo "  FAIL: ca.crt content was not changed"
    ((failed_tests++))
elif ! is_nonzero "ca.crt"; then
    echo "  FAIL: ca.crt is empty or missing"
    ((failed_tests++))
elif ! is_nonzero "service-key.pem"; then
    echo "  FAIL: service-key.pem is empty or missing"
    ((failed_tests++))
elif ! is_nonzero "service.pem"; then
    echo "  FAIL: service.pem is empty or missing"
    ((failed_tests++))
else
    echo "  PASS: All files created/overwritten successfully"
fi

popd >/dev/null
echo

# Test 6: Pre-existing service-key.pem WITH --force
echo "Test 6: Pre-existing service-key.pem WITH --force - should succeed, file changed"
TEST_DIR="$TMPDIR/test6"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

echo "Original service-key.pem content" > service-key.pem
original_hash=$(get_hash service-key.pem)

"${MESON_BUILD_ROOT}/sscg" --debug --force >/dev/null 2>&1
exit_code=$?

new_hash=$(get_hash service-key.pem)

if [ $exit_code -ne 0 ]; then
    echo "  FAIL: sscg failed with exit code $exit_code"
    ((failed_tests++))
elif [ "$original_hash" = "$new_hash" ]; then
    echo "  FAIL: service-key.pem content was not changed"
    ((failed_tests++))
elif ! is_nonzero "ca.crt"; then
    echo "  FAIL: ca.crt is empty or missing"
    ((failed_tests++))
elif ! is_nonzero "service-key.pem"; then
    echo "  FAIL: service-key.pem is empty or missing"
    ((failed_tests++))
elif ! is_nonzero "service.pem"; then
    echo "  FAIL: service.pem is empty or missing"
    ((failed_tests++))
else
    echo "  PASS: All files created/overwritten successfully"
fi

popd >/dev/null
echo

# Test 7: Pre-existing service.pem WITH --force
echo "Test 7: Pre-existing service.pem WITH --force - should succeed, file changed"
TEST_DIR="$TMPDIR/test7"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

echo "Original service.pem content" > service.pem
original_hash=$(get_hash service.pem)

"${MESON_BUILD_ROOT}/sscg" --debug --force >/dev/null 2>&1
exit_code=$?

new_hash=$(get_hash service.pem)

if [ $exit_code -ne 0 ]; then
    echo "  FAIL: sscg failed with exit code $exit_code"
    ((failed_tests++))
elif [ "$original_hash" = "$new_hash" ]; then
    echo "  FAIL: service.pem content was not changed"
    ((failed_tests++))
elif ! is_nonzero "ca.crt"; then
    echo "  FAIL: ca.crt is empty or missing"
    ((failed_tests++))
elif ! is_nonzero "service-key.pem"; then
    echo "  FAIL: service-key.pem is empty or missing"
    ((failed_tests++))
elif ! is_nonzero "service.pem"; then
    echo "  FAIL: service.pem is empty or missing"
    ((failed_tests++))
else
    echo "  PASS: All files created/overwritten successfully"
fi

popd >/dev/null
echo

# Summary
echo "=========================================="
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

