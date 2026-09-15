#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception
#
# Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>

set +e

TMPDIR=$(mktemp --directory --tmpdir=${GITHUB_WORKSPACE:-/tmp} sscg_hostname_san_XXXXXX)

function cleanup {
    exitcode=$?
    rm -rf "$TMPDIR"
    return $exitcode
}

trap cleanup EXIT

failed_tests=0
SSCG="${MESON_BUILD_ROOT}/sscg"

function is_nonzero {
    local file="$1"
    [ -f "$file" ] && [ -s "$file" ]
}

echo "Hostname / SAN CLI validation tests"
echo "===================================="
echo

echo "Test 1: valid hostname and SAN values (expect success)"
TEST_DIR="$TMPDIR/valid"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

"${SSCG}" --quiet \
    --hostname server.example.com \
    --subject-alt-name alt.example.com \
    --subject-alt-name DNS:alt2.example.com \
    --subject-alt-name IP:192.0.2.1
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo "  FAIL: sscg exited with $exit_code"
    ((failed_tests++))
elif ! is_nonzero ca.crt || ! is_nonzero service.pem; then
    echo "  FAIL: expected output files missing or empty"
    ((failed_tests++))
else
    echo "  PASS"
fi

popd >/dev/null
echo

echo "Test 2: comma injection in --hostname (expect EINVAL 22)"
TEST_DIR="$TMPDIR/reject-hostname"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

"${SSCG}" --quiet --hostname 'a, DNS:evil.com' >/dev/null 2>&1
exit_code=$?

if [ $exit_code -ne 22 ]; then
    echo "  FAIL: expected exit 22, got $exit_code"
    ((failed_tests++))
else
    echo "  PASS"
fi

popd >/dev/null
echo

echo "Test 3: comma injection in --subject-alt-name (expect EINVAL 22)"
TEST_DIR="$TMPDIR/reject-san"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

"${SSCG}" --quiet \
    --hostname server.example.com \
    --subject-alt-name 'evil, DNS:other' >/dev/null 2>&1
exit_code=$?

if [ $exit_code -ne 22 ]; then
    echo "  FAIL: expected exit 22, got $exit_code"
    ((failed_tests++))
else
    echo "  PASS"
fi

popd >/dev/null
echo

echo "Test 4: unsupported typed SAN URI: (expect EINVAL 22)"
TEST_DIR="$TMPDIR/reject-uri"
mkdir -p "$TEST_DIR"
pushd "$TEST_DIR" >/dev/null

"${SSCG}" --quiet \
    --hostname server.example.com \
    --subject-alt-name 'URI:https://example.com' >/dev/null 2>&1
exit_code=$?

if [ $exit_code -ne 22 ]; then
    echo "  FAIL: expected exit 22, got $exit_code"
    ((failed_tests++))
else
    echo "  PASS"
fi

popd >/dev/null
echo

echo "===================================="
if [ "$failed_tests" -gt 0 ]; then
    echo "Failed: $failed_tests"
    exit 1
fi

echo "All tests passed."
exit 0
