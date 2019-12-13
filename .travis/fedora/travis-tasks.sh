#!/bin/bash

#Exit on failures
set -e

pushd /builddir/

meson --buildtype=debug -Dtest_dhparams_4096=true travis

meson test -C travis --verbose

# Run clang-analyzer
meson --buildtype=debug clang-analyzer
ninja -C clang-analyzer scan-build

meson --buildtype=debug coverity
pushd coverity

# The coverity scan script returns an error despite succeeding...
 TRAVIS_BRANCH="${TRAVIS_BRANCH:-master}" \
 COVERITY_SCAN_PROJECT_NAME="${COVERITY_SCAN_PROJECT_NAME:-sgallagher/sscg}" \
 COVERITY_SCAN_NOTIFICATION_EMAIL="${COVERITY_SCAN_NOTIFICATION_EMAIL:-sgallagh@redhat.com}" \
 COVERITY_SCAN_BUILD_COMMAND="${COVERITY_SCAN_BUILD_COMMAND:-ninja}" \
 COVERITY_SCAN_BRANCH_PATTERN=${COVERITY_SCAN_BRANCH_PATTERN:-master} \
 /usr/bin/travisci_build_coverity_scan.sh ||:

popd #coverity

popd #builddir
