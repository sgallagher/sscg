#!/bin/bash

#Exit on failures
set -e
set -x


pushd /builddir/

meson --buildtype=debug \
      $COMMON_MESON_ARGS \
      coverity

pushd coverity

# The coverity scan script returns an error despite succeeding...
 TRAVIS_BRANCH="${TRAVIS_BRANCH:-main}" \
 COVERITY_SCAN_PROJECT_NAME="${COVERITY_SCAN_PROJECT_NAME:-sgallagher/sscg}" \
 COVERITY_SCAN_NOTIFICATION_EMAIL="${COVERITY_SCAN_NOTIFICATION_EMAIL:-sgallagh@redhat.com}" \
 COVERITY_SCAN_BUILD_COMMAND="${COVERITY_SCAN_BUILD_COMMAND:-ninja}" \
 COVERITY_SCAN_BRANCH_PATTERN=${COVERITY_SCAN_BRANCH_PATTERN:-main} \
 /usr/bin/travisci_build_coverity_scan.sh ||:

popd #coverity

popd #builddir
