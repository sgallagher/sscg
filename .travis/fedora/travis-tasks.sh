#!/bin/bash

#Exit on failures
set -e

pushd /builddir/

meson --buildtype=debug travis

ninja -C travis test
if [ $? != 0 ]; then
    cat /builddir/travis/meson-logs/testlog.txt
fi

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
