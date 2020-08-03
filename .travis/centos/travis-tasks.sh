#!/bin/bash

#Exit on failures
set -e

pushd /builddir/

meson --buildtype=debug travis

ninja-build -C travis test
if [ $? != 0 ]; then
    cat /builddir/travis/meson-logs/testlog.txt
fi

popd #builddir
