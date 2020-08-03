#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $SCRIPT_DIR

source $SCRIPT_DIR/travis-common.inc

set -e
set -x

function coverity_finalize {
    exitcode=$?

    # Make sure to delete the Dockerfile.deps from centos
    rm -f $SCRIPT_DIR/$SSCG_OS/Dockerfile.deps.$SSCG_RELEASE

    common_finalize

    return $exitcode
}

trap coverity_finalize EXIT

SSCG_OS=centos
SSCG_RELEASE=8
SSCG_IMAGE=${SSCG_OS}:${SSCG_RELEASE}
repository="docker.io"

# Create an archive of the current checkout
SSCG_TARBALL_PATH=`mktemp -p $SCRIPT_DIR tarball-XXXXXX.tar.bz2`
TARBALL=`basename $SSCG_TARBALL_PATH`

pushd $SCRIPT_DIR/..
git ls-files |xargs tar cfj $SSCG_TARBALL_PATH .git
popd

sed -e "s#@IMAGE@#$repository/${SSCG_IMAGE}#" $SCRIPT_DIR/$SSCG_OS/Dockerfile.deps.tmpl \
    | m4 -D_RELEASE_=${SSCG_RELEASE} \
    > $SCRIPT_DIR/$SSCG_OS/Dockerfile.deps.$SSCG_RELEASE

sed -e "s#@RELEASE@#${SSCG_OS}:${SSCG_RELEASE}#" $SCRIPT_DIR/coverity/Dockerfile.tmpl \
    | m4 -D_RELEASE_=${SSCG_RELEASE} \
    > $SCRIPT_DIR/coverity/Dockerfile-$SSCG_RELEASE

$RETRY_CMD $SSCG_BUILDAH $SSCG_LAYERS_TRUE \
    -f $SCRIPT_DIR/centos/Dockerfile.deps.$SSCG_RELEASE \
    -t sgallagher/sscg-deps-$SSCG_OS:$SSCG_RELEASE .

$RETRY_CMD $SSCG_BUILDAH $SSCG_LAYERS_FALSE \
    -f $SCRIPT_DIR/coverity/Dockerfile-$SSCG_RELEASE \
    -t sgallagher/sscg-coverity \
    --build-arg TARBALL=$TARBALL .

rm -f $SSCG_TARBALL_PATH $SCRIPT_DIR/centos/Dockerfile.deps.$SSCG_RELEASE $SCRIPT_DIR/centos/Dockerfile-$SSCG_RELEASE

# Override the standard tasks with the Coverity scan
$RETRY_CMD $SSCG_OCI run \
    -e COVERITY_SCAN_TOKEN=$COVERITY_SCAN_TOKEN \
    -e TRAVIS=$TRAVIS \
    -e TRAVIS_COMMIT="$TRAVIS_COMMIT" \
    --rm sgallagher/sscg-coverity

popd

