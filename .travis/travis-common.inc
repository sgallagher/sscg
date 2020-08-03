#!/bin/bash

set -x

# Global variables to support finalize()
SSCG_OS=
SSCG_RELEASE=
SSCG_TARBALL_PATH=

BUILDAH_PATH=$(which buildah)

DOCKER_PATH=$(which docker)

RETRY_CMD=$SCRIPT_DIR/retry-command.sh

if [ x$BUILDAH_PATH == x ]; then
    if [ x$DOCKER_PATH == x ]; then
        >&2 echo "error: Neither docker nor podman available"
        exit 1
    else
        SSCG_BUILDAH="$RETRY_CMD sudo $DOCKER_PATH build"
        SSCG_LAYERS_TRUE=
        SSCG_LAYERS_FALSE=
    fi
else
    SSCG_BUILDAH="$RETRY_CMD $BUILDAH_PATH bud"
    SSCG_LAYERS_TRUE="--layers=true"
    SSCG_LAYERS_FALSE="--layers=false"
fi

PODMAN_PATH=$(which podman)
if [  x$PODMAN_PATH == x ]; then
    SSCG_OCI="sudo $DOCKER_PATH"
else
    SSCG_OCI="$PODMAN_PATH"
fi

function common_finalize {
    # If any specific test launcher needs to do its own cleanup as well,
    # it should set the EXIT trap and make sure to also call this function
    # internally.
    exitcode=$?

    rm -f $SSCG_TARBALL_PATH \
          $SCRIPT_DIR/$SSCG_OS/Dockerfile.deps.$SSCG_RELEASE \
          $SCRIPT_DIR/$SSCG_OS/Dockerfile-$SSCG_RELEASE

    return $exitcode
}

trap common_finalize EXIT


function sscg_run_docker_tests {
    local os release repository image
    local "${@}"

    if [ -z $SCRIPT_DIR ]; then
        >&2 echo "Programming error: \$SCRIPT_DIR must be set"
        exit 1
    fi

    os=${os-fedora}
    release=${release-rawhide}
    repository=${repository-registry.fedoraproject.org}


    # Lower-case the os and release for the container registry
    SSCG_OS=${os,,}
    SSCG_RELEASE=${release,,}

    image=${image-$SSCG_OS:$SSCG_RELEASE}

    # Create an archive of the current checkout
    SSCG_TARBALL_PATH=`mktemp -p $SCRIPT_DIR tarball-XXXXXX.tar.bz2`
    TARBALL=`basename $SSCG_TARBALL_PATH`

    pushd $SCRIPT_DIR/..
    git ls-files |xargs tar cfj $SSCG_TARBALL_PATH .git
    popd

    sed -e "s#@IMAGE@#$repository/$image#" $SCRIPT_DIR/$SSCG_OS/Dockerfile.deps.tmpl \
        | m4 -D_RELEASE_=$release \
        > $SCRIPT_DIR/$SSCG_OS/Dockerfile.deps.$SSCG_RELEASE
    sed -e "s/@RELEASE@/$SSCG_OS:$SSCG_RELEASE/" $SCRIPT_DIR/$SSCG_OS/Dockerfile.tmpl \
        | m4 -D_RELEASE_=$release \
        > $SCRIPT_DIR/$SSCG_OS/Dockerfile-$SSCG_RELEASE

    $SSCG_BUILDAH $SSCG_LAYERS_TRUE \
        -f $SCRIPT_DIR/$SSCG_OS/Dockerfile.deps.$SSCG_RELEASE \
        -t sgallagher/sscg-deps-$SSCG_OS:$SSCG_RELEASE .

    $SSCG_BUILDAH $SSCG_LAYERS_FALSE \
        -f $SCRIPT_DIR/$SSCG_OS/Dockerfile-$SSCG_RELEASE \
        -t sgallagher/sscg-$SSCG_OS:$SSCG_RELEASE \
        --build-arg TARBALL=${TARBALL} .

    $SSCG_OCI run --rm sgallagher/sscg-$SSCG_OS:$SSCG_RELEASE
}

set +x
