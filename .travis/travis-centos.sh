#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $SCRIPT_DIR

source $SCRIPT_DIR/travis-common.inc

set -e
set -x

JOB_NAME=${TRAVIS_JOB_NAME:-CentOS 7}

arr=($JOB_NAME)
release=${arr[1]:-7}
repository=docker.io

sscg_run_docker_tests \
    os=centos \
    release=$release \
    repository=$repository

popd # $SCRIPT_DIR
