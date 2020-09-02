#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $SCRIPT_DIR

JOB_NAME=${DISTRO:-Fedora rawhide}

arr=(${DISTRO:-Fedora rawhide})
distro_name=${arr[0]}
release=${arr[1]}

if [ "$distro_name" = "Fedora" ]; then
  $SCRIPT_DIR/travis-fedora.sh
elif [ "$distro_name" = "CentOS" ]; then
  $SCRIPT_DIR/travis-centos.sh
fi
