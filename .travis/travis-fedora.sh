#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $SCRIPT_DIR

set -e
set -x

JOB_NAME=${TRAVIS_JOB_NAME:-Fedora rawhide}

arr=($JOB_NAME)
os_name=${arr[0]:-Fedora}
release=${arr[1]:-rawhide}

# Create an archive of the current checkout
TARBALL_PATH=`mktemp -p $SCRIPT_DIR tarball-XXXXXX.tar.bz2`
TARBALL=`basename $TARBALL_PATH`

pushd $SCRIPT_DIR/..
git ls-files |xargs tar cfj $TARBALL_PATH .git
popd

repository="registry.fedoraproject.org"
os="fedora"

sed -e "s/@IMAGE@/$repository\/$os:$release/" \
    $SCRIPT_DIR/fedora/Dockerfile.deps.tmpl > $SCRIPT_DIR/fedora/Dockerfile.deps.$release
sed -e "s/@RELEASE@/$release/" $SCRIPT_DIR/fedora/Dockerfile.tmpl > $SCRIPT_DIR/fedora/Dockerfile-$release

sudo docker build -f $SCRIPT_DIR/fedora/Dockerfile.deps.$release -t sgallagher/sscg-deps-$release .
sudo docker build -f $SCRIPT_DIR/fedora/Dockerfile-$release -t sgallagher/sscg:$release --build-arg TARBALL=$TARBALL .

if [ $release != "31" ]; then
  # Only run Coverity scan on one release since we have a limited number of scans per week.
  # Currently, Coverity doesn't support recent GCC, so we need to use older Fedora.
  unset COVERITY_SCAN_TOKEN
fi

rm -f $TARBALL_PATH $SCRIPT_DIR/fedora/Dockerfile.deps.$release $SCRIPT_DIR/fedora/Dockerfile-$release

docker run -e COVERITY_SCAN_TOKEN=$COVERITY_SCAN_TOKEN -e TRAVIS=$TRAVIS -eTRAVIS_JOB_NAME="$TRAVIS_JOB_NAME" --rm sgallagher/sscg:$release

popd
exit 0
