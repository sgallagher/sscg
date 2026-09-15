#!/usr/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

set -x

# If we are running in a GitHub Actions workflow, use the workspace directory
# otherwise use the script directory
workdir=${GITHUB_WORKSPACE:-${SCRIPT_DIR}}
mkdir -p ${workdir}/coverity

cd ${workdir}/coverity
curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh -o travisci_build_coverity_scan.sh

if [ "$(file -b --mime-type ${workdir}/coverity/travisci_build_coverity_scan.sh)" == "text/x-shellscript" ]; then
    chmod a+x ${workdir}/coverity/travisci_build_coverity_scan.sh
else
    echo "Coverity not detected!"
    exit 1
fi
