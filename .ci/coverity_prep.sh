#!/usr/bin/bash

set -x

echo -n | openssl s_client -connect scan.coverity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | tee -a /etc/ssl/certs/ca-
curl -s -L https://entrust.com/root-certificates/entrust_l1k.cer | tee -a /etc/pki/ca-trust/source/anchors/entrust_l1k.cer
update-ca-trust


curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh -o /usr/bin/travisci_build_coverity_scan.sh

if [ "$(file -b --mime-type /usr/bin/travisci_build_coverity_scan.sh)" == "text/x-shellscript" ]; then
    chmod a+x /usr/bin/travisci_build_coverity_scan.sh
else
    echo "Coverity not detected!"
    exit 1
fi
