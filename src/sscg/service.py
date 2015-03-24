# -*- coding: utf-8 -*-
#
# Copyright (c) 2015, Stephen Gallagher <sgallagh@redhat.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import print_function
import sys
import struct
import gettext
from OpenSSL import crypto, rand

PACKAGE = 'sscg'
LOCALEDIR = '/usr/share/locale'
translation = gettext.translation(PACKAGE, LOCALEDIR, fallback=True)
_ = translation.gettext


def create_service_cert(options, ca_cert, ca_key):
    # Make sure the subject looks like an FQDN
    # We'll just take a simplistic approach and assume
    # that as long as it has a dot in it, it's an FQDN.
    # The worst-case here is that we create a certificate
    # that fails validation.
    if "." not in options.hostname:
        print(_("{hostname} is not a valid FQDN").format(
            subject=options.hostname),
            file=sys.stderr)
        sys.exit(1)

    # Create a keypair for the service certificate
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, options.key_strength)

    # Create a self-signed certificate authority
    svc_cert = crypto.X509()
    svc_cert_name = svc_cert.get_subject()

    # Create the DER name for the certificate
    try:
        svc_cert_name.C = str(options.country)
    except crypto.Error:
        print(_("Country codes must be two characters"),
              file=sys.stderr)
        sys.exit(1)
    svc_cert_name.ST = options.state
    svc_cert_name.L = options.locality
    svc_cert_name.O = options.organization
    svc_cert_name.OU = options.organizational_unit
    svc_cert_name.CN = options.hostname

    svc_cert.set_subject(svc_cert_name)
    svc_cert.set_issuer(ca_cert.get_subject())

    # Set serial and lifespan
    svc_cert.set_serial_number(struct.unpack("Q", rand.bytes(8))[0])
    svc_cert.gmtime_adj_notBefore(0)
    svc_cert.gmtime_adj_notAfter(options.lifetime * 24 * 60 * 60)

    svc_cert.set_pubkey(k)

    # Set constraint extensions
    svc_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints",
                             False,
                             b"CA:FALSE",
                             subject=svc_cert,
                             issuer=ca_cert)])

    # If any subjectAltNames have been provided, include them
    for name in options.subject_alt_names:
        altname = "DNS:{}".format(name).encode()
        svc_cert.add_extensions([
            crypto.X509Extension(b"subjectAltName",
                                 False,
                                 altname,
                                 subject=svc_cert,
                                 issuer=ca_cert)])

    svc_cert.sign(ca_key, options.hash_alg)

    return svc_cert, k
