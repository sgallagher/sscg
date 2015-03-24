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

# Translation header
PACKAGE = 'sscg'
LOCALEDIR = '/usr/share/locale'
translation = gettext.translation(PACKAGE, LOCALEDIR, fallback=True)
_ = translation.gettext


def create_temp_ca(options):
    """
    Create a temporary Certificate authority that will be used to sign a
    single service certificate. We will not save the private key for this
    signing authority, so it cannot be used to sign other certificates in the
    future.
    """

    # Make sure the subject looks like an FQDN
    # We'll just take a simplistic approach and assume
    # that as long as it has a dot in it, it's an FQDN.
    # The worst-case here is that we create a certificate
    # that fails validation.
    if "." not in options.hostname:
        print(_("{host} is not a valid FQDN").format(
            host=options.hostname),
            file=sys.stderr)
        sys.exit(1)

    # Create a keypair for the temporary CA
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, options.key_strength)

    # Create a self-signed certificate authority
    ca_cert = crypto.X509()
    ca_cert_name = ca_cert.get_subject()

    # Create the DER name for the certificate
    try:
        ca_cert_name.C = str(options.country)
    except crypto.Error:
        print(_("Country codes must be two characters"),
              file=sys.stderr)
        sys.exit(1)
    ca_cert_name.ST = options.state
    ca_cert_name.L = options.locality
    ca_cert_name.O = options.organization
    ca_cert_name.OU = options.package
    ca_cert_name.CN = "{}.{}".format(options.package,
                                     options.hostname)

    ca_cert.set_subject(ca_cert_name)

    # Set serial and lifespan
    ca_cert.set_serial_number(struct.unpack("Q", rand.bytes(8))[0])
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(options.lifetime * 24 * 60 * 60)

    # The CA certificate is self-issued and signed
    ca_cert.set_issuer(ca_cert_name)
    ca_cert.set_pubkey(k)
    ca_cert.sign(k, options.hash_alg)

    # Set constraint extensions
    # They are added in separate actions because otherwise
    # authorityKeyIdentifier will fail to find the
    # subjectKeyIdentifier
    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier",
                             False,
                             b"hash",
                             subject=ca_cert,
                             issuer=ca_cert)])
    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier",
                             False,
                             b"keyid:always,issuer",
                             subject=ca_cert,
                             issuer=ca_cert)])

    # This is a CA certificate
    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints",
                             False,
                             b"CA:TRUE",
                             subject=ca_cert,
                             issuer=ca_cert)])

    # Limit this certificate to signing only the requested hostname
    nameconstraint = "permitted;DNS:{}".format(options.hostname).encode()
    ca_cert.add_extensions([
        crypto.X509Extension(b"nameConstraints",
                             True,
                             nameconstraint,
                             subject=ca_cert,
                             issuer=ca_cert)])

    return ca_cert, k
