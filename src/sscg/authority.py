from __future__ import print_function
import sys
import struct
from OpenSSL import crypto, rand

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
        print (_("{host} is not a valid FQDN".format(
                  host=options.hostname)),
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
        print (_("Country codes must be two characters"),
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
    ca_cert.set_serial_number(struct.unpack("Q", rand.bytes(8))[0]);
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

    ca_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints",
                                 False,
                                 b"CA:TRUE",
                                 subject=ca_cert,
                                 issuer=ca_cert)])

    return ca_cert, k
