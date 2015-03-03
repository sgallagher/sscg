from __future__ import print_function
import os
import sys
import tempfile
import gettext
from OpenSSL import crypto

PACKAGE = 'sscg'
LOCALEDIR = '/usr/share/locale'
translation = gettext.translation(PACKAGE, LOCALEDIR, fallback=True)
_ = translation.gettext


DEFAULT_CERT_FORMAT = "PEM"
DEFAULT_CA_CERT = "/etc/pki/ca-trust/source/anchors"
DEFAULT_LIFESPAN = 3650  # Ten years
DEFAULT_KEY_STRENGTH = 2048  # 2048-bit encryption
DEFAULT_HASH_ALG = "sha256"

def write_certificate(options, cert, destination):
    """
    Write out the certificate to a temporary file first, then atomically copy
    it to the destination path. This will avoid race-condition bugs with
    checking for file presence and then writing to it. Note: this will clobber
    the destination path.
    """

    # Create the temporary file in the same directory as the destination
    # This ensures that we can atomically move it to the final name.

    try:
        (fd, fpath) = tempfile.mkstemp(dir=os.path.dirname(destination))
        if options.debug:
            print(_("Creating temporary certificate file at {}".format(fpath)))
        f = os.fdopen(fd, "w")

        f.write(crypto.dump_certificate(options.cert_format, cert).decode("UTF-8"))
        f.close()
    except:
        # Something went wrong. Remove the temporary file before failing.
        print(_("Could not write to {0}. Error: {1}".format(
              fpath, sys.exc_info()[1])),
              file=sys.stderr)
        os.unlink(fpath)
        raise

    # Now atomically move the temporary file into place.
    # We use os.rename because this is guaranteed to be atomic if it succeeds
    # This operation can fail on some flavors of UNIX if the source and
    # destination are on different filesystems, but this should not be the case.
    try:
        if options.debug:
            print(_("Renaming {} to {}".format(fpath, destination)))
        os.rename(fpath, destination)
    except:
        # Something went wrong. Remove the temporary file before failing.
        print(_("Could not rename to {0}. Error: {1}".format(
              destination, sys.exc_info()[1])))
        os.unlink(fpath)
        raise


def write_certificate_key(options, key, destination, cipher=None, passphrase=None):
    """
    Write out the certificate key to a temporary file first, then atomically
    copy it to the destination path. This will avoid race-condition bugs with
    checking for file presence and then writing to it. Note: this will clobber
    the destination path.
    """

    # Create the temporary file in the same directory as the destination
    # This ensures that we can atomically move it to the final name.

    try:
        (fd, fpath) = tempfile.mkstemp(dir=os.path.dirname(destination))
        if options.debug:
            print(_("Creating temporary keyfile at {}".format(fpath)))

        f = os.fdopen(fd, "w")

        f.write(crypto.dump_privatekey(options.cert_format, key, cipher, passphrase).decode("UTF-8"))
        f.close()
    except:
        # Something went wrong. Remove the temporary file before failing.
        print(_("Could not write to {0}. Error: {1}".format(
              fpath, sys.exc_info()[1])),
              file=sys.stderr)
        os.unlink(fpath)
        raise

    # Now atomically move the temporary file into place.
    # We use os.rename because this is guaranteed to be atomic if it succeeds
    # This operation can fail on some flavors of UNIX if the source and
    # destination are on different filesystems, but this should not be the case.
    try:
        if options.debug:
            print(_("Renaming {} to {}".format(fpath, destination)))
        os.rename(fpath, destination)
    except:
        # Something went wrong. Remove the temporary file before failing.
        print(_("Could not rename to {0}. Error: {1}".format(
              destination, sys.exc_info()[1])))
        os.unlink(fpath)
        raise
