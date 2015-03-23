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


def write_secure_file(options, destination, data):
    """
    Write out the certificate or key to a temporary file first, then atomically
    copy it to the destination path. This will avoid race-condition bugs with
    checking for file presence and then writing to it. Note: this will clobber
    the destination path.
    """

    # Create the temporary file in the same directory as the destination
    # This ensures that we can atomically move it to the final name.

    f = tempfile.NamedTemporaryFile(dir=os.path.dirname(destination),
                                    delete=False)
    try:
        f.write(data)
        f.flush()
    except IOError as e:
        f.close()
        os.unlink(f.name)
        raise Exception(_("Could not write to {0}. Error: {1}").format(f.name, e))

    # Now atomically move the temporary file into place.
    # We use os.rename because this is guaranteed to be atomic if it succeeds
    # This operation can fail on some flavors of UNIX if the source and
    # destination are on different filesystems, but this should not be the case.
    if options.debug:
        print(_("Renaming {} to {}").format(f.name, destination))

    f.close()
    try:
        os.rename(f.name, destination)
    except IOError as e:
        os.unlink(f.name)
        raise Exception(_("Could not rename to {0}. Error: {1}").format(destination, e))
