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
import os
import sys
import tempfile
import gettext

PACKAGE = 'sscg'
LOCALEDIR = '/usr/share/locale'
translation = gettext.translation(PACKAGE, LOCALEDIR, fallback=True)
_ = translation.gettext

DEFAULT_CERT_FORMAT = "PEM"
DEFAULT_CA_CERT = "/etc/pki/ca-trust/source/anchors"
DEFAULT_LIFESPAN = 3650  # Ten years
DEFAULT_KEY_STRENGTH = 2048  # 2048-bit encryption
DEFAULT_HASH_ALG = "sha256"


class SSCGIOError(Exception):
    pass


class SSCGBadInputError(Exception):
    pass


def write_secure_file(options, destination, data):
    """
    Write out the certificate or key to a temporary file first, then atomically
    copy it to the destination path. This will avoid race-condition bugs with
    checking for file presence and then writing to it. Note: this will clobber
    the destination path.
    """

    # Create the temporary file in the same directory as the destination
    # This ensures that we can atomically move it to the final name.

    try:
        f = tempfile.NamedTemporaryFile(dir=os.path.dirname(destination),
                                        delete=False)
    except PermissionError:
        raise SSCGIOError(_("Could not create tempfile in {0}. Error: {1}").format(
                            os.path.dirname(destination), sys.exc_info()[1]))

    try:
        f.write(data)
        f.flush()
    except IOError as e:
        f.close()
        os.unlink(f.name)
        raise SSCGIOError(_("Could not write to {0}. Error: {1}").format(f.name, e))

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
        raise SSCGIOError(_("Could not rename to {0}. Error: {1}").format(destination, e))
