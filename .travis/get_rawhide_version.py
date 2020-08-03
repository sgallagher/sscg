#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This file is part of sscg
# Copyright (C) 2020 Stephen Gallagher
#
# Fedora-License-Identifier: MIT
# SPDX-2.0-License-Identifier: MIT
# SPDX-3.0-License-Identifier: MIT
#
# This program is free software.
# For more information on the license, see COPYING.
# For more information on free software, see
# <https://www.gnu.org/philosophy/free-sw.en.html>.

import xmlrpc.client
import time

KOJI_URL = "https://koji.fedoraproject.org/kojihub"


def get_fedora_rawhide_version(session):
    # Koji sometimes disconnects for no apparent reason. Retry up to 5
    # times before failing.
    for attempt in range(5):
        try:
            build_targets = session.getBuildTargets("rawhide")
        except requests.exceptions.ConnectionError:
            logging.warning(
                "Connection lost while retrieving rawhide branch, retrying..."
            )
        else:
            # Succeeded this time, so break out of the loop
            break
        time.sleep(3)

    return build_targets[0]["build_tag_name"].partition("-build")[0][1:]


def main():
    session = xmlrpc.client.ServerProxy(KOJI_URL)
    print(get_fedora_rawhide_version(session))


if __name__ == "__main__":
    main()
