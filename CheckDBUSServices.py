# vim:sw=4:et
#############################################################################
# File          : CheckDBUSServices.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for DBUS services that are not authorized by the security team
#############################################################################

# http://techbase.kde.org/Development/Tutorials/D-Bus/Autostart_Services

from Filter import *
import AbstractCheck
import re
import os
import string

_services_whitelist = (
    "ConsoleKit.conf",
    "hal.conf",
    "cups.conf", # bnc#515977
    "org.freedesktop.ConsoleKit.service",
    "org.freedesktop.PolicyKit.conf",
    "org.freedesktop.PolicyKit.service",
)

# need to end with / so we don't catch directories
_dbus_system_paths = [
        "/usr/share/dbus-1/system-services/",
        "/etc/dbus-1/system.d/"
]

class DBUSServiceCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckDBUSServices")

    def check(self, pkg):
        global _services_whitelist
        global _dbus_system_paths

        if pkg.isSource():
            return

        files = pkg.files()

        for f in files:
            if f in pkg.ghostFiles():
                continue

            for p in _dbus_system_paths:
                if f.startswith(p):

                    bn = f[len(p):]
                    if not bn in _services_whitelist:
                        printError(pkg, "suse-dbus-unauthorized-service", f)

check=DBUSServiceCheck()

if Config.info:
    addDetails(
'suse-dbus-unauthorized-service',
"""The package installs an unauthorized DBUS service.
Please contact security@suse.de for review.""",
)
