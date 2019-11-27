# vim: sw=4 et sts=4 ts=4 :
#############################################################################
# File          : CheckDBUSServices.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for DBUS services that are not authorized by the security team
#############################################################################

# http://techbase.kde.org/Development/Tutorials/D-Bus/Autostart_Services

from Filter import *
import AbstractCheck
import Whitelisting

SERVICES_WHITELIST = Config.getOption('DBUSServices.WhiteList', ())  # set of file names

# need to end with / so we don't catch directories
_dbus_system_paths = [
    "/usr/share/dbus-1/system-services/",
    "/usr/share/dbus-1/system.d/",
    "/etc/dbus-1/system.d/"
]


class DBUSServiceCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckDBUSServices")

    def check(self, pkg):
        global SERVICES_WHITELIST
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
                    if bn not in SERVICES_WHITELIST:
                        printError(pkg, "suse-dbus-unauthorized-service", f)


check = DBUSServiceCheck()

if Config.info:
    for _id, desc in (
        (
            'suse-dbus-unauthorized-service',
            """The package installs a DBUS system service file. If the package
            is intended for inclusion in any SUSE product please open a bug
            report to request review of the service by the security team. Please
            refer to {url} for more information."""
        ),
    ):
        addDetails(_id, desc.format(url=Whitelisting.AUDIT_BUG_URL))
