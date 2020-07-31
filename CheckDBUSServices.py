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
            for p in _dbus_system_paths:
                if f.startswith(p):

                    if f in pkg.ghostFiles():
                        printError(pkig, "suse-dbus-ghost-service", f)
                        continue

                    bn = f[len(p):]
                    if bn not in SERVICES_WHITELIST:
                        printError(pkg, "suse-dbus-unauthorized-service", f)


check = DBUSServiceCheck()

if Config.info:
    Whitelisting.registerErrorDetails((
        (
            'suse-dbus-unauthorized-service',
            """The package installs a DBUS system service file.
            {review_needed_text}"""
        ),
        (
            'suse-dbus-ghost-service',
            """This package installs a DBUS system service marked as %ghost.
            {ghost_encountered_text}
            """
        )
    ))
