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
#    "avahi-dbus.conf",
#    "backup-manager.conf",
#    "bluetooth.conf",
#    "com.google.code.BackupManager.service",
#    "com.novell.Pkcs11Monitor.conf",
    "ConsoleKit.conf",
#    "cups.conf",
#    "fi.epitest.hostap.WPASupplicant.service",
#    "galago-daemon.conf",
#    "gdm.conf",
    "hal.conf",
#    "kerneloops.dbus",
#    "knetworkmanager.conf",
#    "NetworkManager.conf",
#    "newprinternotification.conf",
#    "nm-applet.conf",
#    "nm-avahi-autoipd.conf",
#    "nm-dhcp-client.conf",
#    "nm-dispatcher.conf",
#    "nm-novellvpn-service.conf",
#    "nm-openvpn-service.conf",
#    "nm-pptp-service.conf",
#    "nm-system-settings.conf",
#    "nm-vpnc-service.conf",
#    "org.bluez.service",
    "org.freedesktop.ConsoleKit.service",
#    "org.freedesktop.ModemManager.conf",
#    "org.freedesktop.ModemManager.service",
#    "org.freedesktop.NetworkManagerSystemSettings.service",
#    "org.freedesktop.nm_dispatcher.service",
#    "org.freedesktop.PackageKit.conf",
#    "org.freedesktop.PackageKit.service",
    "org.freedesktop.PolicyKit.conf",
    "org.freedesktop.PolicyKit.service",
#    "org.gnome.ClockApplet.Mechanism.conf",
#    "org.gnome.ClockApplet.Mechanism.service",
#    "org.gnome.GConf.Defaults.conf",
#    "org.gnome.GConf.Defaults.service",
#    "org.opensuse.CupsPkHelper.Mechanism.conf",
#    "org.opensuse.CupsPkHelper.Mechanism.service",
#    "org.opensuse.yast.SCR.conf",
#    "org.opensuse.yast.SCR.service",
#    "pommed.conf",
#    "powersave.conf",
#    "upsd.conf",
#    "wpa_supplicant.conf",
#    "xorg-server.conf",
#    "yum-updatesd.conf",
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
                        printError(pkg, "dbus-unauthorized-service", f)

check=DBUSServiceCheck()

if Config.info:
    addDetails(
'dbus-unauthorized-service',
"""The package installs an unauthorized DBUS service.
Please contact security@suse.de for review.""",
)
