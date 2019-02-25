# vim:sw=4:et
#############################################################################
# File          : CheckPolkitPrivs.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for /etc/polkit-default-privs violations
#############################################################################

from Filter import *
import AbstractCheck
import Config
import re
import os
from xml.dom.minidom import parse


POLKIT_PRIVS_WHITELIST = Config.getOption('PolkitPrivsWhiteList', ())   # set of file names
POLKIT_PRIVS_FILES = Config.getOption('PolkitPrivsFiles', ["/etc/polkit-default-privs.standard"])


class PolkitCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckPolkitPrivs")
        self.privs = {}

        for filename in POLKIT_PRIVS_FILES:
            if os.path.exists(filename):
                self._parsefile(filename)

    def _parsefile(self, filename):
        with open(filename) as inputfile:
            for line in inputfile:
                line = line.split('#')[0].split('\n')[0]
                if len(line):
                    line = re.split(r'\s+', line)
                    priv = line[0]
                    value = line[1]

                    self.privs[priv] = value

    def check_perm_files(self, pkg):
        """Checks files in polkit-default-privs.d."""

        files = pkg.files()
        prefix = "/etc/polkit-default-privs.d/"
        profiles = ("restrictive", "standard", "relaxed")

        permfiles = []
        # first pass, find additional files
        for f in files:
            if f in pkg.ghostFiles():
                continue

            if f.startswith(prefix):

                bn = f[len(prefix):]
                if bn not in POLKIT_PRIVS_WHITELIST:
                    printError(pkg, "polkit-unauthorized-file", f)

                parts = bn.rsplit('.', 1)

                if len(parts) == 2 and parts[-1] in profiles:
                    bn = parts[0]

                if bn not in permfiles:
                    permfiles.append(bn)

        for f in sorted(permfiles):
            f = pkg.dirName() + prefix + f

            for profile in profiles:
                path = '.'.join(f, profile)
                if os.path.exists(path):
                    self._parsefile(path)
                    break
            else:
                self._parsefile(f)

    def check_actions(self, pkg):
        """Checks files in the actions directory."""

        files = pkg.files()
        prefix = "/usr/share/polkit-1/actions/"

        for f in files:
            if f in pkg.ghostFiles():
                continue

            # catch xml exceptions
            try:
                if f.startswith(prefix):
                    xml = parse(pkg.dirName() + f)
                    for a in xml.getElementsByTagName("action"):
                        self.check_action(pkg, a)
            except Exception as x:
                printError(pkg, 'rpmlint-exception', "%(file)s raised an exception: %(x)s" % {'file': f, 'x': x})
                continue

    def check_action(self, pkg, action):
        """Inspect a single polkit action used by an application."""
        action_id = action.getAttribute('id')

        if action_id in self.privs:
            # the action is explicitly whitelisted, nothing else to do
            return

        allow_types = ('allow_any', 'allow_inactive', 'allow_active')
        foundunauthorized = False
        foundno = False
        foundundef = False
        settings = {}
        try:
            defaults = action.getElementsByTagName("defaults")[0]
            for i in defaults.childNodes:
                if not i.nodeType == i.ELEMENT_NODE:
                    continue

                if i.nodeName in allow_types:
                    settings[i.nodeName] = i.firstChild.data
        except KeyError:
            foundunauthorized = True

        for i in allow_types:
            if i not in settings:
                foundundef = True
                settings[i] = '??'
            elif settings[i].find("auth_admin") != 0:
                if settings[i] == 'no':
                    foundno = True
                else:
                    foundunauthorized = True

        action_settings = "{} ({}:{}:{})".format(
            action_id,
            *(settings[type] for type in allow_types)
        )

        if foundunauthorized:
            printError(
                pkg, 'polkit-unauthorized-privilege', action_settings)
        else:
            printError(
                pkg, 'polkit-untracked-privilege', action_settings)

        if foundno or foundundef:
            printInfo(
                pkg, 'polkit-cant-acquire-privilege', action_settings)

    def check(self, pkg):

        if pkg.isSource():
            return

        self.check_perm_files(pkg)
        self.check_actions(pkg)


check = PolkitCheck()

AUDIT_BUG_URL = "https://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs"

addDetails(
'polkit-unauthorized-file',
"""A custom polkit rule file is installed by this package. If the package is
intended for inclusion in any SUSE product please open a bug report to request
review of the package by the security team. Please refer to {} for more
information""".format(AUDIT_BUG_URL),

'polkit-unauthorized-privilege',
"""The package allows unprivileged users to carry out privileged
operations without authentication. This could cause security
problems if not done carefully. If the package is intended for
inclusion in any SUSE product please open a bug report to request
review of the package by the security team. Please refer to {}
for more information.""".format(AUDIT_BUG_URL),

'polkit-untracked-privilege',
"""The privilege is not listed in /etc/polkit-default-privs.*
which makes it harder for admins to find. Furthermore polkit
authorization checks can easily introduce security issues. If the
package is intended for inclusion in any SUSE product please open
a bug report to request review of the package by the security team.
Please refer to {} for more information.""".format(AUDIT_BUG_URL),

'polkit-cant-acquire-privilege',
"""Usability can be improved by allowing users to acquire privileges
via authentication. Use e.g. 'auth_admin' instead of 'no' and make
sure to define 'allow_any'. This is an issue only if the privilege
is not listed in /etc/polkit-default-privs.*""")
