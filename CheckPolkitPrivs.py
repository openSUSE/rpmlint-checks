# vim: sw=4 et sts=4 ts=4 :
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
import Whitelisting
from xml.dom.minidom import parse

POLKIT_PRIVS_WHITELIST = Config.getOption('PolkitPrivsWhiteList', ())   # set of file names
POLKIT_PRIVS_FILES = Config.getOption('PolkitPrivsFiles', ["/etc/polkit-default-privs.standard"])
# path to JSON files containing whitelistings for files in rules.d directories
POLKIT_RULES_WHITELIST = Config.getOption('PolkitRulesWhitelist', ())


class PolkitCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckPolkitPrivs")
        self.privs = {}
        self._collect_privs()
        self._collect_rules_whitelist()

    def _get_err_prefix(self):
        """error prefix label to be used for early error printing."""
        return self.__class__.__name__ + ":"

    def _collect_privs(self):
        for filename in POLKIT_PRIVS_FILES:
            if os.path.exists(filename):
                self._parse_privs_file(filename)

    def _parse_privs_file(self, filename):
        with open(filename) as inputfile:
            for line in inputfile:
                line = line.split('#')[0].split('\n')[0]
                if len(line):
                    line = re.split(r'\s+', line)
                    priv = line[0]
                    value = line[1]

                    self.privs[priv] = value

    def _collect_rules_whitelist(self):
        rules_entries = {}
        for filename in POLKIT_RULES_WHITELIST:
            if not os.path.exists(filename):
                continue
            parser = Whitelisting.WhitelistParser(filename)
            res = parser.parse()
            rules_entries.update(res)

        self.m_rules_checker = Whitelisting.WhitelistChecker(
            rules_entries,
            restricted_paths=(
                "/etc/polkit-1/rules.d/", "/usr/share/polkit-1/rules.d/"
            ),
            error_map={
                "unauthorized": "polkit-unauthorized-rules",
                "changed": "polkit-changed-rules",
                "ghost": "polkit-ghost-file"
            }
        )

    def check_perm_files(self, pkg):
        """Checks files in polkit-default-privs.d."""

        files = pkg.files()
        prefix = "/etc/polkit-default-privs.d/"
        profiles = ("restrictive", "standard", "relaxed")

        permfiles = []
        # first pass, find additional files
        for f in files:

            if f.startswith(prefix):

                if f in pkg.ghostFiles():
                    printError(pkg, 'polkit-ghost-file', f)
                    continue

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
                    self._parse_privs_file(path)
                    break
            else:
                self._parse_privs_file(f)

    def check_actions(self, pkg):
        """Checks files in the actions directory."""

        files = pkg.files()
        prefix = "/usr/share/polkit-1/actions/"

        for f in files:
            # catch xml exceptions
            try:
                if f.startswith(prefix):
                    if f in pkg.ghostFiles():
                        printError(pkg, 'polkit-ghost-file', f)
                        continue

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

    def check_rules(self, pkg):
        """Process files and whitelist for entries in rules.d dirs."""

        self.m_rules_checker.check(pkg)

    def check(self, pkg):

        if pkg.isSource():
            return

        self.check_perm_files(pkg)
        self.check_actions(pkg)
        self.check_rules(pkg)


check = PolkitCheck()

for _id, desc in (
        (
            'polkit-unauthorized-file',
            """A custom polkit rule file is installed by this package. If the package is
            intended for inclusion in any SUSE product please open a bug report to request
            review of the package by the security team. Please refer to {url} for more
            information"""
        ),
        (
            'polkit-unauthorized-privilege',
            """The package allows unprivileged users to carry out privileged
            operations without authentication. This could cause security
            problems if not done carefully. If the package is intended for
            inclusion in any SUSE product please open a bug report to request
            review of the package by the security team. Please refer to {url}
            for more information."""
        ),
        (
            'polkit-untracked-privilege',
            """The privilege is not listed in /etc/polkit-default-privs.*
            which makes it harder for admins to find. Furthermore polkit
            authorization checks can easily introduce security issues. If the
            package is intended for inclusion in any SUSE product please open
            a bug report to request review of the package by the security team.
            Please refer to {url} for more information."""
        ),
        (
            'polkit-cant-acquire-privilege',
            """Usability can be improved by allowing users to acquire privileges
            via authentication. Use e.g. 'auth_admin' instead of 'no' and make
            sure to define 'allow_any'. This is an issue only if the privilege
            is not listed in /etc/polkit-default-privs.*"""
        ),
        (
            'polkit-unauthorized-rules',
            """A polkit rules file installed by this package is not whitelisted in the
            polkit-whitelisting package. If the package is intended for inclusion in any
            SUSE product please open a bug report to request review of the package by the
            security team. Please refer to {url} for more information."""
        ),
        (
            'polkit-changed-rules',
            """A polkit rules file installed by this package changed in content. Please
            open a bug report to request follow-up review of the introduced changes by
            the security team. Please refer to {url} for more information."""
        ),
        (
            'polkit-ghost-file',
            """This package installs a polkit rule or policy as %ghost file.
            This is not allowed as it is impossible to review. For more
            information please refer to {url} for more information."""
        )
):
    addDetails(_id, desc.format(url=Whitelisting.AUDIT_BUG_URL))
