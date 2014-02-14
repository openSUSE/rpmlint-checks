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

POLKIT_PRIVS_WHITELIST = Config.getOption('PolkitPrivsWhiteList', ()) # set of file names
POLKIT_PRIVS_FILES = Config.getOption('PolkitPrivsFiles', [ "/etc/polkit-default-privs.standard" ])

class PolkitCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckPolkitPrivs")
        self.privs = {}

        for filename in POLKIT_PRIVS_FILES:
            if os.path.exists(filename):
                self._parsefile(filename)

    def _parsefile(self,filename):
        for line in open(filename):
            line = line.split('#')[0].split('\n')[0]
            if len(line):
                line = re.split(r'\s+', line)
                priv = line[0]
                value = line[1]

                self.privs[priv] = value

    def check(self, pkg):

        if pkg.isSource():
            return

        files = pkg.files()

        permfiles = {}
        # first pass, find additional files
        for f in files:
            if f in pkg.ghostFiles():
                continue

            if f.startswith("/etc/polkit-default-privs.d/"):

                bn = f[28:]
                if not bn in POLKIT_PRIVS_WHITELIST:
                    printError(pkg, "polkit-unauthorized-file", f)

                if bn.endswith(".restrictive") or bn.endswith(".standard") or bn.endswith(".relaxed"):
                    bn = bn.split('.')[0]

                if not bn in permfiles:
                    permfiles[bn] = 1

        for f in permfiles:
            f = pkg.dirName() + "/etc/polkit-default-privs.d/" + f

            if os.path.exists(f+".restrictive"):
                self._parsefile(f + ".restrictive")
            elif os.path.exists(f+".standard"):
                self._parsefile(f + ".standard")
            elif os.path.exists(f+".relaxed"):
                self._parsefile(f + ".relaxed")
            else:
                self._parsefile(f)


        for f in files:
            if f in pkg.ghostFiles():
                continue

            # catch xml exceptions
            try:
                if f.startswith("/usr/share/PolicyKit/policy/")\
                or f.startswith("/usr/share/polkit-1/actions/"):
                    xml = parse(pkg.dirName() + f)
                    for a in xml.getElementsByTagName("action"):
                        action = a.getAttribute('id')
                        if not action in self.privs:
                            iserr = 0
                            foundno = 0
                            foundundef = 0
                            settings = {}
                            try:
                                defaults = a.getElementsByTagName("defaults")[0]
                                for i in defaults.childNodes:
                                    if not i.nodeType == i.ELEMENT_NODE:
                                        continue

                                    if i.nodeName in ('allow_any', 'allow_inactive', 'allow_active'):
                                        settings[i.nodeName] = i.firstChild.data

                            except:
                                iserr = 1

                            for i in ('allow_any', 'allow_inactive', 'allow_active'):
                                if not i in settings:
                                    foundundef = 1
                                    settings[i] = '??'
                                elif settings[i].find("auth_admin") != 0:
                                    if settings[i] == 'no':
                                        foundno = 1
                                    else:
                                        iserr = 1

                            if iserr:
                                printError(pkg, 'polkit-unauthorized-privilege', '%s (%s:%s:%s)' % (action, \
                                    settings['allow_any'], settings['allow_inactive'], settings['allow_active']))
                            else:
                                printInfo(pkg, 'polkit-untracked-privilege', '%s (%s:%s:%s)' % (action, \
                                    settings['allow_any'], settings['allow_inactive'], settings['allow_active']))

                            if foundno or foundundef:
                                printInfo(pkg,
                                        'polkit-cant-acquire-privilege', '%s (%s:%s:%s)' % (action, \
                                    settings['allow_any'], settings['allow_inactive'], settings['allow_active']))

            except Exception as x:
                printError(pkg, 'rpmlint-exception', "%(file)s raised an exception: %(x)s" % {'file':f, 'x':x})
                continue

check=PolkitCheck()

if Config.info:
    addDetails(
'polkit-unauthorized-file',
"""If the package is intended for inclusion in any SUSE product
please open a bug report to request review of the package by the
security team""",
'polkit-unauthorized-privilege',
"""The package allows unprivileged users to carry out privileged
operations without authentication. This could cause security
problems if not done carefully. If the package is intended for
inclusion in any SUSE product please open a bug report to request
review of the package by the security team""",
'polkit-untracked-privilege',
"""The privilege is not listed in /etc/polkit-default-privs.*
which makes it harder for admins to find. If the package is intended
for inclusion in any SUSE product please open a bug report to
request review of the package by the security team""",
'polkit-cant-acquire-privilege',
"""Usability can be improved by allowing users to acquire privileges
via authentication. Use e.g. 'auth_admin' instead of 'no' and make
sure to define 'allow_any'. This is an issue only if the privilege
is not listed in /etc/polkit-default-privs.*""")
