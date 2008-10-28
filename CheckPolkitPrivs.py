# vim:sw=4:et
#############################################################################
# File          : CheckPolkitPrivs.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for /etc/polkit-default-privs violations
#############################################################################

from Filter import *
import AbstractCheck
import re
import os
from xml.dom.minidom import parse

_whitelist = ()

class PolkitCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckPolkitPrivs")
        self.privs = {}

        files = [ "/etc/polkit-default-privs.standard" ]

        for file in files:
            if os.path.exists(file):
                self._parsefile(file)

    def _parsefile(self,file):
        for line in open(file):
            line = line.split('#')[0].split('\n')[0]
            if len(line):
                line = re.split(r'\s+', line)
                priv = line[0]
                value = line[1]

                self.privs[priv] = value

    def check(self, pkg):
        global _whitelist

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
                if not bn in _whitelist:
                    printError(pkg, "polkit-unauthorized-file", f)

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
                if f.startswith("/usr/share/PolicyKit/policy/"):
                    f = pkg.dirName() + f
                    xml = parse(f)
                    for a in xml.getElementsByTagName("action"):
                        action = a.getAttribute('id')
                        if not action in self.privs:
                            unauth = 0
                            foundno = 0
                            anyseen = 0
                            try:
                                defaults = a.getElementsByTagName("defaults")[0]
                                for i in defaults.childNodes:
                                    if not i.nodeType == i.ELEMENT_NODE:
                                        continue
                                    if i.nodeName == 'allow_any':
                                        anyseen = 1
                                    if i.firstChild.data.find("auth_admin") != 0:
                                        if i.firstChild.data == 'no':
                                            foundno = 1
                                        else:
                                            unauth = 1
                            except:
                                unauth = 1

                            if unauth:
                                printError(pkg, 'polkit-unauthorized-privilege', action)
                            if foundno or not anyseen:
                                printWarning(pkg, 'polkit-cant-acquire-privilege', action)
            except:
                raise
                continue

check=PolkitCheck()

if Config.info:
    addDetails(
'polkit-unauthorized-file',
"""Please contact security@suse.de for review.""",
'polkit-unauthorized-privilege',
"""Please contact security@suse.de for review.""",
'polkit-cant-acquire-privilege',
"""Usability can be improved by allowing users to acquire privileges
via authentication. Use e.g. 'auth_admin' instead of 'no' and make
sure to define 'allow_any'.""")
