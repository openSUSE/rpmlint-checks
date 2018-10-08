# vim:sw=4:et
#############################################################################
# File          : CheckPAMModules.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for pam modules that are not authorized by the security team
#############################################################################

from Filter import *
import AbstractCheck
import re

PAM_WHITELIST = Config.getOption('PAMModules.WhiteList', ())  # set of file names

pam_module_re = re.compile(r'^(?:/usr)?/lib(?:64)?/security/([^/]+\.so)$')


class PAMModulesCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckPAMModules")

    def check(self, pkg):
        global PAM_WHITELIST

        if pkg.isSource():
            return

        files = pkg.files()

        for f in files:
            if f in pkg.ghostFiles():
                continue

            m = pam_module_re.match(f)
            if m:
                bn = m.groups()[0]
                if bn not in PAM_WHITELIST:
                    printError(pkg, "suse-pam-unauthorized-module", bn)


check = PAMModulesCheck()

if Config.info:
    addDetails(
'suse-pam-unauthorized-module',
"""The package installs a PAM module. If the package
is intended for inclusion in any SUSE product please open a bug
report to request review of the service by the security team.
Please refer to https://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs""",
)
