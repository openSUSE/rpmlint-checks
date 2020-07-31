# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# File          : CheckPAMModules.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for pam modules that are not authorized by the security team
#############################################################################

from Filter import *
import AbstractCheck
import re
import Whitelisting

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
            m = pam_module_re.match(f)
            if m:
                if f in pkg.ghostFiles():
                    printError(pkg, 'suse-pam-ghost-module', f)
                    continue

                bn = m.groups()[0]
                if bn not in PAM_WHITELIST:
                    printError(pkg, "suse-pam-unauthorized-module", bn)


check = PAMModulesCheck()

if Config.info:

    Whitelisting.registerErrorDetails((
        (
            'suse-pam-unauthorized-module',
            """The package installs a PAM module. {review_needed_text}"""
        ),
        (
            'suse-pam-ghost-module',
            """The package installs a PAM module as %ghost file.
            {ghost_encountered_text}"""
        )
    ))
