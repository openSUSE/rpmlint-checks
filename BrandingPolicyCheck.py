# vim:sw=4:et
#############################################################################
# File          : BrandingPolicyCheck.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Verify that branding related things comply
#############################################################################

from Filter import *
import AbstractCheck
import rpm
import re
import commands
import stat
import Config
import os
import string
import Pkg

from BinariesCheck import BinaryInfo

class BrandingPolicyCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "BrandingPolicyCheck")

    def check(self, pkg):
        if pkg.isSource():
            return

        pkg_requires = set(map(lambda x: string.split(x[0],'(')[0], pkg.requires()))
        pkg_conflicts = set(map(lambda x: string.split(x[0],'(')[0], pkg.conflicts()))

        # verify that only generic branding is required by non-branding packages
        for r in pkg.requires():
            if (pkg.name.find('-branding-') < 0 and
                    (r[0].find('-theme-') >= 0 or r[0].find('-branding-') >= 0)):
                printError(pkg,'suse-branding-specific-branding-req', r)
            if r[0].endswith('branding') or r[0].endswith('theme'):
                if (r[2] != rpm.RPMSENSE_EQUAL or not r[1].startswith('1')):
                    printError(pkg,'suse-branding-unversioned-req', r[0])

        # verify that it doesn't conflict with branding
        for r in pkg_conflicts:
            if r.find('-theme-') >= 0 or r.find('-branding-') >= 0:
                printError(pkg,'suse-branding-branding-conflict', r)

        if pkg.name.find('-branding-') < 0:
            return

        branding_basename=pkg.name.partition('-branding-')[0]
        branding_style=pkg.name.partition('-branding-')[2]
        generic_branding = ("%s-branding" % (branding_basename))

        pkg_provides = set(map(lambda x: string.split(x[0],'(')[0], pkg.provides()))
        pkg_supplements = set(map(lambda x: x[0], pkg.supplements()))

        # verify that it only supplements with packageand
        found_correct=False
        for s in pkg_supplements:
            if s.startswith('packageand('):
                correct_supplement="packageand(%s:branding-%s)" % (branding_basename, branding_style)
                if s != correct_supplement:
                    printError(pkg,'suse-branding-wrong-branding-supplement', s)
                else:
                    found_correct=True
            else:
                printError(pkg,'suse-branding-excessive-supplement', s)

        if not found_correct:
            printError(pkg,'suse-branding-supplement-missing')

        # nothing else
        for r in pkg.recommends():
            printError(pkg,'suse-branding-excessive-recommends', r[0])
        for r in pkg.suggests():
            printError(pkg,'suse-branding-excessive-suggests', r[0])
        for r in pkg.enhances():
            printError(pkg,'suse-branding-excessive-enhances', r[0])

        # check for provide foo-branding
        branding_provide=None
        for p in pkg.provides():
            if p[0] == generic_branding:
                branding_provide=p
                break

        if not branding_provide:
            printError(pkg,'suse-branding-no-branding-provide')
        else:
            if (len(branding_provide) < 2 or branding_provide[2] != rpm.RPMSENSE_EQUAL):
                printError(pkg, 'suse-branding-unversioned-prov', branding_provide[0])

        for r in pkg.requires():
            if r[0].find('-theme-') >= 0 or r[0].find('-branding-') >= 0:
                if (r[2] != rpm.RPMSENSE_EQUAL or not r[1].startswith('1')):
                    printError(pkg, 'suse-branding-unversioned-req', r[0])


check=BrandingPolicyCheck()

if Config.info:
    addDetails(
'suse-branding-specific-branding-req',
"""bla""",
'suse-branding-no-branding-provides',
"""bla""",
'suse-branding-supplement-missing',
"""branding packages should provide a supplemnent in the form
Supplements: packageand(basepackage:branding-<flavour>)
"""
)
