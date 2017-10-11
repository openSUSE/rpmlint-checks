# vim:sw=4:et
#############################################################################
# File          : BrandingPolicyCheck.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Verify that branding related things comply
#############################################################################

from Filter import *
import AbstractCheck
import Config
import rpm
import string
import Pkg

class BrandingPolicyCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "BrandingPolicyCheck")

    def check(self, pkg):
        if pkg.isSource():
            return

        pkg_requires = set(map(lambda x: string.split(x[0], '(')[0], pkg.requires()))
        pkg_conflicts = set(map(lambda x: x[0], pkg.conflicts()))

        # verify that only generic branding is required by non-branding packages
        for r in pkg.requires():
            if r[0].startswith("config("):
                continue
            if (pkg.name.find('-branding-') < 0 and
                    (r[0].find('-theme-') >= 0 or r[0].find('-branding-') >= 0)):
                printError(pkg, 'suse-branding-specific-branding-req', r[0])
            if (r[0].endswith('branding') or r[0].endswith('theme')) \
                    and not r[0].endswith('-icon-theme'):
                # XXX: that startswith 1 breaks with openSUSE 20...
                if (r[1] != rpm.RPMSENSE_EQUAL or not r[2][1].startswith('1')):
                    printError(pkg, 'suse-branding-unversioned-requires', r[0])

        # verify that it doesn't conflict with branding
        for r in pkg_conflicts:
            if r.startswith("otherproviders("):
                continue
            if r.find('-theme-') >= 0 or r.find('-branding-') >= 0:
                printError(pkg, 'suse-branding-branding-conflict', r)

        if pkg.name.find('-branding-') < 0:
            return

        branding_basename = pkg.name.partition('-branding-')[0]
        branding_style = pkg.name.partition('-branding-')[2]
        generic_branding = ("%s-branding" % (branding_basename))

        pkg_provides = set(map(lambda x: string.split(x[0], '(')[0], pkg.provides()))
        pkg_supplements = set(map(lambda x: x[0], pkg.supplements()))

        # verify that it only supplements with packageand
        found_correct = False
        correct_supplement = "packageand(%s:branding-%s)" % (branding_basename, branding_style)
        for s in pkg_supplements:
            if s.startswith('packageand('):
                if s != correct_supplement:
                    printError(pkg,'suse-branding-wrong-branding-supplement', s)
                else:
                    found_correct = True
            else:
                printError(pkg, 'suse-branding-excessive-supplement', s)

        if not found_correct:
            printError(pkg, 'suse-branding-supplement-missing', correct_supplement)

        # nothing else
        for r in pkg.recommends():
            printError(pkg, 'suse-branding-excessive-recommends', r[0])
        for r in pkg.suggests():
            printError(pkg, 'suse-branding-excessive-suggests', r[0])
        for r in pkg.enhances():
            printError(pkg, 'suse-branding-excessive-enhances', r[0])

        # check for provide foo-branding
        branding_provide = None
        for p in pkg.provides():
            if p[0] == generic_branding:
                branding_provide = p
                break

        # check for Conflicts: otherproviders(kde4-kdm-branding)
        conflict_prop = "otherproviders(%s)" % (generic_branding)
        have_conflict_prop = False
        for c in pkg_conflicts:
            if c == conflict_prop:
                have_conflict_prop = True
                break

        if not have_conflict_prop:
            printError(pkg, 'suse-branding-missing-conflicts', conflict_prop)

        if not branding_provide:
            printError(pkg, 'suse-branding-no-branding-provide')
        else:
            if (len(branding_provide) < 2 or branding_provide[1] != rpm.RPMSENSE_EQUAL):
                printError(pkg, 'suse-branding-unversioned-provides', branding_provide[0])


check = BrandingPolicyCheck()

if Config.info:
    addDetails(
'suse-branding-specific-branding-req',
"""packages must not require a specific branding or theme package to allow for differnt themes""",
'suse-branding-no-branding-provides',
"""Please add a provides entry similar to 'Provides: %name-branding = %version'.""",
'suse-branding-unversioned-provides',
"""Please make sure that your provides entry reads like 'Provides: %name-branding = %version'.""",
'suse-branding-supplement-missing',
"""branding packages should provide a supplemnent in the form
Supplements: packageand(basepackage:branding-<flavour>)
""",
'suse-branding-unversioned-requires',
"""Please make sure that your requires entry reads like 'Requires: %name-branding = <versionnumber>'.""",
'suse-branding-missing-conflicts',
"""Any branding flavor package that provides the generic branding
must also conflict with all other branding packages via a special
otherproviders()""",
)
