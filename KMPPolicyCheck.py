# vim:sw=4:et
#############################################################################
# File          : KMPPolicyCheck.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Verify that kmp's have proper dependencies
#############################################################################

from Filter import *
import AbstractCheck
import Config
import string


class KMPPolicyCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "KMPPolicyCheck")

    def check(self, pkg):
        if pkg.isSource() or pkg.name.find('-kmp-') < 0:
            return

        pkg_requires = set(map(lambda x: string.split(x[0], '(')[0], pkg.requires()))

        kernel_flavour = "kernel-" + pkg.name.partition('-kmp-')[2]

        # verify that Requires: kernel_flavour is present
        have_requires = False
        for r in pkg_requires:
            if r == kernel_flavour:
                have_requires = True
                break

        if not have_requires:
            printError(pkg, 'suse-policy-kmp-missing-requires', kernel_flavour)

        # verify that exactly one enhances on the kernel flavor is present
        if len(pkg.enhances()) > 1:
            printError(pkg, 'suse-policy-kmp-excessive-enhances', str(pkg.enhances()))
        elif len(pkg.enhances()) < 1:
            printError(pkg, 'suse-policy-kmp-missing-enhances', kernel_flavour)

        # check that only modalias supplements are present
        have_modalias = False
        have_proper_suppl = False
        for s in pkg.supplements():
            if s[0].startswith('modalias('):
                have_modalias = True
                continue
            if s[0].startswith('packageand(%s:' % (kernel_flavour)):
                have_proper_suppl = True
                continue

            printWarning(pkg, 'suse-policy-kmp-excessive-supplements', s[0])

        if not have_modalias and not have_proper_suppl:
            printError(pkg, 'suse-policy-kmp-missing-supplements')


check = KMPPolicyCheck()

if Config.info:
    addDetails(
'suse-policy-kmp-missing-requires',
"""Make sure you have extended '%kernel_module_package' by
 '-p %_sourcedir/preamble', a file named 'preamble' as source and there
 specified 'Requires: kernel-%1'.
 """,
'suse-policy-kmp-excessive-enhances',
""" """,
'suse-policy-kmp-missing-enhances',
"""Make sure you have extended '%kernel_module_package' by
 '-p %_sourcedir/preamble', a file named 'preamble' as source and there
 specified 'Enhances: kernel-%1'.
 """,
'suse-policy-kmp-excessive-supplements',
""" """,
'suse-policy-kmp-missing-supplements',
"""Make sure your 'BuildRequires:' include 'kernel-syms' and 'modutils'
for proper dependencies to be built.
""",
)
