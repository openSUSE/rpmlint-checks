# vim:sw=4:et
#############################################################################
# File          : KMPPolicyCheck.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Verify that kmp's have proper dependencies
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

class KMPPolicyCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "KMPPolicyCheck")

    def check(self, pkg):
        if pkg.isSource() or pkg.name.find('-kmp-') < 0:
            return

        pkg_requires = set(map(lambda x: string.split(x[0],'(')[0], pkg.requires()))
        pkg_conflicts = set(map(lambda x: string.split(x[0],'(')[0], pkg.conflicts()))

        kernel_flavour="kernel-" + pkg.name.partition('-kmp-')[2]

        # verify that Requires: kernel_flavour is present
        have_requires=False
        for r in pkg_requires:
            if r == kernel_flavour:
                have_requires = True
                break

        if not have_requires:
            printError(pkg, 'suse-policy-kmp-missing-requires', kernel_flavour)

        # verify that if an enhances is there, it points to the right kernel flavor
        for p in pkg.enhances():
            if p[0].startswith('kernel-'):
                if p[0] != kernel_flavour:
                    printError(pkg, 'suse-policy-kmp-wrong-enhances', p[0])

        # check that only modalias supplements are present
        have_only_modalias=True
        have_modalias=False
        have_proper_suppl=False
        for s in pkg.supplements():
            if s[0].startswith('modalias('):
                have_modalias = True
                continue
            if s[0].startswith('packageand(-%s:' % (kernel_flavour)):
                have_proper_suppl = True

            printWarning(pkg, 'suse-policy-kmp-excessive-supplements', s[0])
            have_only_modalias = False

        if not have_modalias and not have_proper_suppl:
            printError(pkg, 'suse-policy-kmp-missing-supplements')

check=KMPPolicyCheck()

if Config.info:
    addDetails(
'suse-policy-kmp-excessive-supplements',
""" """,
'suse-policy-kmp-missing-supplements',
"""If your kmp modules match some specific hardware, i.e. if the
"find-supplements" search done at the end of a build creates some
modalias() dependencies, you don't need to do anything. If your
module is hardware independent, you need to add the dependencies manually.

To do this, add a preamble (-p) to your %suse_kernel_module_package
macro. the file should look like this:

 Supplements: packageand(kernel-%1:%{-n*})

""",
)
