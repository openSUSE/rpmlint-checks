# vim:sw=4:et
#############################################################################
# File          : SupplementsCheck.py
# Package       : rpmlint
# Author        : Stasiek Michalski
# Purpose       : Verify that supplements aren't using the zypp format
#############################################################################

from Filter import addDetails, printError
import AbstractCheck


class SupplementsCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "SupplementsCheck")

    def check(self, pkg):
        if pkg.isSource():
            return

        pkg_supplements = set(map(lambda x: x[0], pkg.supplements()))

        for s in pkg_supplements:
            if s.startswith('packageand('):
                printError(pkg, 'suse-zypp-format-supplements', s)


check = SupplementsCheck()

addDetails(
'suse-zypp-format-supplements',
'''The packageand(package1:package2) format for supplements is deprecated, please use
Supplements: (package1 and package2)''',
)
