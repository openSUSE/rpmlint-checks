# vim:sw=4:et
#############################################################################
# File          : CheckIconSizes.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Check for common scaling errors in icons
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

class IconSizesCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckIconSizes")
        self.file_size_regex = re.compile('/icons/[^/]+/(\d+)x(\d+)/')
        self.info_size_regex = re.compile('(\d+) x (\d+)')

    def check(self, pkg):

        if pkg.isSource():
            return

        for fname, pkgfile in pkg.files().items():
            res = self.file_size_regex.search(fname)
            if res:
                sizes = (res.group(1), res.group(2))
                res = self.info_size_regex.search(pkgfile.magic)
                if res:
                    actualsizes = (res.group(1), res.group(2))

                    if abs(int(sizes[0])-int(actualsizes[0])) > 2 or \
                            abs(int(sizes[1])-int(actualsizes[1])) > 2:
                        printError(pkg,"wrong-icon-size", fname, "expected:", 
                                "x".join(sizes), "actual:", "x".join(actualsizes))


check=IconSizesCheck()

if Config.info:
    addDetails(
'wrong-icon-size',
"""Your icon file is installed in a fixed-size directory, but has a largely incorrect size.
Some desktop environments (e.g. GNOME) display them incorrectly."""
)
