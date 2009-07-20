# vim:sw=4:et
#############################################################################
# File          : DuplicatesCheck.py
# Package       : rpmlint
# Author        : Stephan Kulow
# Purpose       : Check for duplicate files being packaged separately
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

def get_prefix(file):
    pathlist = string.split(file, '/')
    if len(pathlist) == 3:
        return "/".join(pathlist[0:2])

    return "/".join(pathlist[0:3])

class DuplicatesCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "DuplicatesCheck")

    def check(self, pkg):

        if pkg.isSource():
            return

        md5s = {}
        sizes = {}
        files = pkg.files()
        configFiles = pkg.configFiles()

        for f, pkgfile in files.items():
            if f in pkg.ghostFiles():
                continue

            if not stat.S_ISREG(pkgfile.mode):
                continue

            md5s.setdefault(pkgfile.md5, set()).add(f)
            sizes[pkgfile.md5] = pkgfile.size

        sum=0
        for f in md5s:
            duplicates=md5s[f]
            if len(duplicates) == 1: continue

            one=duplicates.pop()
            one_is_config = False
            if one in configFiles:
                one_is_config = True

            partition=get_prefix(one)

            st = os.stat(pkg.dirName() + '/' + one)
            diff = 1 + len(duplicates) - st[stat.ST_NLINK]
            if diff <= 0: 
                for dupe in duplicates:
                    if partition != get_prefix(dupe):
                        printError(pkg,"hardlink-across-partition",one,dupe)
                    if one_is_config and dupe in configFiles:
                        printError(pkg,"hardlink-across-config-files",one,dupe)
                continue

            for dupe in duplicates:
                if partition != get_prefix(dupe):
                    diff = diff - 1
            sum += sizes[f] * diff
            if sizes[f] and diff > 0:
                printWarning(pkg, 'files-duplicate', one,":".join(duplicates))

        if sum > 100000:
            printError(pkg, 'files-duplicated-waste', sum)

check=DuplicatesCheck()

if Config.info:
    addDetails(
'files-duplicated-waste',
"""Your package contains duplicated files that are not hard- or symlinks.
You should use the %fdupes macro to link the files to one.""",
'hardlink-across-partition',
"""Your package contains two files that are apparently hardlinked and
that are likely on different partitions. Installation of such an RPM will fail
due to RPM being unable to unpack the hardlink. do not hardlink across
the first two levels of a path, e.g. between /srv/ftp and /srv/www or
/etc and /usr. """,
'hardlink-across-config-files',
"""Your package contains two config files that are apparently hardlinked.
Hardlinking a config file is probably not what you want. Please double
check and report false positives."""
)
