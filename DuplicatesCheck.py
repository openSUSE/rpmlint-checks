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
    return string.join(string.split(file, '/')[0:3], '/')

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
        for f in files.keys():
            if f in pkg.ghostFiles():
                continue
            enreg = files[f]
            mode = enreg[0]
            links = enreg[3]
            size = enreg[4]
            md5 = enreg[5]
            rdev = enreg[7]

            if not stat.S_ISREG(mode):
                continue
            if not md5s.has_key(md5):
               md5s[md5] = []
            md5s[md5].append(f)
            sizes[md5] = size
            #print f, links, size, md5, rdev

        sum=0
        for f in md5s.keys():
            if len(md5s[f]) == 1: continue
            st = os.stat(pkg.dirName() + '/' + md5s[f][0])
            diff = len(md5s[f]) - st[stat.ST_NLINK]
            if diff <= 0: continue
            prefix=get_prefix(md5s[f][0])
            for idx in range(1, len(md5s[f])):
                if prefix != get_prefix(md5s[f][idx]):
                    diff = diff - 1
            sum += sizes[f] * diff

        if sum > 100000:
            printError(pkg, 'files-duplicated-waste', sum)

check=DuplicatesCheck()

if Config.info:
    addDetails(
'files-duplicated-waste',
"""Your package contains duplicated files that are not hard- or symlinks.
You should use fdupes to link the files to one."""
)
