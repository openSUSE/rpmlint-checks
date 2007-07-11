# vim:sw=4:et
#############################################################################
# File          : CheckCommonFiles.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Check for common files being packaged
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

class CommonFilesCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "CommonFilesCheck")

    def check(self, pkg):

        if pkg.isSource():
            return
        files = pkg.files()
        for f in files:
            if f in pkg.ghostFiles():
                continue
            enreg = files[f]
            mode = enreg[0]
            links = enreg[3]
            size = enreg[4]
            md5 = enreg[5]
            rdev = enreg[7]

            if len(md5) and md5 in (
                    'c59cbaf0df9bcf35feca0d0f1fc01dae',
                    'cf8c4d1a5ab88db006c47ae2b51a6b30',
                    '5d4638159851671944108691f23e4f28',
                    '0d6be33865b76025c20b48bcac87adb7'):
                printError(pkg, "generic-build-instructions", f)

            if len(md5) and md5 in (
                    '94d55d512a9ba36caa9b7df079bae19f'):
                printError(pkg, "duplicated-file-gpl-v2", f)

            # bsd causes the false positive COPYING.BSD
            if len(md5) and f.rsplit('/',1)[1][0].lower() == 'r' and f.rsplit('.',1)[-1].lower() in (
              'aix', 'bsd', 'dos', 'hpux', 'irix', 'os2', 'mac', 'macos', 'tru64',
              'sco', 'vms', 'win32', 'win', 'solaris'):
                printWarning(pkg, "non-linux-readme", f)

check=CommonFilesCheck()

if Config.info:
    addDetails(
'generic-build-instructions',
"""Your package contains a file that contains the FSF generic
configure/make/make install instructions. Those are useless
for a binary package. Consider removing it to save 3kb of rpm size.""",

'duplicated-file-gpl-v2',
"""Your package contains a file that contains the FSF GPLv2
license. If you really have to ship it, consider symlinking it
from the licenses package.""",
'non-linux-readme',
"""Your package contains a file that contains instructions
for non-linux platforms. They're most likely unneccessary bloat, 
consider removing them from your package."""
)
