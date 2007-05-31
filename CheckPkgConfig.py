# vim:sw=4:et
#---------------------------------------------------------------
# Module          : rpmlint
# File            : CheckExecDocs.py
# Author          : Stephan Kulow, Dirk Mueller
# Purpose         : Check for executable files in %doc
#---------------------------------------------------------------

from Filter import *
import AbstractCheck
import rpm
import re
import commands
import Config
import os

class PkgConfigCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "PkgConfigCheck", ".*/pkgconfig/.*\.pc$")
        self.suspicious_dir=re.compile('^(?:/usr/src/[^\/]+/BUILD|/var|/tmp|/home)')

    def check_file(self, pkg, filename):
        if pkg.isSource():
            return

        if pkg.grep(self.suspicious_dir, filename):
            printError(pkg, "invalid-pkgconfig-file", filename)

check=PkgConfigCheck()

if Config.info:
    addDetails(
'invalid-pkgconfig-file',
"Your .pc file contains traces of $RPM_BUILD_ROOT or $RPM_BUILD_DIR."
)
