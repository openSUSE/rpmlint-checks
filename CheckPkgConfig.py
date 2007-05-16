# vim:sw=4:et
from Filter import *
import AbstractCheck
import rpm
import re
import commands
import Config
import os

class PkgConfigCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "PkgConfigCheck", ".*/pkgconfig/.*\.pc")
        self.rpm_build_dir=re.compile('/usr/src/packages/BUILD')

    def check_file(self, pkg, filename):
        if pkg.grep(self.rpm_build_dir, filename):
            printError(pkg, "invalid-pkgconfig-file", filename)

check=PkgConfigCheck()

if Config.info:
    addDetails(
'invalid-pkgconfig-file',
"Your .pc file contains traces of $RPM_BUILD_ROOT or $RPM_BUILD_DIR."
)
