# vim:sw=4:et
from Filter import *
import AbstractCheck
import rpm
import re
import os
import commands
import Config
import stat

class BuildRootCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "BuildRootCheck", ".*")
        self.build_root_re = re.compile('/var/tmp/[^/]*-build')

    def check_file(self, pkg, filename):
        if filename.startswith('/usr/lib/debug'):
            return

        try:
           if not stat.S_ISREG(os.stat(filename)[0]):
              return
        except OSError:
              return
        if len(pkg.grep(self.build_root_re, filename)):
            printError(pkg, "file-contains-buildroot", filename)

check=BuildRootCheck()

if Config.info:
    addDetails(
'file-contains-buildroot',
"Your file contains traces of $RPM_BUILD_ROOT."
)
