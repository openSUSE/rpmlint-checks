#############################################################################
# File          : BashismsCheck.py
# Purpose       : check /bin/sh shell scripts for bashisms
#############################################################################

import stat

import AbstractCheck
import Pkg
from Filter import printWarning, printInfo, addDetails


class BashismsCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "BashismsCheck", ".*")

    def check_file(self, pkg, filename):
        pkgfile = pkg.files()[filename]

        if not (stat.S_ISREG(pkgfile.mode) and
                pkgfile.magic.startswith('POSIX shell script')):
            return

        try:
            status, output = Pkg.getstatusoutput(["dash", "-n", filename])
            if status == 2:
                printWarning(pkg, "bin-sh-syntax-error", filename)
            status, output = Pkg.getstatusoutput(
                ["checkbashisms", filename])
            if status == 1:
                printInfo(pkg, "potential-bashisms", filename)
        except (FileNotFoundError, UnicodeDecodeError):
            pass


check = BashismsCheck()

addDetails(
'bin-sh-syntax-error',
'''A /bin/sh shell script contains a POSIX shell syntax error.
This might indicate a potential bash-specific feature being used,
try dash -n <file> for more detailed error message.''',

'potential-bashisms',
'''checkbashisms reported potential bashisms in a /bin/sh shell
script, you might want to manually check this script for bashisms.''')
