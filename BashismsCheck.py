#############################################################################
# File          : BashismsCheck.py
# Package       : rpmlint
# Author        : Guido Berhoerster
# Purpose       : check /bin/sh shell scripts for bashisms
#############################################################################

import re
import stat

import AbstractCheck
import Pkg
from Filter import printWarning, printInfo, printError, addDetails


class BashismsCheck(AbstractCheck.AbstractFilesCheck):
    RE_BIN_SH = re.compile(r'#!\s*(/usr)?/bin/sh(\s+|$)')

    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "BashismsCheck", ".*")

    def check_file(self, pkg, filename):
        first_line = ''

        if not stat.S_ISREG(pkg.files()[filename].mode):
            return

        with open(pkg.dirName() + "/" + filename, "rb") as f:
            first_line = Pkg.b2s(f.read(256)).split("\n")[0]

        try:
            if self.RE_BIN_SH.match(first_line):
                status, output = Pkg.getstatusoutput(["dash", "-n", filename])
                if status == 2:
                    printWarning(pkg, "bin-sh-syntax-error", filename)
                try:
                    status, output = Pkg.getstatusoutput(
                        ["checkbashisms", filename])
                    if status == 1:
                        printInfo(pkg, "potential-bashisms", filename)
                except Exception as x:
                    printError(
                        pkg, 'rpmlint-exception',
                        '%(fname)s raised an exception: %(x)s' %
                        {'fname': filename, 'x': x})
        except UnicodeDecodeError:
            pass


check = BashismsCheck()

addDetails(
'bin-sh-syntax-error',
'A /bin/sh shell script contains a syntax error.',

'potential-bashisms',
'''checkbashisms reported potential bashisms in a /bin/sh shell
script, you might want to manually check this script for bashisms.''')
