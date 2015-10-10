#############################################################################
# File          : CheckBuilDate.py
# Package       : rpmlint
# Author        : Cristian Rodriguez
# Purpose       : Check for binaries containing build date
#############################################################################

import AbstractCheck
import Config
import Filter
import re
import stat
import time


class BuildDateCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "CheckBuildDate", ".*")
        self.looksliketime = re.compile(
            '(2[0-3]|[01]?[0-9]):([0-5]?[0-9]):([0-5]?[0-9])')
        self.istoday = re.compile(time.strftime("%b %e %Y"))

    def check_file(self, pkg, filename):
        if filename.startswith('/usr/lib/debug') or pkg.isSource():
            return

        if not stat.S_ISREG(pkg.files()[filename].mode):
            return

        grep_date = pkg.grep(self.istoday, filename)

        if len(grep_date):
            grep_time = pkg.grep(self.looksliketime, filename)

            if len(grep_time):
                Filter.printError(pkg, "file-contains-date-and-time", filename)
            else:
                Filter.printWarning(pkg, "file-contains-current-date",
                                    filename)

check = BuildDateCheck()

if Config.info:
    Filter.addDetails(
'file-contains-current-date',
"""Your file contains the current date, this may cause the package
to rebuild in excess.""",
'file-contains-date-and-time',
"""Your file uses  __DATE and __TIME__ this causes the package to
rebuild when not needed"""
)
