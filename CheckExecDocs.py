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
import stat
import Config
import os
import string

class ExecDocsCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "ExecDocsCheck")

    def check(self, pkg):

        if pkg.isSource():
            return

        files = pkg.files()
        for f in pkg.docFiles():
            enreg=files[f]
            mode=enreg[0]
            if not stat.S_ISREG(mode) or not mode & 0111:
               continue
            for ext in ['txt', 'gif', 'jpg', 'html', 'pdf', 'ps', 'pdf.gz', 'ps.gz']:
               if f.endswith("." + ext):
                   printError(pkg, 'executable-docs', f)

check=ExecDocsCheck()

if Config.info:
    addDetails(
'executable-docs',
"Documentation should not be executable."
)
