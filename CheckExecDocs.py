# vim:sw=4:et
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
        files = pkg.files()

        for f in files.keys():
            enreg=files[f]
            if not stat.S_ISREG(enreg[0]):
               continue
            mode=stat.S_IMODE(enreg[0])
            if not (mode & 0111):
               continue
            if f.find('/share/') == -1:
               continue # the rest can go
            for ext in ['txt', 'gif', 'jpg', 'html', 'pdf', 'ps', 'pdf.gz', 'ps.gz']:
               if f.endswith("." + ext):
                   printError(pkg, 'executable-docs', f)

check=ExecDocsCheck()

if Config.info:
    addDetails(
'executable-docs',
"Documentation should not be executable."
)
