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
        complete_size=0
        lang_size=0
        for f in files:
            if stat.S_ISREG(files[f][0]):
                complete_size += files[f][4]
                if pkg.fileLang(f) != '':
                    lang_size += files[f][4]

        doc_size=0
        for f in pkg.docFiles():
            if stat.S_ISREG(files[f][0]):
                doc_size += files[f][4]

        if doc_size * 2 >= complete_size \
           and doc_size > 100*1024 and (complete_size - doc_size) * 20 > complete_size \
           and pkg.name.find('-doc') < 0 and not pkg.name.startswith('bundle-'):
            printWarning(pkg, "package-with-huge-docs", ("%3d%%" % (doc_size * 100 / complete_size)) )

        if lang_size * 2 >= complete_size \
           and lang_size > 100*1024 and (complete_size - lang_size) * 20 > complete_size \
           and pkg.name.find('-doc') < 0 and not pkg.name.startswith('bundle-'):
            printWarning(pkg, "package-with-huge-translation", ("%3d%%" % (lang_size * 100 / complete_size)))

        for f in pkg.docFiles():
            enreg=files[f]
            mode=enreg[0]
            if not stat.S_ISREG(mode) or not mode & 0111:
               continue
            for ext in ['txt', 'gif', 'jpg', 'html', 'pdf', 'ps', 'pdf.gz', 'ps.gz']:
               if f.endswith("." + ext):
                   printError(pkg, 'executable-docs', f)

            for name in ['README', 'NEWS', 'COPYING', 'AUTHORS']:
                if f.endswith("/" + name):
                    printError(pkg, 'executable-docs', f)

check=ExecDocsCheck()

if Config.info:
    addDetails(
'executable-docs',
"Documentation should not be executable.",
'package-with-huge-docs',
"""More than half the size of your package is documentation.
Consider splitting it into a -doc subpackage.""",
'package-with-huge-translation',
"""More than half the size of your package is language-specific.
Consider splitting it into a -lang subpackage."""
)
