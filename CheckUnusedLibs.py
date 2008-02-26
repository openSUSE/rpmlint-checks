# vim:sw=4:et
#############################################################################
# File          : CheckUnusedLibs.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Check for binaries linking unused libraries
#############################################################################

from Filter import *
import AbstractCheck
import rpm
import re
import os
import string
import commands
import Config
import Pkg
import stat

class UnusedLibsCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "UnusedLibsCheck")

    def check(self, pkg):

        if pkg.isSource():
            return;

        files = pkg.files()

        for file in pkg.getFilesInfo():
            filename = file[0]

            if filename.startswith('/usr/lib/debug') or \
                    not stat.S_ISREG(files[filename][0]) or \
                    string.find(file[1], 'ELF') == -1:
                continue

            ret, output = Pkg.getstatusoutput("ldd -r -u '%s'" % (filename))
            for l in output.split():
                if not l.startswith('/'):
                    continue
                lib = l.rsplit('/')[-1]
                if lib in ('libdl.so.2', 'libm.so.6', 'libpthread.so.0'):
                    continue
                printError(pkg, 'elf-binary-unused-dependency', filename, lib)

check=UnusedLibsCheck()

if Config.info:
    addDetails(
'elf-binary-unused-dependency',
"Your ELF binary links a library that is not used."
)
