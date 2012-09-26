# vim:sw=4:et
#############################################################################
# File          : CheckUnusedLibs.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Check for binaries linking unused libraries
#############################################################################
# XXX: the check can not reliably work as binaries in the package
# could require libraries the package itself provides.

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
        AbstractCheck.AbstractCheck.__init__(self, "CheckUnusedLibs")

    def check(self, pkg):

        if pkg.isSource():
            return;

        files = pkg.files()

        for fname, pkgfile in files.items():

            if pkgfile.is_ghost:
                continue

            if fname.startswith('/usr/lib/debug') or \
                    not stat.S_ISREG(pkgfile.mode) or \
                    string.find(pkgfile.magic, 'ELF') == -1:
                continue

            ret, output = Pkg.getstatusoutput(['ldd', '-r', '-u',  pkgfile.path])
            for l in output.split('\n'):
                l = l.lstrip()
                if not l.startswith('/'):
                    continue
                lib = l.rsplit('/')[-1]
                if lib in ('libdl.so.2', 'libm.so.6', 'libpthread.so.0'):
                    continue
                printError(pkg, 'elf-binary-unused-dependency', fname, lib)

check=UnusedLibsCheck()

if Config.info:
    addDetails(
'elf-binary-unused-dependency',
"Your ELF binary links a library that is not used."
)
