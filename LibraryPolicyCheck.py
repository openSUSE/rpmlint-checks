# vim:sw=4:et
#############################################################################
# File          : LibraryPolicyCheck.py
# Package       : rpmlint
# Author        : Richard Guenther
# Purpose       : Verify shared library packaging policy rules
#############################################################################

from Filter import *
import AbstractCheck
import rpm
import re
import commands
import stat
import Config
import os
import string

from BinariesCheck import BinaryInfo

def libname_from_soname (soname):
    libname = string.split(soname, '.so.')
    if len(libname) == 2:
        if libname[0][-1:].isdigit():
            libname = string.join(libname, '-')
        else:
            libname = string.join(libname, '')
    else:
        libname = soname[:-3]
    libname = libname.replace('.', '_')
    return libname

class LibraryPolicyCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "LibraryPolicyCheck")

    def check(self, pkg):

        if pkg.isSource():
            return

        # Only check unsuffixed lib* packages
        sname = string.split(pkg.name, '-')
        if sname[-1] == 'devel' or sname[-1] == 'doc':
            return

        files = pkg.files()

        # Search for shared libraries in this package
        libs = set()
        dirs = set()
        for f in files.keys():
            ff = f.split('/')[-1]
            sf = string.split(f, '.so')
            if len(sf) != 2:
                continue
            bi = BinaryInfo(pkg, pkg.dirName()+f, f, 0)
            if bi.soname != 0:
                libs.add(bi.soname)
                dirs.add(string.join(f.split('/')[:-1], '/'))

        std_dirs = dirs.intersection(set( ('/lib', '/lib64', '/usr/lib', '/usr/lib64') ))

        # If this package should be or should be splitted into shlib
        # package(s)
        wrong_name = 0
        if len(libs) > 0 and len(std_dirs) > 0:
            # If the package contains a single shlib, name after soname
            if len(libs) == 1:
                soname = libs.copy().pop()
                libname = libname_from_soname (soname)
                if pkg.name != libname:
                    printError(pkg, 'shlib-name-error', libname)

            elif not pkg.name[-1:].isdigit():
                printWarning(pkg, 'library-name-suffix', libs)
                wrong_name = 1
        else:
            return

        # Verify no non-lib stuff is in the package
        dirs = set()
        for f in files.keys():
            sf = string.split(f, '.')
            if os.path.dirname(f) in std_dirs and \
               (sf[-1] == 'so' or sf[-1] == 'a' or sf[-1] == 'la') and \
               not os.path.basename(f) in libs:
                printError(pkg, 'devel-file-in-shlib-pkg', f)
            if os.path.isdir(pkg.dirName()+f):
                dirs.add(f)

        # Check for non-versioned directories beyond sysdirs in package
        sysdirs = set( ( '/lib', '/lib64', '/usr/lib', '/usr/lib64',
                         '/usr/share', '/usr/share/doc/packages' ) )
        cdirs = set()
        for sysdir in sysdirs:
            done = set()
            for dir in dirs:
                sdir = string.split(dir, sysdir)
                if sdir[-1] != dir:
                    ssdir = string.split(sdir[-1],'/')[1]
                    if not ssdir[-1].isdigit():
                        cdirs.add(sysdir+'/'+ssdir)
                    done.add(dir)
            dirs = dirs.difference(done)
        if len(cdirs) > 0:
            printError(pkg, 'nonversioned-dirs-in-shlib-pkg', cdirs)

check=LibraryPolicyCheck()

if Config.info:
    addDetails(
'library-name-suffix',
"""Your package containing shared libraries does not end in a digit and should probably be split.""",
'devel-file-in-shlib-pkg',
"""Your shared library package contains development files.""",
'shlib-name-error',
"""Your package contains a single shared library but is not named after its SONAME.""",
'nonversioned-dir-in-shlib-pkg',
"""Your shared library package contains a non-versioned directory."""
)
