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
import Pkg

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
        if pkg.name.endswith('-devel') or pkg.name.endswith('-doc'):
            return

        files = pkg.files()

        # Search for shared libraries in this package
        libs = set()
        dirs = set()
        reqlibs = set()
        shlib_requires = map(lambda x: string.split(x[0],'(')[0], pkg.requires())
        for f in files:
            if f.find('.so.') != -1 or f.endswith('.so'):
                filename = pkg.dirName() + '/' + f
                try:
                    if stat.S_ISREG(files[filename][0]):
                        bi = BinaryInfo(pkg, filename, f, 0)
                        if bi.soname != 0:
                            libs.add(bi.soname)
                            dirs.add(string.join(f.split('/')[:-1], '/'))
                        if bi.soname in shlib_requires:
                            # But not if the library is used by the pkg itself
                            # This avoids program packages with their own private lib
                            # FIXME: we'd need to check if somebody else links to this lib
                            reqlibs.add(bi.soname)
                except:
                    pass
            pass

        std_dirs = dirs.intersection(set( ('/lib', '/lib64', '/usr/lib', '/usr/lib64') ))

        # If this is a program package (all libs it provides are
        # required by itself), bail out
        if len(libs.difference(reqlibs)) == 0:
            return

        # If this package should be or should be splitted into shlib
        # package(s)
        if len(libs) > 0 and len(std_dirs) > 0:
            # If the package contains a single shlib, name after soname
            if len(libs) == 1:
                soname = libs.copy().pop()
                libname = libname_from_soname (soname)
                if pkg.name != libname:
                    printError(pkg, 'shlib-policy-name-error', libname)

            elif not pkg.name[-1:].isdigit():
                printError(pkg, 'shlib-policy-missing-suffix')
        else:
            return

        # Verify no non-lib stuff is in the package
        dirs = set()
        for f in files.keys():
            if os.path.isdir(pkg.dirName()+f):
                dirs.add(f)
            else:
                sf = string.split(f, '.')
                if os.path.dirname(f)[:len('/usr/include')] == '/usr/include':
                    printError(pkg, 'shlib-policy-devel-file', f)
                if os.path.dirname(f) in std_dirs \
                   and (sf[-1] == 'so' or sf[-1] == 'a' or sf[-1] == 'la') \
                   and not os.path.basename(f) in libs:
                    printError(pkg, 'shlib-policy-devel-file', f)

        # Check for non-versioned directories beyond sysdirs in package
        sysdirs = [ '/lib', '/lib64', '/usr/lib', '/usr/lib64',
                    '/usr/share/doc/packages', '/usr/share' ]
        cdirs = set()
        for sysdir in sysdirs:
            done = set()
            for dir in dirs:
                if dir.startswith(sysdir + '/'):
                    ssdir = string.split(dir[len(sysdir)+1:],'/')[0]
                    if not ssdir[-1].isdigit():
                        cdirs.add(sysdir+'/'+ssdir)
                    done.add(dir)
            dirs = dirs.difference(done)
        map(lambda dir: printError(pkg, 'shlib-policy-nonversioned-dir', dir), cdirs)

check=LibraryPolicyCheck()

if Config.info:
    addDetails(
'shlib-policy-missing-suffix',
"""Your package containing shared libraries does not end in a digit and
should probably be split.""",
'shlib-policy-devel-file',
"""Your shared library package contains development files. Split them into
a -devel subpackage.""",
'shlib-policy-name-error',
"""Your package contains a single shared library but is not named after its SONAME.""",
'shlib-policy-nonversioned-dir',
"""Your shared library package contains non-versioned directories. Those will not
allow to install multiple versions of the package in parallel."""
)
