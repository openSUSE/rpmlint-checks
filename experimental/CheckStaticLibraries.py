# vim:sw=4:et
#############################################################################
# File          : CheckStaticLibraries.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Check for binaries containing copies of common libs
#############################################################################

from Filter import *
import AbstractCheck
import rpm
import re
import os
import commands
import Config
import stat

class StaticLibrariesCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "CheckStaticLibs", ".*")
        self.staticlibsre = re.compile(
           '(?:ruby - Copyright \(C\) 1993-%d Yukihiro Matsumoto|' + # ruby
           'inflate (\d.\d.\d) Copyright 1995-\d+ Mark Adler|' +
           'deflate (\d.\d.\d) Copyright 1995-\d+ Jean-loup Gailly|' + #zlib
           'Berkeley DB: DB 1\.85\'s recno bfname field is not supported|' + # db 4.4
           'close shared connections - see dbus_connection_close|' + # dbus
           'I can\'t handle hardcopy terminals|' + # ncurses
           'readline_callback_read_char\(\) called with no handler|' + # readline
           'EXT2FS Library version \d.\d+|' + # libext2fs
           'requested feature requires XML_DTD support in Expat|' + # libexpat
           'Julian Seward, 15 February 2005|' + # libbz2
           'option type (%d) not implemented in popt|' + # libpopt
           '\(key - \(char *\) 0\) % __alignof__ \(md5_uint32\) == 0|' + # libcrypt
           'Copyright \(C\) \d+, Thomas G. Lane|' + # libjpeg
           'Copyright \(c\) 1995-1996 Guy Eric Schalnat, Group 42, Inc|' + # libpng
           'tag to <libexif-devel@lists.sourceforge.net>|' + # libexif
           'authorization function - should be SQLITE_OK|' + # libsqlite
           'Copyright \(c\) 1988-1996 Sam Leffler|' + # libtiff
           'this version of PCRE is not compiled with PCRE_UTF8 support', + # libpcre
           'Too many heap sections: Increase MAXHINCR or MAX_HEAP_SECTS',  #gc
           ')')

    def check_file(self, pkg, filename):
        if filename.startswith('/usr/lib/debug') or pkg.isSource():
            return

        if not stat.S_ISREG(pkg.files()[filename][0]):
            return

        grep_result = pkg.grep(self.staticlibsre, filename)

        if len(grep_result):
            printError(pkg, "file-contains-system-library", filename, grep_result)

check=StaticLibrariesCheck()

if Config.info:
    addDetails(
'file-contains-system-library',
"Your file contains traces of a system library that should be linked dynamically."
)
