# vim:sw=4:et
# ---------------------------------------------------------------
# Module          : rpmlint
# File            : CheckPkgConfig
# Author          : Stephan Kulow, Dirk Mueller
# Purpose         : Check for errors in Pkgconfig files
# ---------------------------------------------------------------

import AbstractCheck
import Config
import Filter
import re
import stat


class PkgConfigCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(
            self, "CheckPkgConfig", ".*/pkgconfig/.*\.pc$")
        # currently causes too many failures (2008-03-05)
        self.suspicious_dir = re.compile(
            '[=:](?:/usr/src/\w+/BUILD|/var/tmp|/tmp|/home)')

    def check(self, pkg):
        # check for references to /lib when in lib64 mode
        if pkg.arch in ('x86_64', 'ppc64', 's390x'):
            self.wronglib_dir = re.compile('-L/usr/lib\\b')
        else:
            self.wronglib_dir = re.compile('-L/usr/lib64\\b')

        AbstractCheck.AbstractFilesCheck.check(self, pkg)

    def check_file(self, pkg, filename):
        if pkg.isSource() or not stat.S_ISREG(pkg.files()[filename].mode):
            return

        if pkg.grep(self.suspicious_dir, filename):
            Filter.printError(pkg, "invalid-pkgconfig-file", filename)

        pc_file = open(pkg.dirName() + "/" + filename, "r")
        for l in pc_file:
            if l.startswith('Libs:') and self.wronglib_dir.search(l):
                Filter.printError(pkg, 'pkgconfig-invalid-libs-dir',
                                  filename, l)


check = PkgConfigCheck()

if Config.info:
    Filter.addDetails(
        'invalid-pkgconfig-file',
        '''Your .pc file appears to be invalid. Possible causes are:
        - it contains traces of $RPM_BUILD_ROOT or $RPM_BUILD_DIR.
        - it contains unreplaced macros (@have_foo@)
        - it references invalid paths (e.g. /home or /tmp)

        Please double-check and report false positives.
        ''',
        'pkgconfig-invalid-libs-dir',
        ''' Your .pc file contains -L/usr/lib or -L/lib and is
        built on a lib64 target, or contains references to -L/usr/lib64 or
        -L/lib64 and is built for a lib target.

        Please remove the wrong library paths from the pc file.'''
    )
