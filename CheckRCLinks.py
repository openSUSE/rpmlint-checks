#############################################################################
# File          : CheckRCLinks.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for missing rc* links and shadowed init scripts
#############################################################################

import os
import stat

from Filter import *
import AbstractCheck
import Config


class RCLinksCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, 'CheckRCLinks')

    def check(self, pkg):
        if pkg.isSource():
            return

        rclinks = set()
        rccandidates = set()
        initscripts = set()

        for fname, pkgfile in pkg.files().items():
            if fname in pkg.ghostFiles():
                continue

            if (stat.S_ISLNK(pkgfile.mode) and
                    (fname.startswith('/usr/sbin/rc') or
                     fname.startswith('/sbin/rc'))):
                rclinks.add(fname.partition('/rc')[2])
            elif fname.startswith('/usr/lib/systemd/system/'):
                basename = os.path.basename(fname)
                if '@' in fname:
                    continue
                if fname.endswith('.service') or fname.endswith('.target'):
                    rccandidates.add(basename.rpartition('.')[0])
            elif fname.startswith('/etc/init.d/'):
                basename = os.path.basename(fname)
                if not (basename.startswith('rc') or
                        basename.startswith('boot.')):
                    initscripts.add(basename)

        for fname in sorted(initscripts):
            if fname in rccandidates:
                printWarning(pkg, "suse-systemd-shadowed-initscript", fname)
            else:
                rccandidates.add(fname)

        for fname in sorted(rccandidates):
            if fname not in sorted(rclinks):
                printWarning(pkg, "suse-missing-rclink", fname)

check = RCLinksCheck()
if Config.info:
    addDetails(
'suse-missing-rclink',
'''The package contains an init script or systemd service file but
lacks the symlink /usr/sbin/rcFOO -> /usr/sbin/service''',
'suse-systemd-shadowed-initscript',
'''The package contains both an init script and a systemd service
file. Please decide for one.'''
)
