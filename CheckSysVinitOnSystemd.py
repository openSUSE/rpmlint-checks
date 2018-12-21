#############################################################################
# File          : CheckSysVinitOnSystemd.py
# Package       : rpmlint
# Author        : Werner Fink
# Created on    : Tue Feb 21 17:34:50 2017
# Purpose       : Check on systemd systems for required insserv package
#############################################################################

import os

from Filter import addDetails, printError
import AbstractCheck
import Config

insserv_tag = 'suse-obsolete-insserv-requirement'
etcinit_tag = 'suse-deprecated-init-script'
bootscr_tag = 'suse-deprecated-boot-script'


class CheckSysVinitOnSystemd(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, 'CheckSysVinitOnSystemd')

    def check(self, pkg):
        if pkg.isSource():
            return

        for req in pkg.requires() + pkg.prereq():
            if req[0] == 'insserv':
                printError(pkg, insserv_tag)

        for fn in pkg.files():
            if not fn.startswith('/etc/init.d'):
                continue
            if os.path.basename(fn).startswith('boot.'):
                printError(pkg, bootscr_tag, fn)
            else:
                printError(pkg, etcinit_tag, fn)


check = CheckSysVinitOnSystemd()

if Config.info:
    addDetails(
insserv_tag,
'''In systemd based distributions insserv is obsolete.
Please remove dependencies on insserv.''',
etcinit_tag,
'''SysV init scripts are deprecated. Please migrate to
systemd service files.''',
bootscr_tag,
'''SysV boot scripts are deprecated. Please migrate to
systemd service files.''',
)

# Local variables:
# indent-tabs-mode: nil
# py-indent-offset: 4
# End:
# -*- coding: utf-8 -*-
# vim:sw=4:et:
