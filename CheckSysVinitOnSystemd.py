#############################################################################
# File          : CheckSysVinitOnSystemd.py
# Package       : rpmlint
# Author        : Werner Fink
# Created on    : Tue Feb 21 17:34:50 2017
# Purpose       : Check on systemd systems for required insserv package
#############################################################################

from Filter import addDetails, printError, printWarning
import AbstractCheck
import Config
import string
import os
import stat
import Pkg

insserv_tag = 'insserv-is-required-on-systemd-based'
etcinit_tag = 'etc-init-found-on-systemd-based'
bootscr_tag = 'sysv-boot-script-found-on-systemd-based'

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

        for fn, pkgfile in pkg.files().items():
            if not fn.startswith('/etc/init.d'):
                continue
            if stat.S_ISDIR(pkgfile.mode):
                printError(pkg, etcinit_tag, fn)
            else:
                printError(pkg, bootscr_tag, fn)

check = CheckSysVinitOnSystemd()

#
# Should be set in the global configuration file
#
#Config.setBadness(insserv_tag, 10000)
#Config.setBadness(etcinit_tag, 10000)
#Config.setBadness(bootscr_tag, 10000)

if Config.info:
    addDetails(
insserv_tag,
'''packages shall not require insserv on a system based on systemd
therefor please consider to remove such dependencies''',
etcinit_tag,
'''packages shall not include /etc/init.d/ on a system based on systemd
as this is deprecated, please remove''',
bootscr_tag,
'''packages shall not install SysVinit boot scripts on a system based on systemd
therefor please convert all boot scripts into systemd unit files''',
)

# Local variables:
# indent-tabs-mode: nil
# py-indent-offset: 4
# End:
# -*- coding: utf-8 -*-
# vim:sw=4:et:
