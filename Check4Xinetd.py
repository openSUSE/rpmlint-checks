#############################################################################
# File          : Check4Xinetd.py
# Package       : rpmlint
# Author        : Werner Fink
# Created on    : Mon Jul 24 11:04:41 CEST 2017
# Purpose       : Check on systemd systems for obsolate xinetd configurations
#############################################################################

from Filter import addDetails, printError, printWarning
import AbstractCheck
import Config
import string
import os
import stat
import Pkg

xinetd_tag = 'suse-obsolete-xinetd-requirement'
config_tag = 'suse-deprecated-xinetd-configuration'

class Check4Xinetd(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, 'Check4Xinetd')

    def check(self, pkg):
        if pkg.isSource():
            return

        for req in pkg.requires() + pkg.prereq():
            if req[0] == 'xinetd':
                printError(pkg, xinetd_tag)

        for fn, pkgfile in pkg.files().items():
            if not fn.startswith('/etc/xinetd.d'):
                continue
            printError(pkg, config_tag, fn)

check = Check4Xinetd()

if Config.info:
    addDetails(
xinetd_tag,
'''In systemd based distributions xinetd has become obsolete.
Please remove dependencies on xinetd.''',
config_tag,
'''Xinetd configuation files are deprecated. Please migrate to
systemd unit files.''',
)

# Local variables:
# indent-tabs-mode: nil
# py-indent-offset: 4
# End:
# -*- coding: utf-8 -*-
# vim:sw=4:et:
