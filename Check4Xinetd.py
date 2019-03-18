#############################################################################
# File          : Check4Xinetd.py
# Package       : rpmlint
# Author        : Werner Fink
# Created on    : Mon Jul 24 11:04:41 CEST 2017
# Purpose       : Check on systemd systems for obsolate xinetd configurations
#############################################################################

from Filter import addDetails, printError
import AbstractCheck
import Config

xinetd_tag = 'suse-obsolete-xinetd-requirement'


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


check = Check4Xinetd()

if Config.info:
    addDetails(
xinetd_tag,
'''In systemd based distributions xinetd has become obsolete.
Please remove dependencies on xinetd.''',
)

# Local variables:
# indent-tabs-mode: nil
# py-indent-offset: 4
# End:
# -*- coding: utf-8 -*-
# vim:sw=4:et:
