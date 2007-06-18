# vim:sw=4:et
#############################################################################
# File          : CheckInitScripts.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Check for common mistakes in init scripts
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

class InitScriptsCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "InitScriptsCheck", "/etc/init.d/.*")

    def check(self, pkg):

        if pkg.isSource():
            return

        files = pkg.files()
        for f in files:
            enreg = files[f]
            mode = enreg[0]

            if f in pkg.ghostFiles() or not stat.S_ISREG(mode) or not f.startswith("/etc/init.d/"):
                continue

            input_f = file(f, "r")
            for l in input_f:
                if l.startswith('# Required-Start') or l.startswith('# Should-Start'):
                    for dep in l.split()[2:]:
                        if dep.startswith('$') and dep not in ('$local_fs',
                                '$named',
                                '$network',
                                '$portmap',
                                '$remote_fs',
                                '$syslog',
                                '$time'):
                            printError(pkg, "init-script-undefined-dependency", f, dep)
check=InitScriptsCheck()

if Config.info:
    addDetails(
'init-script-undefined-dependency',
"""Your package contains a /etc/init.d script that specifies a
dependency that is not listed in /etc/insserv.conf. Check for
typos.""",

)
