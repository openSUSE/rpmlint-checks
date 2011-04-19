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

insserv_regex=re.compile('^\s*sbin/insserv', re.MULTILINE)
preun_regex=re.compile('^\s*/etc/init.d/\S+ stop', re.MULTILINE)

class CheckInitScripts(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "CheckInitScripts", "/etc/init.d/.*")

    def check(self, pkg):

        if pkg.isSource():
            return

        files = pkg.files()
        bins_list = filter(lambda f: (f.startswith("/usr/bin") \
                or f.startswith("/usr/sbin")) and stat.S_ISREG(files[f].mode), files.keys())

        for f, pkgfile in files.items():

            if f in pkg.ghostFiles() or not stat.S_ISREG(pkgfile.mode) or not f.startswith("/etc/init.d/"):
                continue

            boot_script = f.startswith('/etc/init.d/boot.')

            input_f = file(pkg.dirName() + '/' + f, "r")
            found_remote_fs = False
            for l in input_f:
                if l.startswith('# Required-Start') or l.startswith('# Should-Start'):
                    for dep in l.split()[2:]:
                        if dep.startswith('$') and dep not in ('$local_fs',
                                '$named',
                                '$network',
                                '$portmap',
                                '$remote_fs',
                                '$syslog',
                                '$time',
                                '$null',
                                '$ALL'):
                            printError(pkg, "init-script-undefined-dependency", f, dep)
                        if dep in ('portmap', 'syslog', 'named', 'network', 'xntpd'):
                            printWarning(pkg, "init-script-non-var-dependency", f, dep)
                        if dep in ('$remote_fs'):
                            found_remote_fs = True
                if l.startswith('# X-UnitedLinux-Should'):
                    printWarning(pkg, "obsolete-init-keyword", f, l)
                if l.startswith('# Default-Start'):
                    for dep in l.split()[2:]:
                        if boot_script and dep not in ('B', 'S'):
                            printError(pkg, "init-script-wrong-start-level", f, dep)
                        if not boot_script and dep in ('B'):
                            printError(pkg, "init-script-wrong-start-level", f, dep)

            if not found_remote_fs and bins_list:
                printWarning(pkg, "non-remote_fs-dependency", f)


check=CheckInitScripts()

if Config.info:
    addDetails(
'init-script-undefined-dependency',
"""Your package contains a /etc/init.d script that specifies a
dependency that is not listed in /etc/insserv.conf. Check for
typos.""",
'init-script-non-var-dependency',
"""Your package contains a /etc/init.d script that specifies
a hardcoded dependency that likely should be a variable dependency.
For example portmap should actually be $portmap, and similar.""",
'obsolete-init-keyword',
"""Your package contains a /etc/init.d script that specifies
an obsolete keyword, like X-UnitedLinux-Should-Start. Consider
using the LSB equivalent Should-Start instead.""",
'init-script-wrong-start-level',
"""Your package contains a /etc/init.d script that specifies
that it should be run in boot level but isn't named with a boot prefix
or specifies a non-boot level but has boot prefix. Fix your script.""",
'non-remote_fs-dependency',
"""Your package contains a /etc/init.d script that does not specify
$remote_fs as a start dependency, but the package also contains
files packaged in /usr. Make sure that your start script does not
call any of them, or add the missing $remote_fs dependency."""
)
