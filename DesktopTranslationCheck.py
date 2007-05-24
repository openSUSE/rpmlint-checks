# vim:sw=4:et
#---------------------------------------------------------------
# Module          : rpmlint
# File            : DesktopTranslationCheck.py
# Author          : Dirk Mueller
# Purpose         : Check for untranslated desktop files
#---------------------------------------------------------------

from Filter import *
import AbstractCheck
import rpm
import re
import commands
import Config

desktop_re=re.compile('(services|applets)/.*\.desktop$')

class DesktopCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "DesktopCheck", ".*\.desktop")

    def check_file(self, pkg, filename):
        if pkg.isSource() or filename in pkg.ghostFiles():
            return

        try:
            lines = open(pkg.dirName() + '/' + filename).readlines()
        except Exception, e:
            printWarning(pkg, "read-error", e)
            return 0

        for line in lines:
            if line.startswith('X-SuSE-translate='):
                return
        printWarning(pkg, "untranslated-desktop-file", filename)

check=DesktopCheck()

if Config.info:
    addDetails(
'untranslated-desktop-file',
"""Your desktop file hasn't been handled by suse_update_desktop.sh.
Please use it to make the desktop file translate-able by Novell translations."""
)
