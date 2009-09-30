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
        AbstractCheck.AbstractFilesCheck.__init__(self, "DesktopTranslationCheck", ".*\.desktop$")

    def check_file(self, pkg, filename):
        if pkg.isSource() or filename in pkg.ghostFiles():
            return

        try:
            f = open(pkg.dirName() + '/' + filename)
        except Exception, e:
            printWarning(pkg, "read-error", e)
            return 0

        found_desktop_group=False
        for line in f:
            if line.startswith('X-SuSE-translate='):
                return
            if line.startswith('[Desktop Entry]'):
                found_desktop_group=True
        if found_desktop_group:
            printWarning(pkg, "untranslated-desktop-file", filename)

check=DesktopCheck()

if Config.info:
    addDetails(
'untranslated-desktop-file',
"""Your desktop file hasn't been handled by %suse_update_desktop_file
Please use it to make the desktop file translate-able by Novell translations."""
)
