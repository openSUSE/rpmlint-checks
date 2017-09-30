# vim:sw=4:et
#############################################################################
# File          : CheckAppdata.py
# Package       : rpmlint
# Author        : Stephan Kulow
# Purpose       : Check for valid XML in appdata
#############################################################################

# http://people.freedesktop.org/~hughsient/appdata/

from Filter import *
import AbstractCheck
from xml.dom.minidom import parse
from xml.parsers.expat import ExpatError


class AppdataCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "CheckAppdata", '/usr/share/appdata/.*appdata\.xml$')

    def check_file(self, pkg, filename):
        try:
            parse(pkg.dirName() + filename)
        except ExpatError:
            printError(pkg, 'invalid-xml-in-appdata', filename)


check = AppdataCheck()

addDetails(
'invalid-xml-in-appdata',
"""The appdata file provided by the package is not valid XML and will
cause problems. Use e.g. xmllint to verify the problem and fix."""
)
