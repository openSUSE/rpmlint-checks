# vim:sw=4:et
#############################################################################
# File          : CheckAlternativesGhostFiles.py
# Package       : rpmlint
# Author        : Michal Vyskocil
# Purpose       : Check if files used by update-alternatives are marked as %ghost
#############################################################################

from Filter import *
import AbstractCheck
import rpm

class CheckAlternativesGhostFiles(AbstractCheck.AbstractCheck):
        
    INSTALL="--install"
    SLAVE="--slave"

    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckAlternativesGhostFiles")

    @classmethod
    def read_ghost_files(cls, script):
        ghost_files = []

        if not script or not 'update-alternatives' in script:
            return ghost_files


        for command in ( \
                c.replace('\\\n', '').strip() \
                for c in script.split('update-alternatives') \
                if cls.INSTALL in c):

            #parse install
            xs = command.split(None, 4)
            ghost_files.append(xs[1])
            
            if cls.SLAVE in command:
                for sc in ( \
                        c.strip() \
                        for c in command[command.index(cls.SLAVE):].split(cls.SLAVE) \
                        if c.strip() != ''):

                    xs = sc.split(None, 2)
                    ghost_files.append(xs[0])

        return ghost_files

    def check(self, pkg):

        if pkg.isSource():
            return

        alt_files = []
        for script in (pkg.header[tag] for tag in (rpm.RPMTAG_POSTIN, rpm.RPMTAG_PREIN, rpm.RPMTAG_POSTTRANS)):
            alt_files.extend(self.read_ghost_files(script))

        files = pkg.files()
        ghost_files = pkg.ghostFiles()
        for af in (af for af in alt_files if not af in ghost_files):
            if af in files:
                printWarning(pkg, 'generic-name-not-marked-as-ghost %s' % (af))
            else:
                printWarning(pkg, 'generic-name-not-in-filelist %s' % af)


check=CheckAlternativesGhostFiles()

if Config.info:
    addDetails(

'generic-name-not-marked-as-ghost',
'''The generic name is not marked as a ghost, which may cause a problems during
update. Mark it as a %ghost in %files section.''',

'generic-name-not-in-filelist',
'''The generic name is not in a filelist of package, add it to list marked as
%ghost. Note: this error will be raised, if you use a hash ($) in file name,
use rpm macros in spec file instead.''',

)
