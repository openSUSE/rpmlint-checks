# vim:sw=4:et
#############################################################################
# File          : CheckSUIDPermissions.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for /etc/permissions violations
#############################################################################

from Filter import *
import AbstractCheck
import re
import os
import string
import rpm

_permissions_d_whitelist = (
"lprng",
"lprng.paranoid",
"mail-server",
"mail-server.paranoid",
"postfix",
"postfix.paranoid",
"sendmail",
"sendmail.paranoid",
"squid",
"texlive",
"texlive.texlive",
)

class SUIDCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckSUIDPermissions")
        self.perms = {}
        files = [ "/etc/permissions", "/etc/permissions.secure" ]

        for file in files:
            if os.path.exists(file):
                self._parsefile(file)

    def _parsefile(self,file):
        lnr = 0
        lastfn = None
        for line in open(file):
            lnr+=1
            line = line.split('#')[0].split('\n')[0]
            line = line.lstrip()
            if not len(line):
                continue

            if line.startswith("+capabilities "):
                line = line[len("+capabilities "):]
                if lastfn:
                    self.perms[lastfn]['fscaps'] = line
                continue

            line = re.split(r'\s+', line)
            if len(line) == 3:
                fn = line[0]
                owner = line[1].replace('.', ':')
                mode = line[2]

                self.perms[fn] = { "owner" : owner, "mode" : int(mode,8)&07777}
                # for permissions that don't change and therefore
                # don't need special handling
                if file == '/etc/permissions':
                    self.perms[fn]['static'] = True
            else:
                print >>sys.stderr, "invalid line %d " % lnr

    def check(self, pkg):
        global _permissions_d_whitelist

        if pkg.isSource():
            return

        files = pkg.files()

        permfiles = {}
        # first pass, find and parse permissions.d files
        for f in files:
            if f in pkg.ghostFiles():
                continue

            if f.startswith("/etc/permissions.d/"):

                bn = f[19:]
                if not bn in _permissions_d_whitelist:
                    printError(pkg, "permissions-unauthorized-file", f)

                bn = bn.split('.')[0]
                if not bn in permfiles:
                    permfiles[bn] = 1

        for f in permfiles:
            f = pkg.dirName() + "/etc/permissions.d/" + f
            if os.path.exists(f+".secure"):
                self._parsefile(f + ".secure")
            else:
                self._parsefile(f)

        need_set_permissions = False
        found_suseconfig = False
        # second pass, find permissions violations
        for f, pkgfile in files.items():

            if pkgfile.filecaps:
                printError(pkg, 'permissions-fscaps', '%(file)s has fscaps "%(caps)s"' % \
                        { 'file':f, 'caps':pkgfile.filecaps})

            mode = pkgfile.mode
            owner = pkgfile.user+':'+pkgfile.group

#           S_IFSOCK   014   socket
#           S_IFLNK    012   symbolic link
#           S_IFREG    010   regular file
#           S_IFBLK    006   block device
#           S_IFDIR    004   directory
#           S_IFCHR    002   character device
#           S_IFIFO    001   FIFO
            type = (mode>>12)&017;
            mode &= 07777
            need_verifyscript = False
            if f in self.perms or (type == 04 and f+"/" in self.perms):
                if type == 012:
                    printWarning(pkg, "permissions-symlink", f)
                    continue

                need_verifyscript = True

                m = 0
                o = "invalid"
                if type == 04:
                    if f in self.perms:
                        printWarning(pkg, 'permissions-dir-without-slash', f)
                    else:
                        f += '/'

                if type == 010 and mode&0111:
                    # pie binaries have 'shared object' here
                    if 'ELF' in pkgfile.magic and not 'shared object' in pkgfile.magic:
                        printError(pkg, 'non-position-independent-executable', f)

                m = self.perms[f]['mode']
                o = self.perms[f]['owner']

                if mode != m:
                    printError(pkg, 'permissions-incorrect', '%(file)s has mode 0%(mode)o but should be 0%(m)o' % \
                            { 'file':f, 'mode':mode, 'm':m })

                if owner != o:
                    printError(pkg, 'permissions-incorrect-owner', '%(file)s belongs to %(owner)s but should be %(o)s' % \
                            { 'file':f, 'owner':owner, 'o':o })

            elif type != 012:

                if f+'/' in self.perms:
                    printWarning(pkg, 'permissions-file-as-dir', f+' is a file but listed as directory')

                if mode&06000:
                    need_verifyscript = True
                    msg = '%(file)s is packaged with setuid/setgid bits (0%(mode)o)' % { 'file':f, 'mode':mode }
                    if type != 04:
                        printError(pkg, 'permissions-file-setuid-bit', msg)
                    else:
                        printWarning(pkg, 'permissions-directory-setuid-bit', msg)

                    if type == 010:
                        if not 'shared object' in pkgfile.magic:
                            printError(pkg, 'non-position-independent-executable', f)

                if mode&02:
                    need_verifyscript = True
                    printError(pkg, 'permissions-world-writable', \
                            '%(file)s is packaged with world writable permissions (0%(mode)o)' % \
                            { 'file':f, 'mode':mode })

            script = pkg[rpm.RPMTAG_POSTIN] or pkg.scriptprog(pkg[rpm.RPMTAG_POSTINPROG])
            found = False
            if script:
                for line in script.split("\n"):
                    if "chkstat -n" in line and f in line:
                        found = True
                        break

                    if "SuSEconfig --module permissions" in line \
                            or "run_permissions is obsolete" in line:
                        found = True
                        found_suseconfig = True
                        break

            if need_verifyscript and \
                    (not f in self.perms or not 'static' in self.perms[f]):

                if not script or not found:
                    printError(pkg, 'permissions-missing-postin', \
                            "missing %%set_permissions %s in %%post" % f)

                need_set_permissions = True
                script = pkg[rpm.RPMTAG_VERIFYSCRIPT] or pkg[rpm.RPMTAG_VERIFYSCRIPTPROG]

                found = False
                if script:
                    for line in script.split("\n"):
                        if "/chkstat" in line and f in line:
                            found = True
                            break

                if not script or not found:
                    printWarning(pkg, 'permissions-missing-verifyscript', \
                            "missing %%verify_permissions -e %s" % f)


        if need_set_permissions:
            if not 'permissions' in map(lambda x: x[0], pkg.prereq()):
                printError(pkg, 'permissions-missing-requires', \
                        "missing 'permissions' in PreReq")

        if found_suseconfig:
            printInfo(pkg, 'permissions-suseconfig-obsolete', \
                    "%run_permissions is obsolete")

check=SUIDCheck()

if Config.info:
    addDetails(
'permissions-unauthorized-file',
"""If the package is intended for inclusion in any SUSE product
please open a bug report to request review of the package by the
security team""",
'permissions-symlink',
"""permissions handling for symlinks is useless. Please contact
security@suse.de to remove the entry.""",
'permissions-dir-without-slash',
"""the entry in the permissions file refers to a directory. Please
contact security@suse.de to append a slash to the entry in order to
avoid security problems.""",
'permissions-file-as-dir',
"""the entry in the permissions file refers to a directory but the
package actually contains a file. Please contact security@suse.de to
remove the slash.""",
'permissions-incorrect',
"""please use the %attr macro to set the correct permissions.""",
'permissions-incorrect-owner',
"""please use the %attr macro to set the correct ownership.""",
'permissions-file-setuid-bit',
"""If the package is intended for inclusion in any SUSE product
please open a bug report to request review of the program by the
security team""",
'permissions-directory-setuid-bit',
"""If the package is intended for inclusion in any SUSE product
please open a bug report to request review of the package by the
security team""",
'permissions-world-writable',
"""If the package is intended for inclusion in any SUSE product
please open a bug report to request review of the package by the
security team""",
'permissions-fscaps',
"""Packaging file capabilities is currently not supported. Please
use normal permissions instead. You may contact the security team to
request an entry that sets capabilities in /etc/permissions
instead.""",
'permissions-missing-postin',
"""Please add an appropriate %post section""",
'permissions-missing-requires',
"""Please add \"PreReq: permissions\"""",
'permissions-missing-verifyscript',
"""Please add a %verifyscript section""",
'permissions-suseconfig-obsolete',
"""The %run_permissions macro calls SuSEconfig which sets permissions for all
files in the system. Please use %set_permissions <filename> instead
to only set permissions for files contained in this package""",
)
