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
import pprint

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
"texlive.paranoid",
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
        for line in open(file):
            line = line.split('#')[0].split('\n')[0]
            if len(line):
                line = re.split(r'\s+', line)
                fn = line[0]
                owner = line[1].replace('.', ':')
                mode = line[2]

                self.perms[fn] = { "owner" : owner, "mode" : int(mode,8)&07777}

    def check(self, pkg):
        global _permissions_d_whitelist

        if pkg.isSource():
            return

        files = pkg.files()

        permfiles = {}
        # first pass, find and parse permissions.d files
        for f in files.keys():
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

        # second pass, find permissions violations
        for f, pkgfile in files.items():
            if f in pkg.ghostFiles():
                continue
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
            if f in self.perms or (type == 04 and f+"/" in self.perms):
                if type == 012:
                    printWarning(pkg, "permissions-symlink", f)
                    continue

                m = 0
                o = "invalid"
                if type == 04:
                    if f in self.perms:
                        printWarning(pkg, 'permissions-dir-without-slash', f)
                    else:
                        f += '/'

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
                    msg = '%(file)s is packaged with setuid/setgid bits (0%(mode)o)' % { 'file':f, 'mode':mode }
                    if type != 04:
                        printError(pkg, 'permissions-file-setuid-bit', msg)
                    else:
                        printWarning(pkg, 'permissions-directory-setuid-bit', msg)

                if mode&02:
                    printError(pkg, 'permissions-world-writable', \
                            '%(file)s is packaged with world writable permissions (0%(mode)o)' % \
                            { 'file':f, 'mode':mode })


check=SUIDCheck()

if Config.info:
    addDetails(
'permissions-unauthorized-file',
"""Please remove the unauthorized files or contact security@suse.de for review.""",
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
"""Please remove the setuid/setgid bits or contact security@suse.de for review.""",
'permissions-directory-setuid-bit',
"""Please contact security@suse.de for review.""",
'permissions-world-writable',
"""Please remove the world writable permissions or contact security@suse.de for review."""
)
