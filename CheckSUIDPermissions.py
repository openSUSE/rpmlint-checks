# vim:sw=4:et
#############################################################################
# File          : CheckSUIDPermissions.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check /etc/permissions violations
#############################################################################

from Filter import *
import AbstractCheck
import re
import os
import string
import glob

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
        files = [ "/etc/permissions" ]
        files += glob.glob("/etc/permissions.d/*")

        for file in files:
                if os.path.exists(file):
                    self._parsefile(file)
                file += '.secure'
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
        for f in files:
            if f in pkg.ghostFiles():
                continue
            enreg = files[f]
            mode = enreg[0]
            owner = enreg[1]+':'+enreg[2]
            links = enreg[3]
            size = enreg[4]
            md5 = enreg[5]
            rdev = enreg[7]

            if f.startswith("/etc/permissions.d/"):

                basename = f[19:]
                if not basename in _permissions_d_whitelist:
                    printError(pkg, "unauthorized-permissions-file", f)

#       S_IFSOCK   014   socket
#       S_IFLNK    012   symbolic link
#       S_IFREG    010   regular file
#       S_IFBLK    006   block device
#       S_IFDIR    004   directory
#       S_IFCHR    002   character device
#       S_IFIFO    001   FIFO
            type = (mode>>12)&017;
            mode &= 07777
            if f in self.perms or (type == 04 and f+"/" in self.perms):
                if type == 012:
                    printWarning(pkg, "permissions-handling-useless", f)
                    continue

                m = 0
                o = "invalid"
                if type == 04:
                    if f in self.perms:
                        printWarning(pkg, 'dir-without-slash', f)
                    else:
                        f += '/'

                m = self.perms[f]['mode']
                o = self.perms[f]['owner']

                if mode != m:
                    printError(pkg, 'wrong-permissions', '%(file)s has mode 0%(mode)o but should be 0%(m)o' % \
                            { 'file':f, 'mode':mode, 'm':m })

                if owner != o:
                    printError(pkg, 'wrong-owner', '%(file)s belongs to %(owner)s but should be %(o)s' % \
                            { 'file':f, 'owner':owner, 'o':o })

            elif type != 012:

                if f+'/' in self.perms:
                    printWarning(pkg, 'file-listed-as-dir', f+' is a file but listed as directory')

                if mode&06000:
                    if type != 04:
                        printError(pkg, 'packaged-with-setuid-bit', '%(file)s is packaged with setuid/setgid bits (0%(mode)o)' % \
                                { 'file':f, 'mode':mode })
                    else:
                        printWarning(pkg, 'packaged-with-setuid-bit', '%(file)s is packaged with setuid/setgid bits (0%(mode)o)' % \
                                { 'file':f, 'mode':mode })

                if mode&02:
                    printError(pkg, 'packaged-world-writable', '%(file)s is packaged with world writable permissions (0%(mode)o)' % \
                            { 'file':f, 'mode':mode })


check=SUIDCheck()

if Config.info:
    addDetails(
'unauthorized-permissions-file',
"""Please remove the unauthorized files or contact security@suse.de for review.""",
'permissions-handling-useless',
"""permissions handling for symlinks is useless""",
'dir-without-slash',
"""the entry in the permissions file refers to a directory. Please
append a slash to the entry to avoid security problems""",
'wrong-permissions',
"""please use the %attr macro to set the correct permissions""",
'wrong-owner',
"""please use the %attr macro to set the correct ownership""",
'packaged-with-setuid-bit',
"""Please remove the setuid/setgid bits or contact security@suse.de for review.""",
'packaged-world-writable',
"""Please remove the world writable permissions or contact security@suse.de for review."""
)
