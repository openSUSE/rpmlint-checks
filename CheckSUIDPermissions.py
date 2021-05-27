# vim: sw=4 et sts=4 ts=4 :
#############################################################################
# File          : CheckSUIDPermissions.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for /usr/share/permissions violations
#############################################################################

from __future__ import print_function

from Filter import printWarning, printError, printInfo
import AbstractCheck
import Whitelisting
import Permissions

import os
import rpm
import stat

_permissions_d_whitelist = (
    "postfix",
    "postfix.paranoid",
    "sendmail",
    "sendmail.paranoid",
    "texlive",
    "texlive.texlive"
)


class SUIDCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckSUIDPermissions")
        self.perms = {}

        self.var_handler = Permissions.VariablesHandler("/usr/share/permissions/variables.conf")

        for fname in self._paths_to('permissions', 'permissions.secure'):
            if not os.path.exists(fname):
                continue

            self._parseProfile(fname)

    def _parseProfile(self, path):
        parser = Permissions.PermissionsParser(self.var_handler, path)
        self.perms.update(parser.getEntries())

    def _isStaticEntry(self, entry):
        # entries coming from the fixed permissions profile are considered
        # static
        return entry.profile.endswith("/permissions")

    @staticmethod
    def _paths_to(*file_names):
        # we used to store the permissions data in /etc even though they aren't configuration files
        # the whitelisting should check both paths (old /etc and new /usr/share) until all
        # distributions using the old one (SLE15) are retired
        for name in file_names:
            # return the new path first.
            # chkstat prefers the new paths over the old ones, so callers that only care about the
            # first matching file must mimic that.
            yield '/usr/share/permissions/' + name
            yield '/etc/' + name

    def check(self, pkg):
        global _permissions_d_whitelist

        if pkg.isSource():
            return

        files = pkg.files()

        permfiles = set()
        # first pass, find and parse permissions.d files
        for f in files:
            for prefix in self._paths_to("permissions.d/"):
                if f.startswith(prefix):

                    if f in pkg.ghostFiles():
                        printError(pkg, 'polkit-ghost-file', f)
                        continue

                    bn = f[len(prefix):]
                    if bn not in _permissions_d_whitelist:
                        printError(pkg, "permissions-unauthorized-file", f)

                    bn = 'permissions.d/' + bn.split('.')[0]
                    if bn not in permfiles:
                        permfiles.add(bn)

        for f in permfiles:
            # check for a .secure file first, falling back to the plain file
            for path in self._paths_to(f + '.secure', f):
                if path in files:
                    self._parseProfile(pkg.dirName() + path)
                    break

        need_set_permissions = False
        found_suseconfig = False
        # second pass, find permissions violations
        for f, pkgfile in files.items():

            if pkgfile.filecaps:
                printError(pkg, 'permissions-fscaps',
                                '%(fname)s has fscaps "%(caps)s"' %
                                {'fname': f, 'caps': pkgfile.filecaps})

            mode = pkgfile.mode
            owner = pkgfile.user + ':' + pkgfile.group

            need_verifyscript = False
            if f in self.perms or (stat.S_ISDIR(mode) and f + "/" in self.perms):
                if stat.S_ISLNK(mode):
                    printWarning(pkg, "permissions-symlink", f)
                    continue

                need_verifyscript = True

                m = 0
                o = "invalid"
                if stat.S_ISDIR(mode):
                    if f in self.perms:
                        printWarning(pkg, 'permissions-dir-without-slash', f)
                    else:
                        f += '/'

                entry = self.perms[f]

                if stat.S_ISREG(mode) and mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    # pie binaries have 'shared object' here
                    if (pkgfile.magic.startswith('ELF ') and
                            ('shared object' not in pkgfile.magic) and
                            ('pie executable' not in pkgfile.magic)):
                        printError(pkg, 'non-position-independent-executable',
                                   f)

                m = entry.mode
                o = ':'.join((entry.owner, entry.group))

                if stat.S_IMODE(mode) != m:
                    printError(
                        pkg, 'permissions-incorrect',
                        '%(file)s has mode 0%(mode)o but should be 0%(m)o' %
                        {'file': f, 'mode': stat.S_IMODE(mode), 'm': m})

                if owner != o:
                    printError(
                        pkg, 'permissions-incorrect-owner',
                        '%(file)s belongs to %(owner)s but should be %(o)s' %
                        {'file': f, 'owner': owner, 'o': o})

            elif not stat.S_ISLNK(mode):

                if f + '/' in self.perms:
                    printWarning(
                        pkg, 'permissions-file-as-dir',
                        f + ' is a file but listed as directory')

                if mode & (stat.S_ISUID | stat.S_ISGID):
                    need_verifyscript = True
                    msg = '%(file)s is packaged with ' \
                          'setuid/setgid bits (0%(mode)o)' % \
                          {'file': f, 'mode': stat.S_IMODE(mode)}
                    if not stat.S_ISDIR(mode):
                        printError(pkg, 'permissions-file-setuid-bit', msg)
                    else:
                        printWarning(pkg, 'permissions-directory-setuid-bit', msg)

                    if stat.S_ISREG(mode):
                        if ('shared object' not in pkgfile.magic and
                                'pie executable' not in pkgfile.magic):
                            printError(pkg, 'non-position-independent-executable', f)

            script = pkg[rpm.RPMTAG_POSTIN] or pkg.scriptprog(rpm.RPMTAG_POSTINPROG)
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
                    (f not in self.perms or not self._isStaticEntry(self.perms[f])):

                if not script or not found:
                    printError(pkg, 'permissions-missing-postin',
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
                    printWarning(pkg, 'permissions-missing-verifyscript',
                                 "missing %%verify_permissions -e %s" % f)

        if need_set_permissions:
            if 'permissions' not in map(lambda x: x[0], pkg.prereq()):
                printError(pkg, 'permissions-missing-requires',
                           "missing 'permissions' in PreReq")

        if found_suseconfig:
            printInfo(pkg, 'permissions-suseconfig-obsolete',
                      "%run_permissions is obsolete")


check = SUIDCheck()

Whitelisting.registerErrorDetails((
    (
        'permissions-unauthorized-file',
        """{review_needed_text}"""
    ),
    (
        'permissions-symlink',
        """permissions handling for symlinks is useless. Please contact
        security@suse.de to remove the entry. Please refer to {url} for more
        information."""
    ),
    (
        'permissions-dir-without-slash',
        """the entry in the permissions file refers to a directory. Please
        contact security@suse.de to append a slash to the entry in order to
        avoid security problems. Please refer to {url} for more information."""
    ),
    (
        'permissions-file-as-dir',
        """the entry in the permissions file refers to a directory but the
        package actually contains a file. Please contact security@suse.de to
        remove the slash. Please refer to {url} for more information."""
    ),
    (
        'permissions-incorrect',
        """please use the %attr macro to set the correct permissions."""
    ),
    (
        'permissions-incorrect-owner',
        """please use the %attr macro to set the correct ownership."""
    ),
    (
        'permissions-file-setuid-bit',
        """{review_needed_text}"""
    ),
    (
        'permissions-directory-setuid-bit',
        """{review_needed_text}"""
    ),
    (
        'permissions-fscaps',
        """Packaging file capabilities is currently not supported. Please
        use normal permissions instead. You may contact the security team to
        request an entry that sets capabilities in
        /usr/share/permissions/permissions instead.""",
    ),
    (
        'permissions-missing-postin',
        """Please add an appropriate %post section"""
    ),
    (
        'permissions-missing-requires',
        """Please add 'PreReq: permissions'"""
    ),
    (
        'permissions-missing-verifyscript',
        """Please add a %verifyscript section"""
    ),
    (
        'permissions-suseconfig-obsolete',
        """The %run_permissions macro calls SuSEconfig which sets permissions for all
        files in the system. Please use %set_permissions <filename> instead
        to only set permissions for files contained in this package""",
    ),
    (
        'permissions-ghostfile',
        """This package installs a permissions file as a %ghost file.
        {ghost_encountered_text}"""
    )
))
