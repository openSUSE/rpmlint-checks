# vim:sw=4:et
#############################################################################
# File          : CheckFilelist.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for wrongly packaged files and FHS violations
#############################################################################

from Filter import *
import AbstractCheck
import re
import os
import string
import fnmatch
from rpm import RPMTAG_VENDOR

_defaulterror = 'suse-filelist-forbidden'
_defaultmsg = '%(file)s is not allowed in SUSE'

def notnoarch(pkg):
    return pkg.arch != 'noarch'

def isfilesystem(pkg):
    return pkg.name == 'filesystem'

def isdebuginfo(pkg):
    if pkg.name.endswith('-debuginfo') \
    or pkg.name.endswith('-debuginfo-32bit') \
    or pkg.name.endswith('-debuginfo-64bit') \
    or pkg.name.endswith('-debugsource') \
    or pkg.name.endswith('-debug'):
        return True

def notsymlink(pkg, f):
    mode = pkg.files()[f].mode
    type = (mode>>12)&017
    return type != 012

def ghostfile(pkg, f):
    ghosts = pkg.ghostFiles()
    return f in ghosts

_goodprefixes = (
        '/bin/',
        '/boot/',
        '/etc/',
        '/lib/',
        '/lib64/',
        '/media/',
        # SUSE policy handled in separate check
        '/opt/',
        '/sbin/',
        '/srv/',
        # SUSE policy handled in separate check
        '/usr/X11R6/',
        '/usr/bin/',
        '/usr/games/',
        '/usr/include/',
        '/usr/lib/',
        '/usr/lib64/',
        '/usr/sbin/',
        '/usr/share/',
        # actually only linux is allowed by fhs
        '/usr/src/linux',
        '/usr/src/debug/',
        '/usr/src/packages/',
        '/var/account/',
        '/var/cache/',
        '/var/crash/',
        '/var/games/',
        '/var/lib/',
        '/var/lock/',
        '/var/log/',
        '/var/mail/',
        '/var/opt/',
        '/var/run/',
        '/var/spool/',
        '/var/yp/',
        # those are not in FHS!
        '/var/adm/',
        '/var/nis/',
        '/emul/',
        )

# computed from goodprefixes.
# Directories that are only allowed to have defined subdirs (such as /usr)
_restricteddirs = set()

_checks = [
        {
            'bad': [
                '*/.xvpics',
                '*.orig',
                '*.orig.gz',
                '/usr/share/*/.libs*',
                '/usr/share/*/.deps*',
                '/var/adm/setup',
                '/etc/httpd/*',
                '/etc/init.d/*/*',
                '/usr/share/locale/LC_MESSAGES',
                ],
            },
        {
            'error': 'suse-filelist-forbidden-sysconfig',
            'details': '''Please use /var/adm/fillup-templates/sysconfig.<packagename>
                        and call %fillup_and_insserv to install new sysconfig files''',
            'good': [
                '/etc/sysconfig/cbq',
                '/etc/sysconfig/scripts',
                '/etc/sysconfig/scripts/*',
                '/etc/sysconfig/network',
                '/etc/sysconfig/network/*',
                '/etc/sysconfig/hardware',
                '/etc/sysconfig/hardware/*',
                '/etc/sysconfig/isdn',
                '/etc/sysconfig/isdn/scripts',
                '/etc/sysconfig/isdn/scripts/*',
                '/etc/sysconfig/SuSEfirewall2.d',
                '/etc/sysconfig/SuSEfirewall2.d/*',
                '/etc/sysconfig/uml',
                ],
            'bad': [
                '/var/adm/fillup-templates/rc.config.*',
                '/etc/sysconfig/*',
                '/etc/rc.config.d/*',
                ],
        },
        {
            'error': 'suse-filelist-forbidden-perl-dir',
            'details': '''perl files installed a non-vendor installed path, 
                          which is not allowed in SUSE.''',
            'bad': [
                '/usr/lib/perl5/site_perl/*',
                '/usr/lib/perl5/vendor_perl/5.*/auto',
                '/usr/lib/perl5/vendor_perl/5.*/*-linux-*/auto',
                ],
        },
        {
            'error': 'suse-filelist-forbidden-backup-file',
            'details': 'backup files (e.g. files ending in ~ or .bak) are not allowed',
            'bad': [
                '*~',
                '*.bak',
                ],
            'ignorefileif': ghostfile,
            },
        {
            'error': 'suse-filelist-forbidden-devel-in-lib',
            'details': 'please move la files, static libs and .so symlinks to /usr/lib(64)',
            'bad': [
                "/lib/*.la",
                "/lib/*.a",
                "/lib64/*.la",
                "/lib64/*.a",
                ]
            },
        {
            'error': 'suse-filelist-forbidden-devel-in-lib',
            'details': 'please move la files, static libs and .so symlinks to /usr/lib(64)',
            'good': [
                # exception for pam
                "/lib/security/*.so",
                "/lib64/security/*.so",
                ],
            'bad': [
                "/lib/*.so",
                "/lib64/*.so",
                ],
            # some libs without proper soname are packaged directly
            'ignorefileif': notsymlink,
            },
        {
            'error': 'suse-filelist-forbidden-fhs23',
            'msg': '%(file)s is not allowed in FHS 2.3',
            'details': 'see http://www.pathname.com/fhs/ to find a better location',
            'bad': [
                "/etc/X11/app-defaults/*",
                "/usr/local/man/*/*",
                "/var/lib/games",
                "/var/lib/games/*",
                "/usr/sbin/*/*",
                "/sbin/init.d",
                "/sbin/init.d/*",
                "/bin/*/*",
                ]
            },
        {
                'error': 'suse-filelist-forbidden-yast2',
                'msg': '%(file)s is not allowed anymore in YaST2',
                'bad': [
                    '/usr/lib/YaST2/*.ycp',
                    '/usr/lib/YaST2/*.y2cc',
                    '/usr/lib/YaST2/*.*.scr',
                    ],
                },
        {
                'error': 'suse-filelist-forbidden-srv',
                'details': """Please use /srv for ftp and http data""",
                'bad': [
                    '/usr/local/ftp',
                    '/usr/local/http',
                    ],
                },
        {
                'error': 'suse-filelist-forbidden-games',
                'details': """static data has to be in /usr/share/games, variable in /var/games""",
                'bad': [
                    '/usr/games/bin',
                    '/usr/games/lib',
                    '/usr/games/*/*',
                    ],
                },
        {
                'error': 'suse-filelist-forbidden-noarch',
                'msg': '%(file)s is not allowed in a noarch package',
                'bad': [
                    '/lib64',
                    '/lib64/*',
                    '/usr/lib64',
                    '/usr/lib64/*',
                    '/usr/X11R6/lib64',
                    '/usr/X11R6/lib64/*',
                    '/opt/gnome/lib64',
                    '/opt/gnome/lib64/*',
                    '/opt/kde3/lib64',
                    '/opt/kde3/lib64/*',
                    '/usr/lib/pkgconfig/*',
                    ],
                'ignorepkgif': notnoarch,
                },
        {
                'error': 'suse-filelist-forbidden-debuginfo',
                'msg': '%(file)s may only be packaged in the -debuginfo subpackage',
                'bad': [
                    '/usr/lib/debug/*',
                    ],
                'ignorepkgif': isdebuginfo,
                },
        {
                'error': 'suse-filelist-forbidden-locale',
                'details': """Please use nb or nb_NO (and nn for nynorsk)"""
                """see https://bugzilla.novell.com/show_bug.cgi?id=42748""",
                'bad': [
                    '/opt/gnome/share/locale/no',
                    '/opt/gnome/share/locale/no/*',
                    '/opt/kde3/share/locale/no',
                    '/opt/kde3/share/locale/no/*',
                    '/usr/share/locale/no',
                    '/usr/share/locale/no/*',
                    '/usr/share/vim/*/lang/no',
                    '/usr/share/vim/*/lang/no/*',
                    ],
                },
        {
                'error': 'suse-filelist-forbidden-xorg',
                'details': """Please use the updated paths for Xorg 7.1 and above""",
                'bad': [
                    '/usr/X11R6/*',
                    ],
                'ignorepkgif': isfilesystem,
                },
        {
                'error': 'suse-filelist-forbidden-suseconfig',
                'details': """Adding new SuSEconfig scripts is not accepted for openSUSE 10.2 and newer""",
                'good': [
                    '/sbin/conf.d/SuSEconfig.automake',
                    '/sbin/conf.d/SuSEconfig.cjk-latex',
                    '/sbin/conf.d/SuSEconfig.desktop-file-utils',
                    '/sbin/conf.d/SuSEconfig.fonts',
                    '/sbin/conf.d/SuSEconfig.gdm',
                    '/sbin/conf.d/SuSEconfig.ghostscript-cjk',
                    '/sbin/conf.d/SuSEconfig.glib2',
                    '/sbin/conf.d/SuSEconfig.gnome-vfs2',
                    '/sbin/conf.d/SuSEconfig.groff',
                    '/sbin/conf.d/SuSEconfig.gtk2',
                    '/sbin/conf.d/SuSEconfig.guile',
                    '/sbin/conf.d/SuSEconfig.icu',
                    '/sbin/conf.d/SuSEconfig.isdn',
                    '/sbin/conf.d/SuSEconfig.ispell',
                    '/sbin/conf.d/SuSEconfig.kde',
                    '/sbin/conf.d/SuSEconfig.kdm3',
                    '/sbin/conf.d/SuSEconfig.libxml2',
                    '/sbin/conf.d/SuSEconfig.lyx-cjk',
                    '/sbin/conf.d/SuSEconfig.mailman',
                    '/sbin/conf.d/SuSEconfig.news',
                    '/sbin/conf.d/SuSEconfig.pango',
                    '/sbin/conf.d/SuSEconfig.pbs',
                    '/sbin/conf.d/SuSEconfig.perl',
                    '/sbin/conf.d/SuSEconfig.permissions',
                    '/sbin/conf.d/SuSEconfig.postfix',
                    '/sbin/conf.d/SuSEconfig.prelink',
                    '/sbin/conf.d/SuSEconfig.scim',
                    '/sbin/conf.d/SuSEconfig.scpm',
                    '/sbin/conf.d/SuSEconfig.scrollkeeper',
                    '/sbin/conf.d/SuSEconfig.sendmail',
                    '/sbin/conf.d/SuSEconfig.sgml-skel',
                    '/sbin/conf.d/SuSEconfig.susehelp',
                    '/sbin/conf.d/SuSEconfig.syslog-ng',
                    '/sbin/conf.d/SuSEconfig.tetex',
                    '/sbin/conf.d/SuSEconfig.texlive',
                    '/sbin/conf.d/SuSEconfig.tuxpaint',
                    '/sbin/conf.d/SuSEconfig.wdm',
                    '/sbin/conf.d/SuSEconfig.words',
                    '/sbin/conf.d/SuSEconfig.xdm',
                    '/sbin/conf.d/SuSEconfig.xjdic',
                    '/sbin/conf.d/SuSEconfig.xpdf',
                    '/sbin/conf.d/SuSEconfig.zmessages',
                    ],
                'bad': [
                    '/sbin/conf.d/*',
                    ],
                },
        {
                'error': 'suse-filelist-forbidden-opt',
                'details': """/opt may not be used by a distribution. It is reserved for 3rd party packagers""",
                },
        ]

class FilelistCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckFilelist")
        import re

        _restricteddirs.add('/')
        for d in _goodprefixes:
            if d.count('/') > 2:
                _restricteddirs.add(d[0:-1].rpartition('/')[0])

        for check in _checks:
            if 'good' in check:
                for i in range(len(check['good'])):
                    pattern = check['good'][i]
                    if '*' in pattern:
                        r = fnmatch.translate(pattern)
                        check['good'][i] = re.compile(r)

            if 'bad' in check:
                for i in range(len(check['bad'])):
                    pattern = check['bad'][i]
                    if '*' in pattern:
                        r = fnmatch.translate(pattern)
                        check['bad'][i] = re.compile(r)

    def check(self, pkg):
        global _checks
        global _defaultmsg
        global _defaulterror
        global _goodprefixes
        global _restricteddirs

        if pkg.isSource():
            return

        files = pkg.files()

        if not files:
            printError(pkg, 'suse-filelist-empty', 'packages without any files are not allowed in SUSE')
            return

        for check in _checks:

            if 'ignorepkgif' in check:
                if check['ignorepkgif'](pkg):
                    continue

            if 'msg' in check:
                msg = check['msg']
            else:
                msg = _defaultmsg

            if 'error' in check:
                error = check['error']
            else:
                error = _defaulterror

            if 'good' in check or 'bad' in check:
                for f in files.keys():
                    ok = False
                    if 'good' in check:
                        for g in check['good']:
                            if (not isinstance(g, str) and  g.match(f)) or g == f:
                                ok = True
                                break
                    if ok:
                        continue

                    if 'bad' in check:
                        for b in check['bad']:
                            if 'ignorefileif' in check:
                                if check['ignorefileif'](pkg, f):
                                    continue
                            if (not isinstance(b, str) and  b.match(f)) or b == f:
                                m = msg % { 'file':f }
                                printError(pkg, error, m)

        invalidfhs = set()
        invalidopt = set()

        if pkg.header[RPMTAG_VENDOR] and pkg.header[RPMTAG_VENDOR].find('SUSE') != -1:
            isSUSE = True
        else:
            isSUSE = False

        # the checks here only warn about a directory once rather
        # than reporting potentially hundreds of files individually
        for f, pkgfile in files.items():
            type = (pkgfile.mode>>12)&017

            # append / to directories
            if type == 04:
                f +=  '/'

            if not f.startswith(_goodprefixes):
                base = f.rpartition('/')
                pfx = None
                # find the first invalid path component (/usr/foo/bar/baz -> /usr)
                while base[0] and not base[0].startswith(_goodprefixes) and not base[0] in _restricteddirs:
                    pfx = base[0]
                    base = base[0].rpartition('/')

                if not pfx:
                    invalidfhs.add(f)
                else:
                    invalidfhs.add(pfx)

            if f.startswith('/opt'):
                try:
                    provider = f.split('/')[2]
                except:
                    continue
                # legacy exception
                if provider == 'kde3':
                    continue
                if isSUSE and (provider == 'suse' or provider == 'novell'):
                    continue

                d = '/opt/'+provider
                invalidopt.add(d)

        for f in invalidfhs:
            printError(pkg, 'suse-filelist-forbidden-fhs23', "%(file)s is not allowed in FHS 2.3" % { 'file': f })

        for f in invalidopt:
            printError(pkg, 'suse-filelist-forbidden-opt', '%(file)s is not allowed for official SUSE packages' % { 'file': f })

check=FilelistCheck()

if Config.info:
    for check in _checks:

        if not 'details' in check:
            continue

        if not 'error' in check:
            continue

        addDetails(check['error'], check['details'])
