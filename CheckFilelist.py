# vim:sw=4:et
#############################################################################
# File          : CheckFilelist.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for wrongly packaged files
#############################################################################

from Filter import *
import AbstractCheck
import re
import os
import string
import fnmatch

_defaulterror = 'suse-filelist-forbidden'
_defaultmsg = '%(file)s is not allowed in SUSE Linux'

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
    files = pkg.files()
    enreg = files[f]
    mode = enreg[0]
    type = (mode>>12)&017
    return type != 012

_checks = [
        {
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
                '/usr/share/info/dir',
                '*~',
                '*/CVS',
                '*/CVS/*',
                '*/.cvsignore',
                '*/.svn',
                '*/RCS',
                '*/RCS/*',
                '*,v',
                '*.bak',
                '*/.xvpics',
                '*.orig',
                '*.orig.gz',
                '/usr/share/*/.libs*',
                '/usr/share/*/.deps*',
                '/var/adm/fillup-templates/rc.config.*',
                '/var/adm/setup',
                '/etc/httpd/*',
                '/etc/sysconfig/*',
                '/etc/rc.config.d/*',
                '/etc/init.d/*/*',
                '/usr/share/locale/LC_MESSAGES',
                '/opt/gnome',
                '/usr/lib/perl5/site_perl/*',
                '/usr/lib/perl5/vendor_perl/5.*/auto',
                '/usr/lib/perl5/vendor_perl/5.*/*-linux-*/auto',
                ],
            },
        {
            'error': 'suse-filelist-forbidden-devel-in-lib',
            'details': 'please move la files, static libs and .so symlinks out of /',
            'bad': [
                "/lib/*.la",
                "/lib/*.a",
                "/lib64/*.la",
                "/lib64/*.a",
                ]
            },
        {
            'error': 'suse-filelist-forbidden-devel-in-lib',
            'details': 'please move la files, static libs and .so symlinks out of /',
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
            'error': 'suse-filelist-forbidden-fhs22',
            'msg': '%(file)s is not allowed in FHS 2.2',
            'details': 'see http://www.pathname.com/fhs/ to find a better location',
            'bad': [
                "/usr/dict",
                "/var/locale",
                "/var/locale/*",
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
                'good': [
                    # KDE3 legacy exception
                    '/opt/kde3',
                    '/opt/kde3/*',
                    ],
                'bad': [
                    '/opt/*',
                    ],
                },
        {
                'error': 'suse-filelist-forbidden-fhs23',
                'good': [
                    '/bin/*',
                    '/boot/*',
                    '/etc/*',
                    '/lib/*',
                    '/lib64/*',
                    '/media/*',
                    # SUSE policy handled in separate check
                    '/opt/*',
                    '/sbin/*',
                    '/srv/*',
                    # SUSE policy handled in separate check
                    '/usr/X11R6/*',
                    '/usr/bin/*',
                    '/usr/games/*',
                    '/usr/include/*',
                    '/usr/lib/*',
                    '/usr/lib64/*',
                    '/usr/sbin/*',
                    '/usr/share/*',
                    # actually only linux is allowed by fhs
                    '/usr/src/linux*',
                    '/usr/src/debug/*',
                    '/usr/src/packages/*',
                    # /var
                    '/var/account/*',
                    '/var/cache/*',
                    '/var/crash/*',
                    '/var/games/*',
                    '/var/lib/*',
                    '/var/lock/*',
                    '/var/log/*',
                    '/var/mail/*',
                    '/var/opt/*',
                    '/var/run/*',
                    '/var/spool/*',
                    #'/var/tmp',
                    '/var/yp/*',
                    # we have these below /var, but not nice to have:
                    '/var/adm/*',
                    '/var/nis/*',
                    # allowed, but not nice to have:
                    '/emul/*',
                    ],
                    'bad': [
                        '*',
                        ],
                'ignorepkgif': isfilesystem,
                },
        ]

class FilelistCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckFilelist")
        import re

        for check in _checks:
            if 'good' in check:
                for i in range(len(check['good'])):
                    pattern = check['good'][i]
                    if '*' in pattern:
                        r = fnmatch.translate(pattern)
                        check['good'][i] = re.compile(r)

            for i in range(len(check['bad'])):
                pattern = check['bad'][i]
                if '*' in pattern:
                    r = fnmatch.translate(pattern)
                    check['bad'][i] = re.compile(r)

    def check(self, pkg):
        global _checks
        global _defaultmsg
        global _defaulterror

        if pkg.isSource():
            return

        files = pkg.files()

        if not files:
            printError(pkg, 'suse-filelist-empty', 'packages without any files are not allowed in SUSE Linux')
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

            for f in files:
                ok = False
                if 'good' in check:
                    for g in check['good']:
                        if (not isinstance(g, str) and  g.match(f)) or g == f:
                            ok = True
                            break
                if ok:
                    continue

                for b in check['bad']:
                    if 'ignorefileif' in check:
                        if check['ignorefileif'](pkg, f):
                            continue
                    if (not isinstance(b, str) and  b.match(f)) or b == f:
                        m = msg % { 'file':f }
                        printError(pkg, error, m)


check=FilelistCheck()

if Config.info:
    for check in _checks:

        if not 'details' in check:
            continue

        if not 'error' in check:
            continue

        addDetails(check['error'], check['details'])
