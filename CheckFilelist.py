# vim:sw=4:et
#############################################################################
# File          : CheckFilelist.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for /etc/permissions violations
#############################################################################

from Filter import *
import AbstractCheck
import re
import os
import string
import fnmatch
from rpm import RPMTAG_ARCH

_defaulterror = 'suse-filelist-forbidden'
_defaultmsg = '%(file)s is not allowed anymore in SUSE Linux'

def notnoarch(pkg):
    return pkg.arch != 'noarch'

def isdebuginfo(pkg):
    if pkg.name.endswith('-debuginfo') \
    or pkg.name.endswith('-debugsource') \
    or pkg.name.endswith('-debug'):
        return True

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
                '*/CV',
                '*/CVS/',
                '*/.cvsignor',
                '*/.svn',
                '*/RC',
                '*/RCS/',
                '*,v',
                '*.ba',
                '*/.xvpic',
                '*.ori',
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
                '/usr/X11R6/lib/locale',
                '/usr/X11R6/lib/X11/locale/LC_MESSAGES*',
                '/opt/gnome',
                '/usr/lib/perl5/site_perl/*',
                '/usr/lib/perl5/vendor_perl/5.*/auto',
                '/usr/lib/perl5/vendor_perl/5.*/*-linux-*/auto',
                ],
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
                'ignoreif': notnoarch,
                },
        {
                'error': 'suse-filelist-forbidden-debuginfo',
                'msg': '%(file)s may only be packaged in the -debuginfo subpackage',
                'bad': [
                    '/usr/lib/debug/*',
                    ],
                'ignoreif': isdebuginfo,
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
                    '/usr/X11R6/include/X11',
                    '/usr/X11R6/include/X11/*',
                    '/usr/X11R6/lib/X11',
                    '/usr/X11R6/lib/X11/*',
                    '/usr/X11R6/lib/modules',
                    '/usr/X11R6/lib/modules/*',
                    '/usr/X11R6/lib64/modules',
                    '/usr/X11R6/lib64/modules/*',
                    '/usr/X11R6/lib/X11/app-defaults',
                    '/usr/X11R6/lib/X11/app-defaults/*',
                    '/usr/X11R6/lib64/X11/app-defaults',
                    '/usr/X11R6/lib64/X11/app-defaults/*',
                    ],
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
                'error': 'suse-filelist-forbidden-fhs22',
                'good': [
                    '/bin',
                    '/bin/*',
                    '/boot',
                    '/boot/*',
                    '/cdrom',
                    '/dev',
                    '/dev/*',
                    '/etc',
                    '/etc/*',
                    '/floppy',
                    '/home',
                    '/lib',
                    '/lib/*',
                    '/lib64',
                    '/lib64/*',
                    '/media',
                    '/media/*',
                    '/mnt',
                    '/opt',
                    '/proc',
                    '/root',
                    '/root/.exrc',
                    '/root/.gnupg',
                    '/root/.gnupg/*',
                    '/root/.kbackrc',
                    '/root/.xinitrc',
                    '/root/bin',
                    '/sbin',
                    '/sbin/*',
                    '/subdomain',
                    '/sys',
                    '/tmp',
                    '/tmp/.X11-unix',
                    '/tmp/.ICE-unix',
                    '/usr',
                    '/usr/*-linux-libc5',
                    '/usr/*-linux-libc5/*',
                    '/usr/*-linux',
                    '/usr/*-linux/*',
                    '/usr/X11',
                    '/usr/X11R6',
                    '/usr/X11R6/*',
                    '/usr/bin',
                    '/usr/bin/*',
                    '/usr/games',
                    '/usr/games/*',
                    '/usr/include',
                    '/usr/include/*',
                    '/usr/lib',
                    '/usr/lib/*',
                    '/usr/lib64',
                    '/usr/lib64/*',
                    '/usr/local',
                    '/usr/local/bin',
                    '/usr/local/games',
                    '/usr/local/include',
                    '/usr/local/lib',
                    '/usr/local/lib64',
                    '/usr/local/man',
                    '/usr/local/man/*',
                    '/usr/local/sbin',
                    '/usr/local/share',
                    '/usr/local/src',
                    '/usr/sbin',
                    '/usr/sbin/*',
                    '/usr/share',
                    '/usr/share/*',
                    '/usr/spool',
                    '/usr/src',
                    '/usr/src/debug*',
                    '/usr/src/linux*',
                    '/usr/src/kernel-modules*',
                    '/usr/src/packages',
                    '/usr/src/packages/*',
                    '/usr/src/bxform*',
                    '/usr/src/dicts',
                    '/usr/src/dicts/*',
                    '/usr/tmp',
                    '/var',
                    '/var/X11R6',
                    '/var/X11R6/*',
                    '/var/account',
                    '/var/account/*',
                    '/var/agentx',
                    '/var/agentx/*',
                    '/var/cache',
                    '/var/cache/*',
                    '/var/crash',
                    '/var/crash/*',
                    '/var/games',
                    '/var/games/*',
                    '/var/lib',
                    '/var/lib/*',
                    '/var/local',
                    '/var/lock',
                    '/var/lock/*',
                    '/var/log',
                    '/var/log/*',
                    '/var/mail',
                    '/var/mail/*',
                    '/var/opt',
                    '/var/opt/*',
                    '/var/preserve',
                    '/var/run',
                    '/var/run/*',
                    '/var/spool',
                    '/var/spool/*',
                    '/var/tmp',
                    '/var/tmp/vi.recover',
                    '/var/yp',
                    '/var/yp/*',
                    # we have these below /var, but not nice to have:
                    '/var/adm',
                    '/var/adm/*',
                    '/var/db',
                    '/var/db/*',
                    '/var/nis',
                    '/var/nis/*',
                    '/var/heimdal',
                    # allowed, but not nice to have:
                    '/afs',
                    '/afs/*',
                    '/emul',
                    '/emul/*',
                    '/srv',
                    '/srv/*',
                    ],
                    'bad': [
                        '*',
                        ]
                },
        ]

class FilelistCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckFilelist")

    def check(self, pkg):
        global _checks
        global _defaultmsg
        global _defaulterror

        if pkg.isSource():
            return

        files = pkg.files()

        for check in _checks:

            if 'ignoreif' in check:
                if check['ignoreif'](pkg):
                    continue

            if 'msg' in check:
                msg = check['msg']
            else:
                msg = _defaultmsg

            if 'error' in check:
                error = check['error']
            else:
                error = _defaulterror

            good = []
            if 'good' in check:
                import re
                for pattern in check['good']:
                    r = fnmatch.translate(pattern)
                    good.append(re.compile(r))

            bad = []
            for pattern in check['bad']:
                r = fnmatch.translate(pattern)
                bad.append(re.compile(r))

            for f in files:
                ok = False
                for g in good:
                    if g.match(f):
                        ok = True
                        break
                if ok:
                    continue

                for b in bad:
                    if b.match(f):
                        msg = msg % { 'file':f }
                        printError(pkg, error, msg)


check=FilelistCheck()

if Config.info:
    for check in _checks:

        if not 'details' in check:
            continue

        if not 'error' in check:
            continue

        addDetails(check['error'], check['details'])
