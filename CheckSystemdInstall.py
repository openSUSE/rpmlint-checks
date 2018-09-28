# -*- coding: utf-8 -*-
# ---------------------------------------------------------------
# File            : CheckSystemdInstall.py
# Author          : Johannes Segitz
# Created On      : Tue May 20 12:33:34 CEST 2014
# Purpose         : check that every .service|.socket file in SYSTEMD_SERVICE_DIRECTORY is handled in pre, post, preun and postun
# ---------------------------------------------------------------

import os
import re
import rpm
import AbstractCheck
from Filter import addDetails, printWarning

# check only for files copied to this directory
SYSTEMD_SERVICE_DIRECTORY = "/usr/lib/systemd/system"
# we could extend this later on
CHECKED_UNITS = ['service', 'socket', 'target']
CHECKED_UNITS_REGEXP = re.compile("^" + SYSTEMD_SERVICE_DIRECTORY + r'.+\.(' + '|'.join(CHECKED_UNITS) + ')$')


class CheckSystemdInstall(AbstractCheck.AbstractCheck):

    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, 'CheckSystemdInstall')

    def check(self, pkg):
        # Check only binary package
        if pkg.isSource():
            return

        pre = pkg[rpm.RPMTAG_PREIN] or pkg.scriptprog(rpm.RPMTAG_PREINPROG)
        post = pkg[rpm.RPMTAG_POSTIN] or pkg.scriptprog(rpm.RPMTAG_POSTINPROG)

        preun = pkg[rpm.RPMTAG_PREUN] or pkg.scriptprog(rpm.RPMTAG_PREUNPROG)
        postun = pkg[rpm.RPMTAG_POSTUN] or pkg.scriptprog(rpm.RPMTAG_POSTUNPROG)

        for fname, pkgfile in pkg.files().items():

            if CHECKED_UNITS_REGEXP.search(fname):
                processed = {'pre': False, 'post': False, 'preun': False, 'postun': False}

                escaped_basename = re.escape(os.path.basename(fname))
                PRE_POST_PATTERN = re.compile(r'for service in .*' + escaped_basename)
                PREUN_PATTERN = re.compile(r'systemctl --no-reload disable .*' + escaped_basename)
                POSTUN_PATTERN = re.compile(r'(systemctl try-restart .*|# Restart of .*)' + escaped_basename)

                for line in pre.split("\n"):
                    if PRE_POST_PATTERN.search(line):
                        processed['pre'] = True
                        break
                for line in post.split("\n"):
                    if PRE_POST_PATTERN.search(line):
                        processed['post'] = True
                        break
                for line in preun.split("\n"):
                    if PREUN_PATTERN.search(line):
                        processed['preun'] = True
                        break
                for line in postun.split("\n"):
                    if POSTUN_PATTERN.search(line):
                        processed['postun'] = True
                        break

                if not processed['pre']:
                    printWarning(pkg, 'systemd-service-without-service_add_pre', os.path.basename(fname))
                if not processed['post']:
                    printWarning(pkg, 'systemd-service-without-service_add_post', os.path.basename(fname))
                if not processed['preun']:
                    printWarning(pkg, 'systemd-service-without-service_del_preun', os.path.basename(fname))
                if not processed['postun']:
                    printWarning(pkg, 'systemd-service-without-service_del_postun', os.path.basename(fname))


# Create an object to enable the auto registration of the test
check = CheckSystemdInstall()

addDetails(
'systemd-service-without-service_add_pre',
'''The package contains a systemd service but doesn't contain a %pre with
a call to service_add_pre.''',

'systemd-service-without-service_add_post',
'''The package contains a systemd service but doesn't contain a %post with
a call to service_add_post.''',

'systemd-service-without-service_del_preun',
'''The package contains a systemd service but doesn't contain a %preun with
a call to service_del_preun.''',

'systemd-service-without-service_del_postun',
'''The package contains a systemd service but doesn't contain a %postun with
a call to service_del_postun.''',
)
