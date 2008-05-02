# vim:sw=4:et
#############################################################################
# File          : CheckKDE4Deps.py
# Package       : rpmlint
# Author        : Dirk Mueller
# Purpose       : Check for KDE4 related packaging errors
#############################################################################

from Filter import *
import AbstractCheck
import rpm
import re
import os
import string
import commands
import Config
import Pkg
import stat

_kde4_pimlibs=(
        "libgpgme++-pth.so.1.1.0",
        "libgpgme++-pthread.so.1.1.0",
        "libgpgme++.so.1.1.0",
        "libkabc.so.4",
        "libkabc_file_core.so.4",
        "libkblog.so.4",
        "libkcal.so.4",
        "libkimap.so.4",
        "libkldap.so.4",
        "libkmime.so.4",
        "libkpimidentities.so.4",
        "libkpimutils.so.4",
        "libkresources.so.4",
        "libktnef.so.4",
        "libkxmlrpcclient.so.4",
        "libmailtransport.so.4",
        "libqgpgme.so.1.0.0",
        "libsyndication.so.4"
)

class KDE4Check(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "KDE4Check")

    def check(self, pkg):

        if pkg.isSource():
            return

        pkg_requires = set(map(lambda x: string.split(x[0],'(')[0], pkg.requires()))

        if not "libkdecore.so.5" in pkg_requires:
            return

        if not pkg.name.startswith("lib"):
            if not "kdebase4-runtime" in pkg_requires:
                printError(pkg,"suse-kde4-missing-runtime-dependency")

        kdepimlibs4_dep=False
        for r in pkg_requires:
            if r in _kde4_pimlibs:
                kdepimlibs4_dep=True
                break

        if not pkg.name.startswith("lib"):
            if "libkdepimlibs4" in pkg_requires and not kdepimlibs4_dep:
                printError(pkg,"suse-kde4-missing-pimlibs-dependency")
            if not "libkdepimlibs4" in pkg_requires and kdepimlibs4_dep:
                printError(pkg,"suse-kde4-excessive-pimlibs-dependency")

check=KDE4Check()

#if Config.info:
#    addDetails(
#)
