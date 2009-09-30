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

_kde4_libkdepim4 = (
        "libkdepim.so.4",
        "libkontactinterfaces.so.4",
        "libkleopatraclientcore.so.0.2.0",
        "libkleopatraclientgui.so.0.2.0",
)

_kde4_libakonadi4 = (
        "libakonadi-kde.so.4",
        "libakonadi-kabc.so.4",
        "libakonadi-kcal.so.4",
        "libakonadi-kmime.so.4",
        "libakonadiprotocolinternals.so.1",
)

_kde4_knotificationdep = (
        "libknotificationitem-1.so",
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

        libkdepim4_dep=False
        for r in pkg_requires:
            if r in _kde4_libkdepim4:
                libkdepim4_dep =True
                break

        libakonadi4_dep=False
        for r in pkg_requires:
            if r in _kde4_libakonadi4:
                libakonadi4_dep =True
                break

        if not pkg.name.startswith("lib"):
            if "kdepimlibs4" in pkg_requires and not kdepimlibs4_dep:
                printError(pkg,"suse-kde4-excessive-dependency", "%kde4_pimlibs_requires")
            if not "kdepimlibs4" in pkg_requires and kdepimlibs4_dep:
                printError(pkg,"suse-kde4-missing-dependency", "%kde4_pimlibs_requires")

            if "libkdepim4" in pkg_requires and not libkdepim4_dep:
                printError(pkg,"suse-kde4-excessive-dependency", "libkdepim4")
            if not "libkdepim4" in pkg_requires and libkdepim4_dep:
                printError(pkg,"suse-kde4-missing-dependency", "libkdepim4")

            if "akonadi-runtime" in pkg_requires and not libakonadi4_dep:
                printError(pkg,"suse-kde4-excessive-dependency", "%kde4_akonadi_requires")
            if not "akonadi-runtime" in pkg_requires and libakonadi4_dep:
                printError(pkg,"suse-kde4-missing-dependency", "%kde4_akonadi_requires")
            if not "libknotificationitem-1" in pkg_requires and _kde4_knotificationdep:
                printError(pkg, "suse-kde4-missing-dependency", "kde4_knotification_requires")


check=KDE4Check()

if Config.info:
    addDetails('suse-kde4-missing-runtime-dependency',
"""Please add %kde4_runtime_requires to the (sub-)package to have the right versioned
dependency on the KDE version it was built against.""",
'suse-kde4-missing-dependency',
"""The package builds against a KDE4 related library, but it is missing the runtime 
depencency macro. please add the suggested macro to the (sub-)package listing in
the spec file."""
)
