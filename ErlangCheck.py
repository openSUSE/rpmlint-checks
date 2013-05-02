# vim:sw=4:et
#############################################################################
# File          : CheckErlang.py
# Package       : rpmlint
# Author        : Matwey V. Kornilov
# Purpose       : Check for erlang compiled files
#############################################################################

from Filter import *
import AbstractCheck
import rpm
import re
import os
import commands
import Config
import stat

try:
	from pybeam import BeamFile
except:
	BeamFile = None

class ErlangCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "ErlangCheck", ".*?\.beam$")
        build_dir = rpm.expandMacro("%_builddir") 
        self.source_re = re.compile(build_dir)

    def check_file(self, pkg, filename):
        beam = BeamFile(pkg.files()[filename].path)
        if not 'debug_info' in beam.compileinfo['options']:
            printWarning(pkg, "beam-compiled-without-debug_info", filename)
        if not self.source_re.match(beam.compileinfo['source'].value):
            printWarning(pkg, "beam-was-not-recompiled", filename, beam.compileinfo['source'].value)

class DummyErlangCheck(AbstractCheck.AbstractFilesCheck):
    def __init__(self):
        AbstractCheck.AbstractFilesCheck.__init__(self, "ErlangCheck", ".*?\.beam$")

    def check_file(self, pkg, filename):
        printWarning(pkg, "beam-found-but-no-pybeam-installed", filename)

if BeamFile:
	check=ErlangCheck()
else:
	check=DummyErlangCheck()

if Config.info:
    addDetails(
'beam-found-but-no-pybeam-installed',
"It would be possible to do some erlang-specific diagnostic, If python-pybeam were installed.",
'beam-compiled-without-debug_info',
"Your beam file indicates that it doesn't contain debug_info. Please, make sure that you compile with +debug_info.",
'beam-was-not-recompiled',
"It seems that your beam file was not compiled by you, but was just copied in binary form to destination. Please, make sure that you really compile it from the sources.",
)

