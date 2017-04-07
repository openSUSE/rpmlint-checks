# vim:sw=4:et
#############################################################################
# File          : CompressionCheck.py
# Package       : rpmlint
# Author        : Bernhard M. Wiedemann
# Purpose       : Check for compressed files using correct extension
#############################################################################

import AbstractCheck
import Config
import Filter
import os
import stat
import string

magic = {
    "gz": "\x1f\x8b",
    "tgz": "\x1f\x8b",
    "bz2": "BZ",
    "xz": "\xfd\x37"}


def get_ext(file):
    return file.split("/")[-1].split(".")[-1]


def get_filestart(file):
    f = open(file, "r")
    return f.read(2)


def wrong_compression(file):
    ext = get_ext(file)
    if ext in magic and magic[ext] != get_filestart(file):
        return 1
    return 0


class CompressionCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        self.map = []
        AbstractCheck.AbstractCheck.__init__(self, "CompressionCheck")

    def check(self, pkg):
        ghosts = pkg.ghostFiles()
        for filename in pkg.files():
            if filename in ghosts:
                continue

            if not stat.S_ISREG(pkg.files()[filename].mode):
                continue

            if wrong_compression(os.path.join(pkg.dirname, filename)):
                Filter.printError(pkg, 'files-wrong-compression', filename)

check = CompressionCheck()

if Config.info:
    Filter.addDetails(
'files-wrong-compression',
"""Your package has compressed files that are not using the compression indicated by their extension.
You should rename them."""
    )
