#############################################################################
# File          : MixedFileOwnerships.py
# Package       : rpmlint
# Author        : Malte Kraus
# Purpose       : Check for files which have a parent with insecure owner.
#############################################################################

from AbstractCheck import AbstractCheck
from Filter import addDetails, printError


class MixedFileOwnerships(AbstractCheck):
    def __init__(self):
        super().__init__("MixedFileOwnerships")

    def check(self, pkg):
        if pkg.isSource():
            return

        files = pkg.files()
        for path, info in files.items():
            parent = path.rpartition("/")[0]
            if parent not in files:
                # can't figure out who owns the parent directory if it's part of another RPM :(
                continue

            parent_owner = files[parent].user

            # root user is trusted
            if info.user != parent_owner and parent_owner not in ('root', '0'):
                printError(pkg, 'file-parent-ownership-mismatch', path, "owned by", info.user,
                           "is stored in directory owned by different user", parent_owner)


check = MixedFileOwnerships()

addDetails("file-parent-ownership-mismatch",
           """A file or directory is stored in a directory owned by another unprivileged user.
           This is a security issue since the owner of the parent directory can replace this
           file/directory with a different one.""")
