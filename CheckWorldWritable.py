# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : Enforce Whitelisting for world writable files
#############################################################################

import Whitelisting
from WhitelistingCheckBase import WhitelistingCheckBase


class WorldWritableCheck(WhitelistingCheckBase):

    def __init__(self):
        super().__init__("CheckWorldWritable", "world-writable-whitelist.json")

    def setupChecker(self, whitelist_path):

        parser = Whitelisting.MetaWhitelistParser(whitelist_path)
        whitelist_entries = parser.parse()
        return Whitelisting.MetaWhitelistChecker(
            whitelist_entries,
            error_map={
                "unauthorized": "world-writable-unauthorized-file",
                "mismatch": "world-writable-mismatched-attrs",
            },
            # we're only interested in directories, regular files, pipes or
            # sockets.
            # devices are handled by the DeviceFileChecker. Symlinks are
            # always world-writable.
            restricted_types=("-", "f", "d", "s", "p"),
            # we're interested in any world-writable files
            restricted_mode=0o0002,
        )


# needs to be instantiated for the check to be registered with rpmlint
check = WorldWritableCheck()

Whitelisting.registerErrorDetails((
    (
        'world-writable-unauthorized-file',
        """A world-writable file is installed by this package.
        {review_needed_text}"""
    ),
    (
        'world-writable-mismatched-attrs',
        """A world-writable file doesn't match the expected file
        properties. {followup_needed_text}"""
    )
))
