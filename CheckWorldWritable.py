# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : Enforce Whitelisting for world writable files
#############################################################################

import os

import AbstractCheck
import Config
import Whitelisting

from Filter import addDetails

# this option is found in config files in /opt/testing/share/rpmlint/mini,
# installed there by the rpmlint-mini package.
WHITELIST_DIR = Config.getOption('WhitelistDataDir', [])


class WorldWritableCheck(AbstractCheck.AbstractCheck):

    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckWorldWritable")

        for wd in WHITELIST_DIR:
            candidate = os.path.join(wd, "world-writable-whitelist.json")
            if os.path.exists(candidate):
                whitelist_path = candidate
                break
        else:
            whitelist_path = None

        self.m_check_configured = whitelist_path is not None

        if not self.m_check_configured:
            return

        parser = Whitelisting.MetaWhitelistParser(whitelist_path)
        whitelist_entries = parser.parse()
        self.m_wl_checker = Whitelisting.MetaWhitelistChecker(
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

    def check(self, pkg):
        """This is called by rpmlint to perform the check on the given pkg."""

        if not self.m_check_configured:
            # don't ruin the whole run if this check is not configured, this
            # was hopefully intended by the user.
            return

        self.m_wl_checker.check(pkg)


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
