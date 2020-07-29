# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : Enforce Whitelisting for device files
#############################################################################

import os

import AbstractCheck
import Config
import Whitelisting

# this option is found in config files in /opt/testing/share/rpmlint/mini,
# installed there by the rpmlint-mini package.
WHITELIST_DIR = Config.getOption('WhitelistDataDir', [])


class DeviceFilesCheck(AbstractCheck.AbstractCheck):

    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckDeviceFiles")

        for wd in WHITELIST_DIR:
            candidate = os.path.join(wd, "device-files-whitelist.json")
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
                "unauthorized": "device-unauthorized-file",
                "mismatch": "device-mismatched-attrs",
            },
            # we are interested in any device files
            restricted_types=("c", "b"),
            # regardless the mode we want to catch all device files
            restricted_mode=0o7777
        )

    def check(self, pkg):
        """This is called by rpmlint to perform the check on the given pkg."""

        if not self.m_check_configured:
            # don't ruin the whole run if this check is not configured, this
            # was hopefully intended by the user.
            return

        self.m_wl_checker.check(pkg)


# needs to be instantiated for the check to be registered with rpmlint
check = DeviceFilesCheck()

Whitelisting.registerErrorDetails((
    (
        'device-unauthorized-file',
        """A device file is installed by this package.
        {review_needed_text}"""
    ),
    (
        'device-mismatched-attrs',
        """A device file doesn't match the expected file properties.
        Please open a bug report to request follow-up review of the
        introduced changes by the security team. Please refer to {url} for
        more information."""
    )
))
