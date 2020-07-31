# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : Enforce Whitelisting for device files
#############################################################################

import Whitelisting
from WhitelistingCheckBase import WhitelistingCheckBase


class DeviceFilesCheck(WhitelistingCheckBase):

    def __init__(self):
        super().__init__("CheckDeviceFiles", "device-files-whitelist.json")

    def setupChecker(self, whitelist_path):

        parser = Whitelisting.MetaWhitelistParser(whitelist_path)
        whitelist_entries = parser.parse()
        return Whitelisting.MetaWhitelistChecker(
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
