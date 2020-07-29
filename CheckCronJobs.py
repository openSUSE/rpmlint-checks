# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : Enforce Whitelisting for cron jobs in /etc/cron.* directories
#############################################################################

import Whitelisting
from WhitelistingCheckBase import WhitelistingCheckBase


class CronCheck(WhitelistingCheckBase):

    def __init__(self):
        super().__init__("CheckCronJobs", "cron-whitelist.json")

    def setupChecker(self, whitelist_path):

        parser = Whitelisting.DigestWhitelistParser(whitelist_path)
        whitelist_entries = parser.parse()
        return Whitelisting.DigestWhitelistChecker(
            whitelist_entries,
            restricted_paths=(
                "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
                "/etc/cron.weekly/", "/etc/cron.monthly/"
            ),
            error_map={
                "unauthorized": "cronjob-unauthorized-file",
                "changed": "cronjob-changed-file",
                "ghost": "cronjob-ghost-file"
            }
        )


# needs to be instantiated for the check to be registered with rpmlint
check = CronCheck()

Whitelisting.registerErrorDetails((
    (
        'cronjob-unauthorized-file',
        """A cron job file is installed by this package. {review_needed_text}"""
    ),
    (
        'cronjob-changed-file',
        """A cron job or cron job related file installed by this package changed
        in content. {followup_needed_text}"""
    ),
    (
        'cronjob-ghost-file',
        """A cron job path has been marked as %ghost file by this package.
        This is not allowed as it is impossible to review. Please refer to
        {url} for more information."""
    )
))
