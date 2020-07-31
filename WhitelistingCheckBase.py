# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : Common base class for whitelisting related checks
#############################################################################
import AbstractCheck
import Config

import os


class WhitelistingCheckBase(AbstractCheck.AbstractCheck):
    """Base class for rpmlint checks that use the Whitelisting module."""

    def __init__(self, check_name, whitelist_name):
        AbstractCheck.AbstractCheck.__init__(self, check_name)
        # this option is found in config files in /opt/testing/share/rpmlint/mini,
        # installed there by the rpmlint-mini package.
        WHITELIST_DIR = Config.getOption('WhitelistDataDir', [])

        for wd in WHITELIST_DIR:
            candidate = os.path.join(wd, whitelist_name)
            if os.path.exists(candidate):
                whitelist_path = candidate
                self.m_check_configured = True
                break
        else:
            self.m_check_configured = False

        if self.m_check_configured:
            self.m_wl_checker = self.setupChecker(whitelist_path)

    def check(self, pkg):
        """This is called by rpmlint to perform the cron check on the given
        pkg."""

        if not self.m_check_configured:
            # don't ruin the whole run if this check is not configured, this
            # was hopefully intended by the user.
            return

        self.m_wl_checker.check(pkg)
