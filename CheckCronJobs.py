# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : Enforce Whitelisting for cron jobs in /etc/cron.* directories
#############################################################################

import os
import sys

import AbstractCheck
import Config
import Whitelisting

from Filter import addDetails, printError

# this option is found in config files in /opt/testing/share/rpmlint/mini,
# installed there by the rpmlint-mini package.
WHITELIST_DIR = Config.getOption('WhitelistDataDir', [])


class CronCheck(AbstractCheck.AbstractCheck):

    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckCronJobs")

        for wd in WHITELIST_DIR:
            candidate = os.path.join(wd, "cron-whitelist.json")
            if os.path.exists(candidate):
                whitelist_path = candidate
                break
        else:
            whitelist_path = None

        self.m_check_configured = whitelist_path is not None

        if not self.m_check_configured:
            return

        parser = Whitelisting.WhitelistParser(whitelist_path)
        self.m_whitelist_entries = parser.parse()

    def _getPrintPrefix(self):
        """Returns a prefix for error / warning output."""
        return self.__class__.__name__ + ":"

    def _getErrorPrefix(self):
        return self._getPrintPrefix() + " ERROR: "

    def _getWarnPrefix(self):
        return self._getPrintPrefix() + " WARN: "

    def _printVerificationResults(self, verification_results):
        """For the case of changed file digests this function prints the
        encountered and expected digests and paths for diagnostic purposes."""

        for result in verification_results:
            if result.matches():
                continue

            print("{path}: expected {alg} digest {expected} but encountered {encountered}".format(
                path=result.path(), alg=result.algorithm(),
                expected=result.expected(), encountered=result.encountered()
            ), file=sys.stderr)

    def check(self, pkg):
        """This is called by rpmlint to perform the cron check on the given
        pkg."""

        if pkg.isSource():
            return
        elif not self.m_check_configured:
            # don't ruin the whole run if this check is not configured, this
            # was hopefully intended by the user.
            return

        files = pkg.files()
        cron_dirs = (
            "/etc/cron.d/",
            "/etc/cron.hourly/",
            "/etc/cron.daily/",
            "/etc/cron.weekly/",
            "/etc/cron.monthly/"
        )

        for f in files:
            if f in pkg.ghostFiles():
                continue

            for cron_dir in cron_dirs:
                if f.startswith(cron_dir):
                    break
            else:
                # no match
                continue

            entries = self.m_whitelist_entries.get(f, [])
            wl_match = None
            for entry in entries:
                if entry.package() == pkg.name:
                    wl_match = entry
                    break
            else:
                # no whitelist entry exists for this file
                printError(pkg, 'cronjob-unauthorized-file', f)
                continue

            # for the case that there's no match of digests, remember the most
            # recent digest verification result for diagnosis output towards
            # the user
            diag_results = None

            # check the newest (bottom) entry first it is more likely to match
            # what we have
            for audit in reversed(wl_match.audits()):
                digest_matches, results = audit.compareDigests(pkg)

                if digest_matches:
                    break

                if not diag_results:
                    diag_results = results
            else:
                # none of the digest entries matched
                self._printVerificationResults(diag_results)
                printError(pkg, 'cronjob-changed-file', f)
                continue


# needs to be instantiated for the check to be registered with rpmlint
check = CronCheck()

AUDIT_BUG_URL = "https://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs"

for detail, desc in (
        ('cronjob-unauthorized-file',
        """A cron job rule file is installed by this package. If the package is
        intended for inclusion in any SUSE product please open a bug report to request
        review of the package by the security team. Please refer to {url} for more
        information"""),
        ('cronjob-changed-file',
        """A cron job or cron job related file installed by this package changed
        in content. Please open a bug report to request follow-up review of the
        introduced changes by the security team. Please refer to {url} for more
        information.""")
    ):
    addDetails(detail, desc.format(url = AUDIT_BUG_URL))

