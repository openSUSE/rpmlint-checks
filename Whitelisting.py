# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : reusable code for dealing with security whitelistings
#############################################################################

import os
import sys
import json
import hashlib
import traceback

from Filter import printError

AUDIT_BUG_URL = "https://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs"


class DigestVerificationResult(object):
    """This type represents the result of a digest verification as returned
    from AuditEntry.compareDigests()."""

    def __init__(self, path, alg, expected, encountered):

        self.m_path = path
        self.m_alg = alg
        self.m_expected = expected
        self.m_encountered = encountered

    def path(self):
        return self.m_path

    def algorithm(self):
        return self.m_alg

    def matches(self):
        """Returns a boolean whether the encountered digest matches the
        expected digest."""
        return self.m_expected == self.m_encountered

    def expected(self):
        return self.m_expected

    def encountered(self):
        return self.m_encountered


class AuditEntry(object):
    """This object represents a single audit entry as found in a whitelisting
    entry like:

    "bsc#1234": {
        "comment": "some comment",
        "digests": {
            "/some/file": "<alg>:<digest>",
            ...
        }
    }

    """

    def __init__(self, bug):

        self.m_bug = bug
        self._verifyBugNr()
        self.m_comment = ""
        self.m_digests = {}

    def bug(self):
        return self.m_bug

    def setComment(self, comment):
        self.m_comment = comment

    def comment(self):
        return self.m_comment

    def setDigests(self, digests):
        for path, digest in digests.items():
            self._verifyPath(path)
            self._verifyDigestSyntax(digest)

        self.m_digests = digests

    def digests(self):
        """Returns a dictionary specifying file paths and their whitelisted
        digests. The digests are suitable for the
        Python hashlib module. They're of the form '<alg>:<hexdigest>'. As a
        special case the digest entry can be 'skip:<none>' which indicates
        that no digest verification should be performed and the file is
        acceptable regardless of its contents."""
        return self.m_digests

    def isSkipDigest(self, digest):
        """Returns whether the given digest entry denotes the special "skip
        digest" case which means not to check the file digest at all."""
        return digest == 'skip:<none>'

    def compareDigests(self, pkg):
        """Compares the digests recorded in this AuditEntry against the actual
        files coming from the given rpmlint @pkg. Returns a tuple of
        (boolean, [DigestVerificationResult, ...]). The boolean indicates the
        overall verification result, while the list of
        DigestVerificationResult entries provides detailed information about
        the encountered data. Any "skip digest" entries will be ignored and
        not be included in the result list."""

        results = []

        # NOTE: syntax and algorithm validity of stored digests was already
        # checked in setDigests() so we can skip the respective error handling
        # here.

        fileinfos = pkg.files()

        for path, digest in self.digests().items():
            if self.isSkipDigest(digest):
                continue

            alg, digest = digest.split(':', 1)

            try:
                h = hashlib.new(alg)

                src_info = fileinfos.get(path, None)

                if not src_info:
                    raise Exception("expected file {} is not part of the RPM".format(path))

                # resolve potential symbolic links
                #
                # this function handles both absolute and relative symlinks
                # and does not access paths outside the RPM.
                #
                # it is not safe against symlink loops, however, it will
                # result in an infinite loop it such cases. But there are
                # probably a lot of other possibilities to DoS the RPM build
                # process or rpmlint.
                dst_info = pkg.readlink(src_info)

                if not dst_info:
                    raise Exception("symlink {} -> {} is broken or pointing outside this RPM".format(src_info.path, src_info.linkto))

                # NOTE: this path is dynamic, rpmlint unpacks the RPM
                # contents into a temporary directory even when outside the
                # build environment i.e. the file content should always be
                # available to us.
                with open(dst_info.path, 'rb') as fd:
                    while True:
                        chunk = fd.read(4096)
                        if not chunk:
                            break

                        h.update(chunk)

                    encountered = h.hexdigest()
            except IOError as e:
                encountered = "error:" + str(e)
            except Exception as e:
                encountered = "error:" + str(e)

            dig_res = DigestVerificationResult(path, alg, digest, encountered)
            results.append(dig_res)

        return (all([res.matches() for res in results]), results)

    def _verifyBugNr(self):
        """Perform some sanity checks on the bug nr associated with this audit
        entry."""

        parts = self.m_bug.split('#')

        if len(parts) != 2 or \
                parts[0] not in ("bsc", "boo", "bnc") or \
                not parts[1].isdigit():
            raise Exception("Bad bug nr# '{}'".format(self.m_bug))

    def _verifyDigestSyntax(self, digest):
        if self.isSkipDigest(digest):
            return

        parts = digest.split(':')
        if len(parts) != 2:
            raise Exception("Bad digest specification " + digest)

        alg, hexdigest = parts

        try:
            hashlib.new(alg)
        except ValueError:
            raise Exception("Bad digest algorithm in " + digest)

    def _verifyPath(self, path):
        if not path.startswith(os.path.sep):
            raise Exception("Bad whitelisting path " + path)


class WhitelistEntry(object):
    """This object represents a single whitelisting entry like:

    "somepackage" {
        "audits": {
            ...
        }
    },
    """

    def __init__(self, package):
        self.m_package = package
        # a list of AuditEntry objects associated with this whitelisting entry
        self.m_audits = []

    def package(self):
        return self.m_package

    def addAudit(self, audit):
        self.m_audits.append(audit)

    def audits(self):
        return self.m_audits


class WhitelistParser(object):
    """This type knows how to parse the JSON whitelisting format. The format
    is documented in [1].

    [1]: https://github.com/openSUSE/rpmlint-security-whitelistings/blob/master/README.md
    """

    def __init__(self, wl_path):
        """Creates a new instance of WhitelistParser that operates on
        @wl_path."""

        self.m_path = wl_path

    def parse(self):
        """Parses the whitelisting file and returns a dictionary of the
        following structure:

        {
            "path/to/file": [WhitelistEntry(), ...],
            ...
        }

        Since a single path might be claimed by more than one package the
        values of the dictionary are lists, to cover for this possibility.
        """

        ret = {}

        try:
            with open(self.m_path, 'r') as fd:
                data = json.load(fd)

                for pkg, config in data.items():
                    entry = self._parseWhitelistEntry(pkg, config)
                    if not entry:
                        # soft error, continue parsing
                        continue
                    for a in entry.audits():
                        for path in a.digests():
                            entries = ret.setdefault(path, [])
                            entries.append(entry)
        except Exception as e:
            _, _, tb = sys.exc_info()
            fn, ln, _, _ = traceback.extract_tb(tb)[-1]
            raise Exception(self._getErrorPrefix() + "Failed to parse JSON file: {}:{}: {}".format(
                fn, ln, str(e)
            ))

        return ret

    def _parseWhitelistEntry(self, package, config):
        """Parses a single JSON whitelist entry and returns a WhitelistEntry()
        object for it. On non-critical error conditions None is returned,
        otherwise an exception is raised."""

        ret = WhitelistEntry(package)

        audits = config.get("audits", {})

        if not audits:
            raise Exception(self._getErrorPrefix() + "no 'audits' entries for package {}".format(package))

        for bug, data in audits.items():
            try:
                audit = self._parseAuditEntry(bug, data)
            except Exception as e:
                raise Exception(self._getErrorPrefix() + "Failed to parse audit entries: " + str(e))

            if not audit:
                # soft error, continue parsing
                continue
            ret.addAudit(audit)

        return ret

    def _parseAuditEntry(self, bug, data):
        """Parses a single JSON audit sub-entry returns an AuditEntry() object
        for it. On non-critical error conditions None is returned, otherwise
        an exception is raised"""

        ret = AuditEntry(bug)

        comment = data.get("comment", None)
        if comment:
            ret.setComment(comment)

        digests = data.get("digests", {})

        if not digests:
            raise Exception(self._getErrorPrefix() + "no 'digests' entry for '{}'".format(bug))

        ret.setDigests(digests)

        return ret

    def _getErrorPrefix(self):
        return self.m_path + ": ERROR: "

    def _getWarnPrefix(self):
        return self.m_path + ": WARN: "


class WhitelistChecker(object):
    """This type actually compares files found in an RPM against whitelist
    entries."""

    def __init__(self, whitelist_entries, restricted_paths, error_map):
        """Instantiate a properly configured checker

        :param whitelist_entries: is a dictionary data structure as returned
                                  from WhitelistParser.parse().
        :param restricted_paths: a sequence of path prefixes that will trigger
                                 the whitelisting check. All other paths will
                                 be ignored.
        :param error_map: is a specification of rpmlint error labels for ghost
                          files, unauthorized files and changed files like:
                          {
                            "unauthorized": "polkit-unauthorized-rules",
                            "changed": "polkit-changed-rules",
                            "ghost": "polkit-ghost-file"
                          }
        """

        self.m_restricted_paths = restricted_paths
        self.m_whitelist_entries = whitelist_entries
        self.m_error_map = error_map

        req_error_keys = ("unauthorized", "changed", "ghost")

        for req_key in req_error_keys:
            if req_key not in self.m_error_map:
                raise Exception("Missing {} error mapping".format(req_key))

    def check(self, pkg):
        """Checks the given RPM pkg instance against the configured whitelist
        restriction.

        Each whitelist violation will be printed with the according error tag.
        Nothing is returned from this function.
        """

        if pkg.isSource():
            return

        files = pkg.files()

        for f in files:
            for restricted in self.m_restricted_paths:
                if f.startswith(restricted):
                    break
            else:
                # no match
                continue

            if f in pkg.ghostFiles():
                printError(pkg, self.m_error_map['ghost'], f)
                continue

            entries = self.m_whitelist_entries.get(f, [])
            wl_match = None
            for entry in entries:
                if entry.package() == pkg.name:
                    wl_match = entry
                    break
            else:
                # no whitelist entry exists for this file
                printError(pkg, self.m_error_map['unauthorized'], f)
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
                printError(pkg, self.m_error_map['changed'], f)
                continue

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
