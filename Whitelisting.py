# vim: sw=4 ts=4 sts=4 et :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : reusable code for dealing with security whitelistings
#############################################################################

import os
import sys
import hashlib
import json
import stat
import traceback

AUDIT_BUG_URL = "https://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs"
REVIEW_NEEDED_TEXT = """If the package is
    intended for inclusion in any SUSE product please open a bug report to request
    review of the package by the security team. Please refer to {url} for more
    information.""".format(url=AUDIT_BUG_URL)
FOLLOWUP_NEEDED_TEXT = """Please open a bug report to request follow-up review of the
    introduced changes by the security team. Please refer to {url} for more
    information."""
GHOST_ENCOUNTERED_TEXT = """This is not allowed, since it is impossible to
    review. Please refer to {url} for more information."""


def registerErrorDetails(details):
    """details is expected to be a sequence of (id, description) pairs, where
    id is the error id like 'cronjob-unauthorized-file' and description is a
    human readable text describing the situation. The text may contain
    placeholders that will be replaced by the constants above."""
    from Filter import addDetails

    for _id, desc in details:
        addDetails(
            _id,
            desc.format(
                url=AUDIT_BUG_URL,
                review_needed_text=REVIEW_NEEDED_TEXT,
                followup_needed_text=FOLLOWUP_NEEDED_TEXT,
                ghost_encountered_text=GHOST_ENCOUNTERED_TEXT))


class DigestVerificationResult(object):
    """This type represents the result of a digest verification as returned
    from DigestAuditEntry.compareDigests()."""

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


class AuditEntryBase(object):
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

    def bug(self):
        return self.m_bug

    def setComment(self, comment):
        self.m_comment = comment

    def comment(self):
        return self.m_comment

    def _verifyBugNr(self):
        """Perform some sanity checks on the bug nr associated with this audit
        entry."""

        parts = self.m_bug.split('#')

        if len(parts) != 2 or \
                parts[0] not in ("bsc", "boo", "bnc") or \
                not parts[1].isdigit():
            raise Exception("Bad bug nr# '{}'".format(self.m_bug))

    def _verifyPath(self, path):
        if not path.startswith(os.path.sep):
            raise Exception("Bad whitelisting path " + path)


class DigestAuditEntry(AuditEntryBase):

    def __init__(self, bug):

        super().__init__(bug)
        self.m_digests = {}

    def setDigests(self, digests):
        for path, digest in digests.items():
            self._verifyPath(path)
            self._verifyDigestSyntax(digest)

        self.m_digests = digests

    def paths(self):
        return self.digests().keys()

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


class MetaAuditEntry(AuditEntryBase):

    def __init__(self, bug):

        super().__init__(bug)
        self.m_meta = {}

    def paths(self):
        return self.meta().keys()

    def setMeta(self, meta):
        for path, data in meta.items():
            self._verifyPath(path)
            self._verifyMetaData(path, data)

        self.m_meta = meta

    def meta(self):
        """Returns a dictionary specifying file paths and their whitelisted
        metadata attributes:

        "type": one of 'c', 'd', 's' or '-'
        "mode": integer defining the file mode
        "owner": tuple of (user, group) defining the ownership
        "dev": tuple of (minor, major) integers defining device file numbers
        """
        return self.m_meta

    def _verifyMetaData(self, path, data):
        """Verify and CONVERT metadata."""

        req_fields = ("type", "mode", "owner")

        for field in req_fields:
            if field not in data:
                raise Exception("Missing required setting '{}' for path {}".format(field, path))

        _type = data["type"]

        if _type not in ("c", "d", "s", "-"):
            raise Exception("Unexpected type '{}' for path {}".format(_type, path))

        try:
            data["mode"] = int(data["mode"], 8)

            if data["mode"] > 0o7777:
                raise ValueError("octal mode too large")
        except ValueError:
            raise Exception("Bad 'mode' for path " + path)

        if _type == "c" and "dev" not in data:
            raise Exception("Missing 'dev' for path " + path)
        elif _type != "c" and "dev" in data:
            raise Exception("Unsuitable 'dev' specification for path " + path)

        if "dev" in data:
            try:
                major, minor = data["dev"].split(",")
                data["dev"] = int(major), int(minor)
            except Exception as e:
                raise Exception("Bad 'dev' specification for path {}: {}".format(path, str(e)))

        try:
            user, group = data["owner"].split(":")
            data["owner"] = user, group
        except Exception as e:
            raise Exception("Bad 'owner' specification for path {}: {}".format(path, str(e)))

    def _isWeakerMode(self, ours, theirs):
        """Checks whether the mode @theirs only grants less permissions than
        what @ours would grant."""

        if (ours & stat.S_ISVTX) and not (theirs & stat.S_ISVTX):
            # if it's the sticky bit that's missing then we can't consider the
            # encountered mode weaker. The sticky bit might be necessary to
            # protect shared world-writable directories.
            return False

        # otherwise if there's no extra bit in their mode then it should be
        # weaker or equal to ours, security wise
        return (ours | theirs) == ours

    def compareMeta(self, pkg, path, their_meta):
        our_meta = self.m_meta.get(path)
        warning = ""

        their_mode_str = stat.filemode(their_meta.mode)
        their_type = their_mode_str[0]

        if their_type != our_meta["type"]:
            msg = "type mismatch, expected type {} but encountered type {}".format(
                our_meta["type"], their_type
            )
            return (False, msg)

        their_mode = stat.S_IMODE(their_meta.mode)

        if their_mode != our_meta["mode"]:

            if self._isWeakerMode(our_meta["mode"], their_mode):
                # if there are no extra bits set then we can accept it
                # anyways, however we should still warn that something is
                # unexpected.
                warning = "mode doesn't match but grants less permissions than expected"
            else:
                msg = "mode mismatch, expected mode {} but encountered mode {}".format(
                    stat.filemode(our_meta["mode"])[1:], stat.filemode(their_meta.mode)[1:]
                )
                return (False, msg)

        if their_meta.user != our_meta["owner"][0] or their_meta.group != our_meta["owner"][1]:
            msg = "ownership mismatch, expected {} but encountered {}".format(
                ':'.join(our_meta["owner"]), ':'.join(their_meta.user, their_meta.group)
            )
            return (False, msg)

        if their_type in ("c", "b"):
            their_rdev = their_meta.rdev
            their_major, their_minor = os.major(their_rdev), os.minor(their_rdev)
            our_major, our_minor = our_meta["dev"]

            if their_major != our_major or their_minor != our_minor:
                msg = "device node mismatch, expected {} but encountered {}".format(
                    ','.join(our_major, our_minor), ','.join(their_major, their_minor)
                )
                return (False, msg)

        return (True, warning)


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
                        for path in a.paths():
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

    def _getErrorPrefix(self):
        return self.m_path + ": ERROR: "

    def _getWarnPrefix(self):
        return self.m_path + ": WARN: "


class DigestWhitelistParser(WhitelistParser):

    def __init__(self, wl_path):

        super().__init__(wl_path)

    def _parseAuditEntry(self, bug, data):
        """Parses a single JSON audit sub-entry returns an AuditEntry() object
        for it. On non-critical error conditions None is returned, otherwise
        an exception is raised"""

        ret = DigestAuditEntry(bug)

        comment = data.get("comment", None)
        if comment:
            ret.setComment(comment)

        digests = data.get("digests", {})

        if not digests:
            raise Exception(self._getErrorPrefix() + "missing 'digests' for '{}'".format(bug))

        ret.setDigests(digests)

        return ret


class MetaWhitelistParser(WhitelistParser):

    def __init__(self, wl_path):

        super().__init__(wl_path)

    def _parseAuditEntry(self, bug, data):
        """Parses a single JSON audit sub-entry returns an AuditEntry() object
        for it. On non-critical error conditions None is returned, otherwise
        an exception is raised"""

        ret = MetaAuditEntry(bug)

        comment = data.get("comment", None)
        if comment:
            ret.setComment(comment)

        meta = data.get("meta", {})

        if not meta:
            raise Exception(self._getErrorPrefix() + "missing 'meta' entry for '{}'".format(bug))

        ret.setMeta(meta)

        return ret


class DigestWhitelistChecker(object):
    """This type actually compares files found in an RPM against digest
    whitelist entries."""

    def __init__(self, whitelist_entries, restricted_paths, error_map):
        """Instantiate a properly configured checker

        :param whitelist_entries: is a dictionary data structure as returned
                                  from DigestWhitelistParser.parse().
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

    def _isRestrictedPath(self, path):
        for restricted in self.m_restricted_paths:
            if path.startswith(restricted):
                return True

        return False

    def _getWhitelist(self, pkg_name, path):
        entries = self.m_whitelist_entries.get(path, [])
        for entry in entries:
            if entry.package() == pkg_name:
                return entry

        return None

    def check(self, pkg):
        """Checks the given RPM pkg instance against the configured whitelist
        restriction.

        Each whitelist violation will be printed with the according error tag.
        Nothing is returned from this function.
        """

        from Filter import printError

        if pkg.isSource():
            return

        files = pkg.files()
        already_tested = set()

        for f in files:
            if not self._isRestrictedPath(f):
                continue

            if f in pkg.ghostFiles():
                printError(pkg, self.m_error_map['ghost'], f)
                continue

            wl_match = self._getWhitelist(pkg.name, f)

            if not wl_match:
                # no whitelist entry exists for this file
                printError(pkg, self.m_error_map['unauthorized'], f)
                continue

            # avoid testing the same paths multiple times thereby avoiding
            # duplicate error messages or unnecessary re-checks of the same
            # files.
            # this is necessary since whitelisting entries can consist of
            # groups of files that are all checked in one go below.
            if f in already_tested:
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
                    for r in results:
                        already_tested.add(r.path())
                    break

                if not diag_results:
                    diag_results = results
            else:
                for r in diag_results:
                    already_tested.add(r.path())
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


class MetaWhitelistChecker(object):
    """This type actually compares files found in an RPM against whitelist
    entries."""

    def __init__(self, whitelist_entries, error_map, restricted_mode, restricted_types):
        """Instantiate a properly configured checker. For metadata
        restrictions both `restricted_mode` and `restricted_types` need to
        match for a check to be triggered.

        :param whitelist_entries: is a dictionary data structure as returned
                                  from MetaWhitelistParser.parse().
        :param error_map: is a specification of rpmlint error labels for
                          files like "unauthorized" and "mismatch"
                          {
                            "unauthorized": "special-file-unauthorized",
                            "mismatch": "special-file-mismatch"
                          }
        :param restricted_mode: an octal bit mask that specifies file mode
                                bits that are restricted by this whitelist.
                                e.g. 0o001 would trigger a check for all files
                                containing a world executable bit. 0o7777
                                would catch any mode.
        :param restricted_types: a sequence of file types that are restricted
                                by this whitelist. E.g. ("f", "s") would
                                trigger a check for all regular files and
                                socket files. An entry of "*" will match all
                                file types.
        """

        self.m_whitelist_entries = whitelist_entries
        self.m_error_map = error_map
        self.m_restricted_mode = restricted_mode
        self.m_restricted_types = restricted_types

        req_error_keys = ("unauthorized", "mismatch")

        for req_key in req_error_keys:
            if req_key not in self.m_error_map:
                raise Exception("Missing {} error mapping".format(req_key))

    def _hasRestrictedMeta(self, meta):

        if self.m_restricted_mode == 0o7777:
            # all modes should match so ignore it
            pass
        elif (meta.mode & self.m_restricted_mode) == 0:
            # none of the interesting mode bits matches
            return False

        if "*" in self.m_restricted_types:
            # match all file types
            return True
        elif stat.filemode(meta.mode)[0] in self.m_restricted_types:
            # filemode() returns an ls like string like `-rwx------`.
            # we # inspect the type character and compare it against our list
            # of restricted file types
            return True

        return False

    def _getWhitelist(self, pkg_name, path):
        entries = self.m_whitelist_entries.get(path, [])
        for entry in entries:
            if entry.package() == pkg_name:
                return entry

        return None

    def check(self, pkg):
        """Checks the given RPM pkg instance against the configured whitelist
        restriction.

        Each whitelist violation will be printed with the according error tag.
        Nothing is returned from this function.
        """

        from Filter import printError

        if pkg.isSource():
            return

        files = pkg.files()

        for f, meta in files.items():
            if not self._hasRestrictedMeta(meta):
                continue

            wl_match = self._getWhitelist(pkg.name, f)

            if not wl_match:
                # no whitelist entry exists for this file
                printError(pkg, self.m_error_map['unauthorized'], f)
                continue

            for audit in wl_match.audits():
                res, msg = audit.compareMeta(pkg, f, meta)

                if res:
                    if msg:
                        # a warning only message
                        print("{}: {}".format(f, msg), file=sys.stderr)
                    break

                print("{}: {}".format(f, msg), file=sys.stderr)
                printError(pkg, self.m_error_map['mismatch'], f)
