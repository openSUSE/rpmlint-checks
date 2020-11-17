# vim: sw=4 et sts=4 ts=4 :
#############################################################################
# Author        : Matthias Gerstner
# Purpose       : reusable code for parsing permissions/chkstat profiles
#############################################################################

import os
import copy


class PermissionsEntry:

    # source profile path
    profile = None
    # source profile line nr
    linenr = None
    # target path
    path = None
    owner = None
    group = None
    # mode as integer
    mode = None
    caps = []
    # related paths from variable expansions
    related_paths = []

    def __init__(self, _profile, _line_nr):

        self.profile = _profile
        self.linenr = _line_nr

    def __str__(self):

        ret = "{}:{}: {path} {owner}:{group} {mode}".format(
            self.profile,
            self.linenr,
            path=self.path,
            owner=self.owner,
            group=self.group,
            mode=oct(self.mode)
        )

        for cap in self.caps:
            ret += "\n+capability " + cap

        for related in self.related_paths:
            ret += "\nrelated to " + related

        return ret


class VariablesHandler:

    def __init__(self, variables_conf_path):

        self.m_variables = {}

        try:
            with open(variables_conf_path) as fd:
                self._parse(variables_conf_path, fd)
        except FileNotFoundError:
            # this can happen during migration in OBS when the new permissions
            # package is not yet around
            pass

    def _parse(self, label, fd):

        for nr, line in enumerate(fd.readlines(), 1):

            line = line.strip()

            if not line or line.startswith('#'):
                continue

            parts = line.split('=', 1)

            if len(parts) != 2:
                raise Exception("{}:{}: parse error".format(label, nr))

            varname = parts[0].strip()
            values = parts[1].split()
            # strip leading or trailing slashes
            values = [v.strip(os.path.sep) for v in values]

            self.m_variables[varname] = values

    def getVariables(self):
        """Returns a dictionary with variable names as keys and a list of
        variable values as values."""
        return self.m_variables

    def expandPaths(self, path):
        """Checks for %{...} variables in the given path and expands them, as
        necessary. Will return a list of expanded paths, will be only a single
        path if no variables are used."""

        ret = [""]

        for part in path.split(os.path.sep):
            if part.startswith('%{') and part.endswith('}'):
                # variable found
                variable = part[2:-1]
                try:
                    expansions = self.m_variables[variable]
                except KeyError:
                    raise Exception("Undeclared variable '{}' encountered in profile".format(variable))

                new_ret = []

                for p in ret:
                    for value in expansions:
                        new_ret.append(os.path.sep.join([p, value]))

                ret = new_ret
            elif not part:
                # a leading slash, ignore
                continue
            else:
                # a regular, fixed string
                ret = [os.path.sep.join([p, part]) for p in ret]

        if path.endswith(os.path.sep):
            # restore trailing slashes since they signify that we
            # expect a directory
            ret = [p + os.path.sep for p in ret]

        return ret


class PermissionsParser:

    def __init__(self, var_handler, profile_path):

        self.m_var_handler = var_handler
        self.m_entries = {}

        with open(profile_path) as fd:
            self._parseFile(profile_path, fd)

    def _parseFile(self, _label, fd):

        class ParseContext:
            active_entries = []
            label = _label

        context = ParseContext()

        for nr, line in enumerate(fd.readlines(), 1):
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            context.line_nr = nr

            self._parseLine(context, line)

    def _parseLine(self, context, line):

        if line.startswith('/') or line.startswith('%'):
            context.active_entries = []

            entry = PermissionsEntry(context.label, context.line_nr)
            path, ownership, mode = line.split()
            # the format supports both "user.group" and
            # "user:group"
            entry.owner, entry.group = ownership.replace('.', ':').split(':')
            entry.mode = int(mode, 8)
            expanded = self.m_var_handler.expandPaths(path)

            for p in expanded:
                entry.path = p
                entry.related_paths = list(filter(lambda e: e != path, expanded))
                key = entry.path.rstrip(os.path.sep)
                if not key:
                    # this is the root node, keep the slash
                    key = '/'
                entry_copy = copy.deepcopy(entry)
                self.m_entries[key] = entry_copy
                context.active_entries.append(entry_copy)
        elif line.startswith('+'):
            # capability line
            _type, rest = line.split()
            _type = _type.lstrip('+')

            if _type != "capabilities":
                raise Exception("Unexpected +[line] encountered in {}:{}".format(context.label, context.line_nr))

            caps = rest.split(',')

            if not context.active_entries:
                raise Exception("+capabilities line without active entries in {}:{}".format(context.label, context.line_nr))

            for entry in context.active_entries:
                entry.caps = caps
        else:
            raise Exception("Unexpected line encountered in {}:{}".format(context.label, context.line_nr))

    def getEntries(self):
        """Returns a dictionary mapping the target file paths to instances of
        PermissionsEntry."""
        return self.m_entries
