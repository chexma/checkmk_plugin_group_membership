#!/usr/bin/env python3
"""Checkmk agent plugin: who has administrative rights on a Linux host.

Reports the members of privileged groups, the users and groups named in the
sudoers files and the accounts with UID 0. What to report is listed in the
configuration file $MK_CONFDIR/local_group_members.cfg:

    group=sudo           (name of a group)
    group=@sudoers       (users and groups in /etc/sudoers and the files it includes)
    group=@uid0          (accounts with UID 0)

Output (section local_group_members, separated by pipes):

    computer|<short host name>
    group|<key>|<gid:N>|<group name>|<status>|<method>|<message>
    member|<key>|<uid:N or gid:N>|<member name>|<object class>|<source>|<details>

<status> is ok, missing (no such group, no sudoers file) or error. <source> is
Local (the account is in /etc/passwd or /etc/group), Directory (it is known to
the system only by NSS, e.g. SSSD or LDAP) or Unknown (it cannot be resolved).
<details> is set for sudoers entries: "ALL" if the entry may run every command
as root, "restricted" otherwise, plus "NOPASSWD".

Needs Python 3.4 or newer and only the standard library.
"""

import errno
import grp
import io
import os
import pwd
import re
import socket
import sys

SUDOERS = "@sudoers"
UID0 = "@uid0"
DEFAULT_GROUPS = ["sudo", "wheel", "admin", "root", SUDOERS, UID0]

SUDOERS_FILE = "/etc/sudoers"
MAX_INCLUDE_DEPTH = 16

_ALIAS_KINDS = ("User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias")
# One word of a sudoers line: escaped characters and quoted strings belong to it.
_WORD = re.compile(r'(?:\\.|"[^"]*"|[^\s\\"])+')
_TAG = re.compile(r"^[A-Z_]+:\s*")
_OPTION = re.compile(r"^[A-Z_]+=\S+\s+")


def read_config(path):
    """Return the configured group specs, or the defaults without a usable file."""
    try:
        text = read_file(path)
    except (IOError, OSError):
        return list(DEFAULT_GROUPS)
    specs = []
    for line in text.splitlines():
        match = re.match(r"^\s*group\s*=\s*(.+?)\s*$", line)
        if match and match.group(1) not in specs:
            specs.append(match.group(1))
    return specs or list(DEFAULT_GROUPS)


def read_file(path):
    with io.open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _local_names(path):
    try:
        text = read_file(path)
    except (IOError, OSError):
        return set()
    return {line.split(":", 1)[0] for line in text.splitlines() if ":" in line}


class Accounts(object):
    """Users and groups as the system resolves them (NSS, so including SSSD or LDAP).

    Users are (name, uid, gid), groups are (name, gid, member names).
    """

    def __init__(self):
        self.local_users = _local_names("/etc/passwd")
        self.local_groups = _local_names("/etc/group")

    def all_users(self):
        return [(entry.pw_name, entry.pw_uid, entry.pw_gid) for entry in pwd.getpwall()]

    def user(self, name):
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            return None
        return (entry.pw_name, entry.pw_uid, entry.pw_gid)

    def user_by_uid(self, uid):
        try:
            entry = pwd.getpwuid(uid)
        except (KeyError, OverflowError):
            return None
        return (entry.pw_name, entry.pw_uid, entry.pw_gid)

    def group(self, name):
        try:
            entry = grp.getgrnam(name)
        except KeyError:
            return None
        return (entry.gr_name, entry.gr_gid, list(entry.gr_mem))

    def group_by_gid(self, gid):
        try:
            entry = grp.getgrgid(gid)
        except (KeyError, OverflowError):
            return None
        return (entry.gr_name, entry.gr_gid, list(entry.gr_mem))


def _ident(kind, number, name, owner):
    # Several accounts can share one UID (that is what "UID 0" is about): only
    # the account the system resolves the number to gets the plain ident.
    if owner is not None and owner[0] != name:
        return "%s:%d/%s" % (kind, number, name)
    return "%s:%d" % (kind, number)


def user_member(accounts, name, details=""):
    user = accounts.user(name)
    if user is None:
        return ("name:" + name, name, "User", "Unknown", details)
    ident = _ident("uid", user[1], user[0], accounts.user_by_uid(user[1]))
    source = "Local" if user[0] in accounts.local_users else "Directory"
    return (ident, user[0], "User", source, details)


def group_member(accounts, name, details=""):
    """A group as member of the sudoers: shown as %<name>, like in the file."""
    group = accounts.group(name)
    if group is None:
        return ("name:%" + name, "%" + name, "Group", "Unknown", details)
    ident = _ident("gid", group[1], group[0], accounts.group_by_gid(group[1]))
    source = "Local" if group[0] in accounts.local_groups else "Directory"
    return (ident, "%" + group[0], "Group", source, details)


def group_members(accounts, name):
    """Return (gid, members) of a group, or None if there is no such group.

    Members are the listed ones plus the users having the group as primary group.
    """
    group = accounts.group(name)
    if group is None:
        return None
    names = list(group[2])
    names += [user[0] for user in accounts.all_users() if user[2] == group[1]]
    members = []
    for member_name in names:
        member = user_member(accounts, member_name)
        if member not in members:
            members.append(member)
    return group[1], members


def uid0_accounts(accounts):
    members = []
    for user in accounts.all_users():
        if user[1] == 0:
            member = user_member(accounts, user[0])
            if member not in members:
                members.append(member)
    return members


def _strip_comment(line):
    if re.match(r"\s*#include(dir)?\s", line):
        return line
    # "#" starts a comment unless a UID or GID follows (#1000, %#1000).
    return re.sub(r"#(?![0-9]).*$", "", line)


def sudoers_lines(path, read, list_dir, hostname="", depth=0):
    """Yield the statements of a sudoers file and of the files it includes."""
    if depth > MAX_INCLUDE_DEPTH:
        return
    pending = ""
    for raw in read(path).splitlines():
        if raw.endswith("\\"):
            pending += raw[:-1]
            continue
        line = _strip_comment(pending + raw).strip()
        pending = ""
        if not line:
            continue

        include = re.match(r"[#@](include|includedir)\s+(.+)$", line)
        if not include:
            yield line
            continue
        target = include.group(2).strip().strip('"').replace("\\ ", " ").replace("%h", hostname)
        target = os.path.join(os.path.dirname(path), target)
        if include.group(1) == "include":
            files = [target]
        else:
            try:
                names = sorted(list_dir(target))
            except (IOError, OSError):
                continue
            # sudo skips these names: backup files and files of package managers.
            files = [
                os.path.join(target, name)
                for name in names
                if "." not in name and not name.endswith("~")
            ]
        for included in files:
            try:
                for statement in sudoers_lines(included, read, list_dir, hostname, depth + 1):
                    yield statement
            except (IOError, OSError):
                continue


def _unquote(word):
    return re.sub(r"\\(.)", r"\1", word.replace('"', ""))


def _split_list(text):
    """Split a comma separated list, ignoring commas in parentheses or quotes."""
    items, current, depth, quoted, escaped = [], "", 0, False, False
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth = max(depth - 1, 0)
        elif not quoted and depth == 0 and char == ",":
            items.append(current.strip())
            current = ""
            continue
        current += char
    items.append(current.strip())
    return [item for item in items if item]


def _resolve(names, aliases, seen=()):
    """Replace alias names in a list by their members."""
    resolved = []
    for name in names:
        if name in aliases and name not in seen:
            resolved += _resolve(aliases[name], aliases, seen + (name,))
        else:
            resolved.append(name)
    return resolved


def _runs_as_root(runas, aliases):
    """Does the Runas specification "(users : groups)" include root?"""
    if runas is None:
        return True  # the default target user is root
    users = _resolve(
        [_unquote(user) for user in _split_list(runas.split(":", 1)[0])],
        aliases.get("Runas_Alias", {}),
    )
    return any(user in ("ALL", "root", "#0") for user in users)


def _rights(commands, aliases):
    """Return (may run every command as root, without password) of a command list."""
    full = False
    nopasswd = False
    runas = None
    for item in _split_list(commands):
        match = re.match(r"\(([^)]*)\)\s*", item)
        if match:
            runas = match.group(1)
            item = item[match.end() :]
        while True:
            tag = _TAG.match(item) or _OPTION.match(item)
            if not tag:
                break
            nopasswd = nopasswd or tag.group(0).startswith("NOPASSWD:")
            item = item[tag.end() :]
        names = _resolve([item.strip()], aliases.get("Cmnd_Alias", {}))
        if "ALL" in names and _runs_as_root(runas, aliases):
            full = True
    return full, nopasswd


def parse_sudoers(statements):
    """Return the principals of the user specifications: [(name, full, nopasswd)].

    A principal is written as in the file: user, %group, #uid, %#gid, +netgroup
    or ALL. Entries of several rules are merged; negated entries are ignored.
    """
    statements = list(statements)
    aliases = {}
    rules = []
    for statement in statements:
        keyword = statement.split(None, 1)[0]
        if re.match(r"Defaults([@:!>\s]|$)", statement):
            continue
        if keyword in _ALIAS_KINDS:
            kind = "Cmnd_Alias" if keyword == "Cmd_Alias" else keyword
            definitions = re.split(r":\s*(?=[A-Z][A-Z0-9_]*\s*=)", statement[len(keyword) :])
            for definition in definitions:
                if "=" in definition:
                    name, members = definition.split("=", 1)
                    aliases.setdefault(kind, {})[name.strip()] = [
                        _unquote(member) for member in _split_list(members)
                    ]
            continue
        if "=" in statement:
            left, right = statement.split("=", 1)
            # "user host1 = commands : host2 = commands": the hosts do not matter here.
            for commands in re.split(r"\s:\s*[^=:()]+=", right):
                rules.append((left, commands))

    principals = {}
    order = []
    for left, commands in rules:
        # "alice, %admins ALL": the first word is the user list, hosts follow.
        words = _WORD.findall(re.sub(r"\s*,\s*", ",", left.strip()))
        if not words:
            continue
        users = _resolve(
            [_unquote(user) for user in _split_list(words[0])], aliases.get("User_Alias", {})
        )
        full, nopasswd = _rights(commands, aliases)
        for user in users:
            if user.startswith("!"):
                continue
            if user not in principals:
                principals[user] = [False, False]
                order.append(user)
            principals[user][0] = principals[user][0] or full
            principals[user][1] = principals[user][1] or nopasswd
    return [(user, principals[user][0], principals[user][1]) for user in order]


def sudoers_members(accounts, principals):
    # The same account can be written in several ways (bob, #1001): merge by ident.
    members = {}
    order = []
    for name, full, nopasswd in principals:
        if name == "ALL":
            member = ("name:ALL", "ALL", "Other", "Unknown")
        elif re.match(r"%#\d+$", name):
            group = accounts.group_by_gid(int(name[2:]))
            member = group_member(accounts, group[0] if group else name[1:])[:4]
        elif name.startswith("%:") or name.startswith("+"):
            # Non-Unix groups and netgroups: only the directory knows them.
            member = ("name:" + name, name, "Group", "Directory")
        elif name.startswith("%"):
            member = group_member(accounts, name[1:])[:4]
        elif re.match(r"#\d+$", name):
            user = accounts.user_by_uid(int(name[1:]))
            member = user_member(accounts, user[0] if user else name)[:4]
        else:
            member = user_member(accounts, name)[:4]
        if member[0] not in members:
            members[member[0]] = [member, False, False]
            order.append(member[0])
        members[member[0]][1] = members[member[0]][1] or full
        members[member[0]][2] = members[member[0]][2] or nopasswd
    return [
        member + (("ALL" if full else "restricted") + (", NOPASSWD" if nopasswd else ""),)
        for member, full, nopasswd in (members[ident] for ident in order)
    ]


def _field(value):
    # Keep the section parseable: no separators or line breaks inside a field.
    return re.sub(r"[|\r\n]+", " ", str(value))


def _group_line(key, ident, name, status, method="", message=""):
    return "|".join(["group", str(key), ident, _field(name), status, method, _field(message)])


def section_lines(specs, accounts, read=read_file, list_dir=os.listdir, hostname=""):
    lines = ["<<<local_group_members:sep(124)>>>", "computer|" + _field(hostname)]
    for key, spec in enumerate(specs, start=1):
        try:
            if spec == SUDOERS:
                name, ident, method = "sudoers", "", "sudoers"
                members = sudoers_members(
                    accounts,
                    parse_sudoers(sudoers_lines(SUDOERS_FILE, read, list_dir, hostname)),
                )
            elif spec == UID0:
                name, ident, method = "UID 0", "", "nss"
                members = uid0_accounts(accounts)
            else:
                name, ident, method = spec, "", "nss"
                found = group_members(accounts, spec)
                if found is None:
                    lines.append(_group_line(key, "", spec, "missing"))
                    continue
                ident, members = "gid:%d" % found[0], found[1]
        except (IOError, OSError) as exc:
            status = "missing" if exc.errno == errno.ENOENT else "error"
            lines.append(_group_line(key, ident, name, status, "", exc.strerror or exc))
            continue
        except Exception as exc:  # pylint: disable=broad-except
            lines.append(_group_line(key, ident, name, "error", "", exc))
            continue

        lines.append(_group_line(key, ident, name, "ok", method))
        for member in members:
            fields = ["member", str(key)] + [_field(value) for value in member]
            lines.append("|".join(fields).rstrip("|"))
    return lines


def main():
    config = os.path.join(os.environ.get("MK_CONFDIR", "/etc/check_mk"), "local_group_members.cfg")
    lines = section_lines(
        read_config(config),
        Accounts(),
        hostname=socket.gethostname().split(".")[0],
    )
    sys.stdout.buffer.write(("\n".join(lines) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
