#!/usr/bin/env python3
"""Tests for the Linux agent plugin local_group_members.py (all names are fictional)."""

import errno
import importlib.util
from pathlib import Path

import pytest

_PLUGIN = Path(__file__).parent.parent / "plugins/local_group_members/agents/local_group_members.py"
_spec = importlib.util.spec_from_file_location("agent_local_group_members", _PLUGIN)
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class FakeAccounts(agent.Accounts):
    # root and toor share UID 0, carol and linux-admins come from a directory,
    # dave has sudo as primary group, ghost is listed in a group but does not exist.
    USERS = [
        ("root", 0, 0),
        ("toor", 0, 0),
        ("alice", 1000, 1000),
        ("bob", 1001, 1001),
        ("dave", 1002, 27),
        ("carol", 20001, 20000),
    ]
    GROUPS = [
        ("root", 0, []),
        ("sudo", 27, ["alice", "carol", "ghost"]),
        ("linux-admins", 2000, []),
        ("domain admins", 2001, []),
    ]

    def __init__(self):  # pylint: disable=super-init-not-called
        self.local_users = {"root", "toor", "alice", "bob", "dave"}
        self.local_groups = {"root", "sudo"}

    def all_users(self):
        return list(self.USERS)

    def user(self, name):
        return next((user for user in self.USERS if user[0] == name), None)

    def user_by_uid(self, uid):
        return next((user for user in self.USERS if user[1] == uid), None)

    def group(self, name):
        return next((group for group in self.GROUPS if group[0] == name), None)

    def group_by_gid(self, gid):
        return next((group for group in self.GROUPS if group[1] == gid), None)


SUDOERS = r"""
# This file MUST be edited with visudo.
Defaults        env_reset
Defaults:alice  !requiretty
User_Alias ADMINS = alice, bob : OPS = carol
Cmnd_Alias SERVICES = /usr/bin/systemctl restart *, \
    /usr/bin/journalctl

root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL   # members of sudo
ADMINS  ALL=(ALL) NOPASSWD: ALL
OPS     ALL = SERVICES
dave, !erin ALL=(appuser) ALL
#1002   ALL=(ALL) ALL
%#2000  ALL=(ALL) ALL
+netadmins ALL=(ALL) ALL
"%domain admins" ALL=(ALL) ALL
frank   host1 = /bin/ls : host2 = ALL
@includedir /etc/sudoers.d
#include sudoers.local
"""

FILES = {
    "/etc/sudoers": SUDOERS,
    "/etc/sudoers.d/10-app": "svc_app ALL=(root) NOPASSWD: /usr/bin/app\n",
    "/etc/sudoers.d/README.txt": "mallory ALL=(ALL) ALL\n",
    "/etc/sudoers.d/old~": "mallory ALL=(ALL) ALL\n",
    "/etc/sudoers.local": "grace ALL=(ALL) ALL\n",
}


def _read(path):
    if path not in FILES:
        raise IOError(errno.ENOENT, "No such file or directory")
    return FILES[path]


def _list_dir(path):
    names = [name[len(path) + 1 :] for name in FILES if name.startswith(path + "/")]
    if not names:
        raise OSError(errno.ENOENT, "No such file or directory")
    return names


@pytest.fixture(name="principals")
def _principals():
    return agent.parse_sudoers(agent.sudoers_lines("/etc/sudoers", _read, _list_dir))


def test_sudoers_principals(principals):
    assert principals == [
        ("root", True, False),
        ("%sudo", True, False),
        ("alice", True, True),
        ("bob", True, True),
        ("carol", False, False),  # only the commands of a Cmnd_Alias
        ("dave", False, False),  # every command, but not as root
        ("#1002", True, False),
        ("%#2000", True, False),
        ("+netadmins", True, False),
        ("%domain admins", True, False),
        ("frank", True, False),  # ALL on the second host
        ("svc_app", False, True),
        ("grace", True, False),
    ]


def test_sudoers_skips_backup_and_dotted_files_of_includedir(principals):
    assert "mallory" not in [name for name, _full, _nopasswd in principals]


def test_sudoers_members_resolve_and_merge(principals):
    members = {member[1]: member for member in agent.sudoers_members(FakeAccounts(), principals)}
    assert members["root"] == ("uid:0", "root", "User", "Local", "ALL")
    assert members["%sudo"] == ("gid:27", "%sudo", "Group", "Local", "ALL")
    assert members["alice"] == ("uid:1000", "alice", "User", "Local", "ALL, NOPASSWD")
    assert members["carol"] == ("uid:20001", "carol", "User", "Directory", "restricted")
    # "dave" (restricted) and "#1002" (ALL) are the same account.
    assert members["dave"] == ("uid:1002", "dave", "User", "Local", "ALL")
    assert members["%linux-admins"] == ("gid:2000", "%linux-admins", "Group", "Directory", "ALL")
    assert members["+netadmins"] == ("name:+netadmins", "+netadmins", "Group", "Directory", "ALL")
    assert members["frank"] == ("name:frank", "frank", "User", "Unknown", "ALL")
    assert members["svc_app"][4] == "restricted, NOPASSWD"
    assert "#1002" not in members


def test_sudoers_all_users():
    principals = agent.parse_sudoers(["ALL ALL=(ALL) ALL"])
    assert agent.sudoers_members(FakeAccounts(), principals) == [
        ("name:ALL", "ALL", "Other", "Unknown", "ALL")
    ]


@pytest.mark.parametrize(
    "commands, expected",
    [
        ("ALL", (True, False)),
        ("(ALL : ALL) ALL", (True, False)),
        ("(root) NOPASSWD:ALL", (True, True)),
        ("(#0) ALL", (True, False)),
        ("(:wheel) ALL", (False, False)),
        ("(appuser) ALL, (root) /bin/ls", (False, False)),
        ("/bin/ls, (root) ALL", (True, False)),
        ("NOPASSWD: SETENV: /bin/ls", (False, True)),
        ("ALL, !/bin/su", (True, False)),
    ],
)
def test_sudoers_rights(commands, expected):
    assert agent.parse_sudoers(["alice ALL = " + commands]) == [("alice", *expected)]


def test_sudoers_runas_and_command_aliases():
    statements = [
        "Runas_Alias APP = appuser, root",
        "Cmnd_Alias EVERYTHING = ALL",
        "alice ALL = (APP) EVERYTHING",
    ]
    assert agent.parse_sudoers(statements) == [("alice", True, False)]


def test_group_members_include_primary_group_and_unknown_names():
    assert agent.group_members(FakeAccounts(), "sudo") == (
        27,
        [
            ("uid:1000", "alice", "User", "Local", ""),
            ("uid:20001", "carol", "User", "Directory", ""),
            ("name:ghost", "ghost", "User", "Unknown", ""),
            ("uid:1002", "dave", "User", "Local", ""),
        ],
    )


def test_group_members_of_missing_group():
    assert agent.group_members(FakeAccounts(), "wheel") is None


def test_uid0_accounts_have_distinct_idents():
    assert agent.uid0_accounts(FakeAccounts()) == [
        ("uid:0", "root", "User", "Local", ""),
        ("uid:0/toor", "toor", "User", "Local", ""),
    ]


def test_section_lines():
    lines = agent.section_lines(
        ["sudo", "wheel", "@sudoers", "@uid0"],
        FakeAccounts(),
        read=lambda path: "%sudo ALL=(ALL) ALL\n",
        list_dir=_list_dir,
        hostname="srv-app01",
    )
    assert lines == [
        "<<<local_group_members:sep(124)>>>",
        "computer|srv-app01",
        "group|1|gid:27|sudo|ok|nss|",
        "member|1|uid:1000|alice|User|Local",
        "member|1|uid:20001|carol|User|Directory",
        "member|1|name:ghost|ghost|User|Unknown",
        "member|1|uid:1002|dave|User|Local",
        "group|2||wheel|missing||",
        "group|3||sudoers|ok|sudoers|",
        "member|3|gid:27|%sudo|Group|Local|ALL",
        "group|4||UID 0|ok|nss|",
        "member|4|uid:0|root|User|Local",
        "member|4|uid:0/toor|toor|User|Local",
    ]


def test_section_without_sudoers_file_and_with_unreadable_one():
    def denied(_path):
        raise IOError(errno.EACCES, "Permission denied")

    missing = agent.section_lines(["@sudoers"], FakeAccounts(), read=_read_nothing)
    assert missing[2] == "group|1||sudoers|missing||No such file or directory"
    unreadable = agent.section_lines(["@sudoers"], FakeAccounts(), read=denied)
    assert unreadable[2] == "group|1||sudoers|error||Permission denied"


def _read_nothing(_path):
    raise IOError(errno.ENOENT, "No such file or directory")


def test_read_config(tmp_path):
    config = tmp_path / "local_group_members.cfg"
    assert agent.read_config(str(config)) == agent.DEFAULT_GROUPS
    config.write_text("# header\ngroup = sudo\ngroup=@uid0\ngroup=sudo\n")
    assert agent.read_config(str(config)) == ["sudo", "@uid0"]
    config.write_text("# nothing configured\n")
    assert agent.read_config(str(config)) == agent.DEFAULT_GROUPS
