#!/usr/bin/env python3
from pathlib import Path

import pytest
from cmk.agent_based.v2 import Result, Service, State, TableRow
from cmk.bakery.v2_unstable import OS, Plugin, PluginConfig
from cmk_addons.plugins.local_administrators.agent_based.local_administrators import (
    check_local_administrators,
    discover_local_administrators,
    inventory_local_administrators,
    parse_local_administrators,
)
from cmk_addons.plugins.local_administrators.bakery.local_administrators import (
    Config,
    get_local_administrators_files,
)

MACHINE = "S-1-5-21-1111111111-2222222222-3333333333"
DOMAIN = "S-1-5-21-4444444444-5555555555-6666666666"

AGENT_OUTPUT = f"""\
group|1|S-1-5-32-544|Administratoren|ok|Get-LocalGroupMember|
member|1|{MACHINE}-500|WINSRV\\Administrator|Benutzer|Local
member|1|{MACHINE}-1001|WINSRV\\backup|Benutzer|Local
member|1|{DOMAIN}-512|CONTOSO\\Domänen-Admins|Gruppe|ActiveDirectory
member|1|{DOMAIN}-1105|CONTOSO\\svc_deploy|Benutzer|ActiveDirectory
group|2|S-1-5-32-555|Remote Desktop Users|ok|ADSI|
member|2|{DOMAIN}-1200|CONTOSO\\helpdesk|Group|ActiveDirectory
group|3|S-1-5-32-578|S-1-5-32-578|missing||
group|4|{MACHINE}-1010|App Admins|error||Access denied
"""

DEFAULT_PARAMS = {"query_error_state": 3}


@pytest.fixture(name="section")
def _section():
    return parse_local_administrators([line.split("|") for line in AGENT_OUTPUT.splitlines()])


def _check(section, params, item="Administrators"):
    return list(check_local_administrators(item, {**DEFAULT_PARAMS, **params}, section))


def _state_of(results, member):
    (result,) = [r for r in results if isinstance(r, Result) and r.details.startswith(member)]
    return result.state


def _worst(results):
    return State.worst(*(r.state for r in results if isinstance(r, Result)))


def test_parse_uses_english_names_for_builtin_groups(section):
    assert set(section) == {
        "Administrators",
        "Remote Desktop Users",
        "Hyper-V Administrators",
        "App Admins",
    }
    assert section["Administrators"].name == "Administratoren"


def test_parse_normalizes_german_object_classes(section):
    assert [m.object_class for m in section["Administrators"].members] == [
        "User",
        "User",
        "Group",
        "User",
    ]


def test_discovery_skips_missing_groups_and_stores_members(section):
    services = list(discover_local_administrators(section))
    assert [s.item for s in services] == ["Administrators", "Remote Desktop Users", "App Admins"]
    assert services[1] == Service(
        item="Remote Desktop Users",
        parameters={"discovered_members": {f"{DOMAIN}-1200": "CONTOSO\\helpdesk"}},
    )


def test_check_without_rule_is_ok_and_lists_members(section):
    results = _check(section, {})
    assert _worst(results) is State.OK
    assert results[0].summary == "Members: 4 (3 users, 1 groups)"
    assert sum(r.details.startswith(("WINSRV", "CONTOSO")) for r in results) == 4


def test_check_unknown_item_yields_nothing(section):
    assert _check(section, {}, item="Guests") == []


def test_local_users_ignore_builtin_administrator(section):
    results = _check(section, {"local_users": {"state": 1, "ignore_builtin_administrator": True}})
    assert _state_of(results, "WINSRV\\Administrator") is State.OK
    assert _state_of(results, "WINSRV\\backup") is State.WARN
    assert _state_of(results, "CONTOSO\\svc_deploy") is State.OK


def test_local_users_including_builtin_administrator(section):
    results = _check(section, {"local_users": {"state": 2, "ignore_builtin_administrator": False}})
    assert _state_of(results, "WINSRV\\Administrator") is State.CRIT
    assert _state_of(results, "WINSRV\\backup") is State.CRIT


def test_forbidden_matches_users_and_groups_case_insensitively(section):
    results = _check(
        section,
        {
            "forbidden": [
                {"pattern": r"contoso\\SVC_.*", "state": 2},
                {"pattern": r"CONTOSO\\Domänen-Admins", "state": 1},
            ]
        },
    )
    assert _state_of(results, "CONTOSO\\svc_deploy") is State.CRIT
    assert _state_of(results, "CONTOSO\\Domänen-Admins") is State.WARN
    assert _state_of(results, "WINSRV\\backup") is State.OK


def test_forbidden_requires_full_match(section):
    results = _check(section, {"forbidden": [{"pattern": r"CONTOSO\\svc", "state": 2}]})
    assert _worst(results) is State.OK


def test_forbidden_matches_sid(section):
    results = _check(section, {"forbidden": [{"pattern": f"{DOMAIN}-1105", "state": 2}]})
    assert _state_of(results, "CONTOSO\\svc_deploy") is State.CRIT


def test_allow_list_overrides_all_other_settings(section):
    results = _check(
        section,
        {
            "local_users": {"state": 2, "ignore_builtin_administrator": False},
            "forbidden": [{"pattern": r".*\\backup", "state": 2}],
            "allowed": [r"WINSRV\\.*"],
            "not_allowed_state": 1,
            "membership_changes": {"added": 2, "removed": 2},
            "discovered_members": {},
        },
    )
    assert _state_of(results, "WINSRV\\backup") is State.OK
    assert _state_of(results, "WINSRV\\Administrator") is State.OK
    assert _state_of(results, "CONTOSO\\svc_deploy") is State.CRIT


def test_strict_allow_list(section):
    results = _check(section, {"allowed": [r"WINSRV\\Administrator"], "not_allowed_state": 2})
    assert _state_of(results, "WINSRV\\Administrator") is State.OK
    assert _state_of(results, "WINSRV\\backup") is State.CRIT
    assert _state_of(results, "CONTOSO\\Domänen-Admins") is State.CRIT


def test_additionally_allowed_members_extend_the_allow_list(section):
    results = _check(
        section,
        {
            "allowed": [r"WINSRV\\Administrator"],
            "allowed_additional": [r"CONTOSO\\svc_deploy"],
            "not_allowed_state": 2,
        },
    )
    assert _state_of(results, "WINSRV\\Administrator") is State.OK
    assert _state_of(results, "CONTOSO\\svc_deploy") is State.OK
    assert _state_of(results, "WINSRV\\backup") is State.CRIT


def test_additionally_allowed_members_without_allow_list(section):
    results = _check(
        section,
        {
            "local_users": {"state": 2, "ignore_builtin_administrator": True},
            "allowed_additional": [r"WINSRV\\backup"],
        },
    )
    assert _worst(results) is State.OK


def test_membership_changes(section):
    results = _check(
        section,
        {
            "membership_changes": {"added": 1, "removed": 2},
            "discovered_members": {
                f"{MACHINE}-500": "WINSRV\\Administrator",
                f"{MACHINE}-1001": "WINSRV\\backup",
                f"{DOMAIN}-512": "CONTOSO\\Domänen-Admins",
                f"{DOMAIN}-777": "CONTOSO\\gone",
            },
        },
    )
    assert _state_of(results, "CONTOSO\\svc_deploy") is State.WARN
    assert _state_of(results, "WINSRV\\backup") is State.OK
    assert _state_of(results, "CONTOSO\\gone") is State.CRIT


def test_membership_changes_are_off_without_the_rule(section):
    results = _check(section, {"discovered_members": {}})
    assert _worst(results) is State.OK


def test_membership_changes_need_discovered_members(section):
    # Enforced services have no discovered members: nothing to compare against.
    results = _check(section, {"membership_changes": {"added": 2, "removed": 2}})
    assert _worst(results) is State.OK


@pytest.mark.parametrize(
    "params, state",
    [
        ({}, State.UNKNOWN),
        ({"query_error_state": 2}, State.CRIT),
        ({"query_error_state": 0}, State.OK),
    ],
)
def test_query_error_state(section, params, state):
    (result,) = _check(section, params, item="App Admins")
    assert result.state is state
    assert result.summary == "Members could not be queried: Access denied"


def test_missing_group(section):
    (result,) = _check(section, {}, item="Hyper-V Administrators")
    assert result.state is State.UNKNOWN
    assert result.summary == "Group does not exist"


def test_invalid_regex_is_reported(section):
    results = _check(section, {"allowed": ["("]})
    assert _worst(results) is State.UNKNOWN


def test_inventory(section):
    rows = list(inventory_local_administrators(section))
    assert len(rows) == 5
    assert rows[0] == TableRow(
        path=["software", "os", "local_group_members"],
        key_columns={"group": "Administrators", "sid": f"{MACHINE}-500"},
        inventory_columns={
            "member": "WINSRV\\Administrator",
            "type": "User",
            "source": "Local",
            "group_local_name": "Administratoren",
        },
    )


def test_bakery_deploys_plugin_and_config():
    conf = Config.model_validate(
        {
            "deployment": (
                "deploy",
                {
                    "builtin_groups": ["administrators", "remote_desktop_users"],
                    "custom_groups": ["App Admins"],
                    "interval": 3600.0,
                },
            )
        }
    )
    assert list(get_local_administrators_files(conf)) == [
        Plugin(base_os=OS.WINDOWS, source=Path("local_administrators.ps1"), interval=3600),
        PluginConfig(
            base_os=OS.WINDOWS,
            lines=["group=S-1-5-32-544", "group=S-1-5-32-555", "group=App Admins"],
            target=Path("local_administrators.cfg"),
            include_header=True,
        ),
    ]


def test_bakery_do_not_deploy():
    conf = Config.model_validate({"deployment": ("do_not_deploy", None)})
    assert list(get_local_administrators_files(conf)) == []
