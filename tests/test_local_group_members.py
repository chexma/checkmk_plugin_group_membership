#!/usr/bin/env python3
from pathlib import Path

import pytest
from cmk.agent_based.v2 import Metric, Result, Service, State, TableRow
from cmk.bakery.v2_unstable import OS, Plugin, PluginConfig
from cmk_addons.plugins.local_group_members.agent_based.local_group_members import (
    check_local_group_members,
    discover_local_group_members,
    inventory_local_group_members,
    parse_local_group_members,
)
from cmk_addons.plugins.local_group_members.bakery.local_group_members import (
    Config,
    get_local_group_members_files,
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
    return parse_local_group_members([line.split("|") for line in AGENT_OUTPUT.splitlines()])


def _check(section, params, item="Administrators"):
    return list(check_local_group_members(item, {**DEFAULT_PARAMS, **params}, section))


def _state_of(results, member):
    (result,) = [r for r in results if isinstance(r, Result) and r.details.startswith(member)]
    return result.state


def _worst(results):
    return State.worst(*(r.state for r in results if isinstance(r, Result)))


def test_parse_uses_english_names_for_builtin_groups(section):
    assert set(section.groups) == {
        "Administrators",
        "Remote Desktop Users",
        "Hyper-V Administrators",
        "App Admins",
    }
    assert section.groups["Administrators"].name == "Administratoren"


def test_parse_normalizes_german_object_classes(section):
    assert [m.object_class for m in section.groups["Administrators"].members] == [
        "User",
        "User",
        "Group",
        "User",
    ]


def test_discovery_skips_missing_groups_and_stores_members(section):
    services = list(discover_local_group_members(section))
    assert [s.item for s in services] == ["Administrators", "Remote Desktop Users", "App Admins"]
    assert services[1] == Service(
        item="Remote Desktop Users",
        parameters={"discovered_members": {f"{DOMAIN}-1200": "CONTOSO\\helpdesk"}},
    )


def test_check_without_rule_is_ok_and_lists_members(section):
    results = _check(section, {})
    assert _worst(results) is State.OK
    assert results[0].summary == "Members: 4 (3 users, 1 groups)"
    assert (
        sum(r.details.startswith(("WINSRV", "CONTOSO")) for r in results if isinstance(r, Result))
        == 4
    )


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


def _missing(results):
    return [
        (r.state, r.details)
        for r in results
        if isinstance(r, Result) and r.details.startswith("Required member missing")
    ]


def test_required_members_present_and_missing(section):
    results = _check(
        section,
        {
            "required": [
                {"pattern": r"contoso\\domänen-admins", "state": 2},
                {"pattern": f"{DOMAIN}-1105", "state": 2},
                {"pattern": r"CONTOSO\\Server Admins", "state": 2},
                {"pattern": r"CONTOSO\\monitoring", "state": 1},
            ]
        },
    )
    assert _missing(results) == [
        (State.CRIT, r"Required member missing: CONTOSO\\Server Admins"),
        (State.WARN, r"Required member missing: CONTOSO\\monitoring"),
    ]
    assert _worst(results) == State.CRIT


def test_required_members_are_exempt_like_allowed_ones(section):
    results = _check(
        section,
        {
            "required": [{"pattern": r"WINSRV\\backup", "state": 2}],
            "local_users": {"state": 2, "ignore_builtin_administrator": True},
            "forbidden": [{"pattern": r"WINSRV\\backup", "state": 2}],
            "not_allowed_state": 1,
        },
    )
    assert _missing(results) == []
    assert _state_of(results, "WINSRV\\backup") == State.OK
    assert _state_of(results, "CONTOSO\\svc_deploy") == State.WARN


def test_required_member_with_hostname_placeholder():
    section = _parse(REAL_OUTPUT_GERMAN)
    present = _check(
        section, {"required": [{"pattern": r"CONTOSO\\srvadmins_$HOSTNAME$", "state": 2}]}
    )
    assert _missing(present) == []
    absent = _check(section, {"required": [{"pattern": r"CONTOSO\\other_$HOSTNAME$", "state": 2}]})
    assert _missing(absent) == [(State.CRIT, r"Required member missing: CONTOSO\\other_SRV-APP01")]


def test_required_invalid_regex_is_reported(section):
    results = _check(section, {"required": [{"pattern": "CONTOSO(", "state": 2}]})
    assert _worst(results) == State.UNKNOWN
    assert _missing(results) == []


def test_metrics_count_users_and_groups(section):
    assert [r for r in _check(section, {}) if isinstance(r, Metric)] == [
        Metric("local_group_member_users", 3),
        Metric("local_group_member_groups", 1),
    ]


def test_no_metrics_if_the_group_cannot_be_queried(section):
    assert not [r for r in _check(section, {}, item="App Admins") if isinstance(r, Metric)]


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
    rows = list(inventory_local_group_members(section))
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
    assert list(get_local_group_members_files(conf)) == [
        Plugin(base_os=OS.WINDOWS, source=Path("local_group_members.ps1"), interval=3600),
        PluginConfig(
            base_os=OS.WINDOWS,
            lines=["group=S-1-5-32-544", "group=S-1-5-32-555", "group=App Admins"],
            target=Path("local_group_members.cfg"),
            include_header=True,
        ),
    ]


def test_bakery_do_not_deploy():
    conf = Config.model_validate({"deployment": ("do_not_deploy", None)})
    assert list(get_local_group_members_files(conf)) == []


# Modelled on the output of plugin version 1.0.0 on a German Windows server
# (domain member); all names and SIDs are fictional. No "computer" line yet.
REAL_OUTPUT_GERMAN = """\
group|1|S-1-5-32-544|Administratoren|ok|Get-LocalGroupMember|
member|1|S-1-5-21-2000000001-2000000002-2000000003-512|FABRIKAM\\Domänen-Admins|Gruppe|ActiveDirectory
member|1|S-1-5-21-3000000001-3000000002-3000000003-6871|CONTOSO\\srvadmins_SRV-APP01|Gruppe|ActiveDirectory
member|1|S-1-5-21-3000000001-3000000002-3000000003-512|CONTOSO\\Domänen-Admins|Gruppe|ActiveDirectory
member|1|S-1-5-21-3000000001-3000000002-3000000003-3189|CONTOSO\\svc_backup|Benutzer|ActiveDirectory
member|1|S-1-5-21-4000000001-4000000002-4000000003-500|SRV-APP01\\Administrator|Benutzer|Local
"""


def _parse(output):
    return parse_local_group_members([line.split("|") for line in output.splitlines()])


@pytest.fixture(name="real_section")
def _real_section():
    return _parse(REAL_OUTPUT_GERMAN)


def test_real_output_german(real_section):
    assert list(real_section.groups) == ["Administrators"]
    results = _check(real_section, {})
    assert _worst(results) is State.OK
    assert results[0].summary == "Members: 5 (2 users, 3 groups)"


def test_computer_name_from_local_member_without_computer_line(real_section):
    assert real_section.computer == "SRV-APP01"


def test_computer_line_wins():
    section = _parse("computer|SRV01\n" + REAL_OUTPUT_GERMAN)
    assert section.computer == "SRV01"
    assert list(section.groups) == ["Administrators"]


def test_hostname_placeholder_in_allow_list(real_section):
    results = _check(
        real_section,
        {
            "allowed": [r"CONTOSO\\srvadmins_$HOSTNAME$", r"$HOSTNAME$\\Administrator"],
            "not_allowed_state": 2,
        },
    )
    assert _state_of(results, "CONTOSO\\srvadmins_SRV-APP01") is State.OK
    assert _state_of(results, "SRV-APP01\\Administrator") is State.OK
    assert _state_of(results, "CONTOSO\\svc_backup") is State.CRIT


def test_hostname_placeholder_does_not_allow_other_hosts_group():
    section = _parse("computer|SRV-APP02\n" + REAL_OUTPUT_GERMAN)
    results = _check(
        section, {"allowed": [r"CONTOSO\\srvadmins_$HOSTNAME$"], "not_allowed_state": 2}
    )
    assert _state_of(results, "CONTOSO\\srvadmins_SRV-APP01") is State.CRIT


def test_hostname_placeholder_in_additional_and_unwanted(real_section):
    results = _check(
        real_section,
        {
            "allowed_additional": [r"contoso\\SRVADMINS_$HOSTNAME$"],
            "forbidden": [{"pattern": r"$HOSTNAME$\\.*", "state": 1}],
        },
    )
    assert _state_of(results, "CONTOSO\\srvadmins_SRV-APP01") is State.OK
    assert _state_of(results, "SRV-APP01\\Administrator") is State.WARN
    assert _state_of(results, "CONTOSO\\svc_backup") is State.OK


def test_hostname_placeholder_is_escaped():
    # A dot in the computer name must not act as a wildcard.
    section = _parse("computer|A.B\n" + REAL_OUTPUT_GERMAN.replace("SRV-APP01", "AXB"))
    results = _check(
        section, {"allowed": [r"CONTOSO\\srvadmins_$HOSTNAME$"], "not_allowed_state": 1}
    )
    assert _state_of(results, "CONTOSO\\srvadmins_AXB") is State.WARN


def test_builtin_administrator_is_recognized_in_real_output(real_section):
    results = _check(
        real_section, {"local_users": {"state": 2, "ignore_builtin_administrator": True}}
    )
    assert _worst(results) is State.OK


# Output of the Linux agent plugin local_group_members.py.
LINUX_OUTPUT = """\
computer|srv-app01
group|1|gid:27|sudo|ok|nss|
member|1|uid:1000|alice|User|Local
member|1|uid:20001|carol|User|Directory
member|1|name:ghost|ghost|User|Unknown
group|2||wheel|missing||
group|3||sudoers|ok|sudoers|
member|3|uid:0|root|User|Local|ALL
member|3|gid:20500|%adm_srv-app01|Group|Directory|ALL, NOPASSWD
member|3|uid:1000|alice|User|Local|restricted
group|4||UID 0|ok|nss|
member|4|uid:0|root|User|Local
member|4|uid:0/toor|toor|User|Local
"""


@pytest.fixture(name="linux_section")
def _linux_section():
    return _parse(LINUX_OUTPUT)


def test_linux_services(linux_section):
    assert linux_section.computer == "srv-app01"
    services = list(discover_local_group_members(linux_section))
    assert [service.item for service in services] == ["sudo", "sudoers", "UID 0"]
    assert services[0].parameters["discovered_members"] == {
        "uid:1000": "alice",
        "uid:20001": "carol",
        "name:ghost": "ghost",
    }
    # Two accounts that share UID 0 are still two members.
    assert len(services[2].parameters["discovered_members"]) == 2


def test_linux_sudoers_details_and_metrics(linux_section):
    results = _check(linux_section, {}, item="sudoers")
    details = [r.details for r in results if isinstance(r, Result)]
    assert "Group: sudoers" in details
    assert "%adm_srv-app01 (Group, Directory, ALL, NOPASSWD)" in details
    assert "alice (User, Local, restricted)" in details
    assert Metric("local_group_member_users", 2) in results
    assert Metric("local_group_member_groups", 1) in results


def test_linux_root_counts_as_builtin_administrator_but_not_its_twins(linux_section):
    params = {"local_users": {"state": 2, "ignore_builtin_administrator": True}}
    results = _check(linux_section, params, item="UID 0")
    assert _state_of(results, "root") is State.OK
    assert _state_of(results, "toor") is State.CRIT


def test_linux_patterns_and_hostname_placeholder(linux_section):
    params = {
        "allowed": ["root", "%adm_$HOSTNAME$"],
        "not_allowed_state": 1,
        "required": [{"pattern": "%adm_$HOSTNAME$", "state": 2}],
    }
    results = _check(linux_section, params, item="sudoers")
    assert _state_of(results, "%adm_srv-app01") is State.OK
    assert _state_of(results, "alice") is State.WARN
    assert _missing(results) == []
    assert (
        _state_of(
            _check(
                linux_section, {"forbidden": [{"pattern": "uid:20001", "state": 2}]}, item="sudo"
            ),
            "carol",
        )
        is State.CRIT
    )


def test_linux_inventory_has_details_only_for_sudoers(linux_section):
    rows = {
        (row.key_columns["group"], row.key_columns["sid"]): row.inventory_columns
        for row in inventory_local_group_members(linux_section)
    }
    assert rows[("sudoers", "uid:1000")]["details"] == "restricted"
    assert "details" not in rows[("sudo", "uid:1000")]


def test_bakery_deploys_linux_plugin_only_if_configured():
    conf = Config.model_validate(
        {
            "deployment": (
                "deploy",
                {
                    "builtin_groups": ["administrators"],
                    "linux": {
                        "groups": ["sudo"],
                        "custom_groups": [" wheel "],
                        "sudoers": True,
                        "uid0": False,
                    },
                    "interval": 600.0,
                },
            )
        }
    )
    files = list(get_local_group_members_files(conf))
    assert files[2:] == [
        Plugin(base_os=OS.LINUX, source=Path("local_group_members.py"), interval=600),
        PluginConfig(
            base_os=OS.LINUX,
            lines=["group=sudo", "group=wheel", "group=@sudoers"],
            target=Path("local_group_members.cfg"),
            include_header=True,
        ),
    ]
    assert [type(f) for f in files[:2]] == [Plugin, PluginConfig]


def test_rule_forms_can_be_built():
    # cmk-validate-plugins does not call the form functions of agent rules.
    from cmk_addons.plugins.local_group_members.rulesets import agent_config, local_group_members

    assert agent_config.rule_spec_local_group_members_bakery.parameter_form().elements
    assert local_group_members.rule_spec_local_group_members.parameter_form().elements


def test_inventory_ui_knows_all_inventory_columns(linux_section, section):
    from cmk_addons.plugins.local_group_members.inventory_ui.local_group_members import (
        node_software_os_local_group_members as node,
    )

    rows = [*inventory_local_group_members(linux_section), *inventory_local_group_members(section)]
    assert list(node.path) == rows[0].path
    for row in rows:
        assert {*row.key_columns, *row.inventory_columns} <= set(node.table.columns)
