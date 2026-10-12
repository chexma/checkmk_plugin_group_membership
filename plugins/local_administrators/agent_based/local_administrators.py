#!/usr/bin/env python3
"""Members of local groups on Windows hosts (agent plugin local_administrators.ps1).

Section format, separated by pipes (a character Windows forbids in account names):

    <<<local_administrators:sep(124)>>>
    group|<key>|<group SID>|<group name>|<status>|<method>|<message>
    member|<key>|<member SID>|<member name>|<object class>|<principal source>

<key> ties the members to their group. <status> is "ok", "missing" (the group
does not exist) or "error" (the members could not be queried).
"""

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    InventoryPlugin,
    InventoryResult,
    Result,
    Service,
    State,
    StringTable,
    TableRow,
)
from cmk_addons.plugins.local_administrators.lib import GROUP_NAME_BY_SID

# Get-LocalGroupMember localizes the object class.
_OBJECT_CLASSES = {
    "user": "User",
    "benutzer": "User",
    "group": "Group",
    "gruppe": "Group",
}


@dataclass(frozen=True)
class Member:
    sid: str
    name: str
    object_class: str
    source: str

    @property
    def is_local_user(self) -> bool:
        return self.object_class == "User" and self.source == "Local"

    @property
    def is_builtin_administrator(self) -> bool:
        return (
            self.source == "Local"
            and self.sid.startswith("S-1-5-21-")
            and self.sid.endswith("-500")
        )


@dataclass
class Group:
    sid: str
    name: str
    status: str
    method: str = ""
    message: str = ""
    members: list[Member] = field(default_factory=list)


Section = Mapping[str, Group]


def _item_name(sid: str, name: str) -> str:
    return GROUP_NAME_BY_SID.get(sid.upper()) or name or sid


def parse_local_administrators(string_table: StringTable) -> Section:
    groups: dict[str, Group] = {}
    for line in string_table:
        if len(line) < 2:
            continue
        kind, key, *rest = (word.strip() for word in line)
        rest += [""] * (5 - len(rest))
        if kind == "group":
            sid, name, status, method, message = rest[:5]
            groups[key] = Group(sid=sid, name=name, status=status, method=method, message=message)
        elif kind == "member" and key in groups:
            sid, name, object_class, source = rest[:4]
            groups[key].members.append(
                Member(
                    sid=sid,
                    name=name or sid,
                    object_class=_OBJECT_CLASSES.get(object_class.lower(), object_class),
                    source=source or "Unknown",
                )
            )
    return {_item_name(group.sid, group.name): group for group in groups.values()}


agent_section_local_administrators = AgentSection(
    name="local_administrators",
    parse_function=parse_local_administrators,
)


def discover_local_administrators(section: Section) -> DiscoveryResult:
    for item, group in section.items():
        # A configured group that does not exist on this host gets no service.
        if group.status == "missing":
            continue
        yield Service(
            item=item,
            parameters={
                "discovered_members": {member.sid: member.name for member in group.members}
            },
        )


def _matches(patterns: Iterable[str], member: Member) -> bool:
    return any(_pattern_matches(pattern, member) for pattern in patterns)


def _pattern_matches(pattern: str, member: Member) -> bool:
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return False
    return bool(regex.fullmatch(member.name) or regex.fullmatch(member.sid))


def _allowed_patterns(params: Mapping[str, Any]) -> Sequence[str]:
    # "allowed_additional" lets a host specific rule extend the general allow list:
    # rules are merged per key, so a second "allowed" would replace the first one.
    return [*params.get("allowed", []), *params.get("allowed_additional", [])]


def _invalid_patterns(params: Mapping[str, Any]) -> Sequence[str]:
    patterns = [
        *_allowed_patterns(params),
        *(rule["pattern"] for rule in params.get("forbidden", [])),
    ]
    invalid = []
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error:
            invalid.append(pattern)
    return invalid


def _evaluate_member(
    member: Member, params: Mapping[str, Any], group_was_discovered: bool
) -> tuple[State, Sequence[str]]:
    """Return the state of one member and the reasons for it."""
    if _matches(_allowed_patterns(params), member):
        return State.OK, ["allowed"]

    findings: list[tuple[State, str]] = []

    local_users = params.get("local_users")
    if local_users and member.is_local_user:
        if not (
            local_users.get("ignore_builtin_administrator", True)
            and member.is_builtin_administrator
        ):
            findings.append((State(local_users["state"]), "local user"))

    for rule in params.get("forbidden", []):
        if _pattern_matches(rule["pattern"], member):
            findings.append((State(rule["state"]), "unwanted member"))
            break

    if (state := params.get("not_allowed_state")) is not None:
        findings.append((State(state), "not on the allow list"))

    changes = params.get("membership_changes")
    if changes and group_was_discovered and member.sid not in params["discovered_members"]:
        findings.append((State(changes["added"]), "added since service discovery"))

    if not findings:
        return State.OK, []
    return State.worst(*(state for state, _reason in findings)), [
        reason for _state, reason in findings
    ]


def _describe(member: Member) -> str:
    return f"{member.name} ({member.object_class}, {member.source})"


def check_local_administrators(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (group := section.get(item)) is None:
        return

    if group.status != "ok":
        problem = (
            "Group does not exist" if group.status == "missing" else "Members could not be queried"
        )
        yield Result(
            state=State(params.get("query_error_state", State.UNKNOWN.value)),
            summary=f"{problem}: {group.message}" if group.message else problem,
        )
        return

    members = sorted(group.members, key=lambda member: member.name.lower())
    users = sum(member.object_class == "User" for member in members)
    groups = sum(member.object_class == "Group" for member in members)
    yield Result(
        state=State.OK,
        summary=f"Members: {len(members)} ({users} users, {groups} groups)",
    )
    yield Result(
        state=State.OK,
        notice=f"Group: {group.name} ({group.sid}), queried with {group.method or 'unknown'}",
    )

    if invalid := _invalid_patterns(params):
        yield Result(
            state=State.UNKNOWN,
            summary="Invalid regular expression in rule: " + ", ".join(invalid),
        )

    group_was_discovered = "discovered_members" in params
    for member in members:
        state, reasons = _evaluate_member(member, params, group_was_discovered)
        text = _describe(member) + (": " + ", ".join(reasons) if reasons else "")
        yield Result(state=state, notice=text)

    changes = params.get("membership_changes")
    if changes and group_was_discovered:
        present = {member.sid for member in members}
        for sid, name in sorted(params["discovered_members"].items(), key=lambda kv: kv[1].lower()):
            if sid not in present:
                yield Result(
                    state=State(changes["removed"]),
                    notice=f"{name}: removed since service discovery",
                )


check_plugin_local_administrators = CheckPlugin(
    name="local_administrators",
    service_name="Local group %s",
    discovery_function=discover_local_administrators,
    check_function=check_local_administrators,
    check_default_parameters={"query_error_state": State.UNKNOWN.value},
    check_ruleset_name="local_administrators",
)


def inventory_local_administrators(section: Section) -> InventoryResult:
    for item, group in section.items():
        for member in group.members:
            yield TableRow(
                path=["software", "os", "local_group_members"],
                key_columns={"group": item, "sid": member.sid},
                inventory_columns={
                    "member": member.name,
                    "type": member.object_class,
                    "source": member.source,
                    "group_local_name": group.name,
                },
            )


inventory_plugin_local_administrators = InventoryPlugin(
    name="local_administrators",
    inventory_function=inventory_local_administrators,
)
