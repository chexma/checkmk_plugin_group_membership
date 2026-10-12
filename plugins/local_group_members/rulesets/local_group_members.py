#!/usr/bin/env python3
"""Check parameters for the services "Group Membership <name>"."""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    List,
    MatchingScope,
    RegularExpression,
    ServiceState,
    String,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic

# Appended to the help of every member list: the format is the same everywhere.
_PATTERN_FORMAT = (
    "<br><br><b>Format:</b> each entry is a regular expression that has to match the "
    "complete name of a member as shown in the service details, i.e. "
    "<tt>DOMAIN\\name</tt> or <tt>COMPUTER\\name</tt>, or the SID of the member. An "
    "entry can be a single user or a group; both are written the same way. Upper and "
    "lower case are not distinguished.<br><br>"
    "<b>The backslash between domain and name has to be written twice (\\\\)</b>, "
    "because a single backslash has a special meaning in regular expressions.<br><br>"
    "Examples:<br>"
    "<tt>CONTOSO\\\\jdoe</tt> - the domain user jdoe<br>"
    "<tt>CONTOSO\\\\Domain Admins</tt> - the domain group Domain Admins<br>"
    "<tt>SRV01\\\\Administrator</tt> - a local user of the computer SRV01<br>"
    "<tt>.*\\\\Administrator</tt> - the user Administrator of any computer or domain<br>"
    "<tt>CONTOSO\\\\svc_.*</tt> - all accounts of the domain whose name starts with svc_<br>"
    "<tt>S-1-5-21-.*-500</tt> - the built-in Administrator account, by its SID<br><br>"
    "<b>Placeholder:</b> <tt>$HOSTNAME$</tt> is replaced by the Windows computer name "
    "of the host, so one rule fits accounts that carry the name of their server:<br>"
    "<tt>CONTOSO\\\\srvadmins_$HOSTNAME$</tt> - on SRV01 the domain group srvadmins_SRV01<br>"
    "<tt>$HOSTNAME$\\\\adm_$HOSTNAME$</tt> - on SRV01 the local user adm_SRV01<br>"
    "<tt>$HOSTNAME$\\\\.*</tt> - all local accounts of the host<br><br>"
    "<b>Linux:</b> members are named as on the host, without a domain. Groups in the "
    "service <tt>sudoers</tt> start with a percent sign; instead of a SID there is "
    "<tt>uid:&lt;number&gt;</tt> or <tt>gid:&lt;number&gt;</tt>. <tt>$HOSTNAME$</tt> is "
    "the short host name.<br>"
    "<tt>jdoe</tt> - the user jdoe<br>"
    "<tt>%linux-admins</tt> - the group linux-admins in the sudoers files<br>"
    "<tt>%adm_$HOSTNAME$</tt> - on srv01 the group adm_srv01<br>"
    "<tt>uid:0</tt> - the account that owns UID 0, usually root"
)

_PATTERN_HELP = Help(
    "Complete name of a user or group, e.g. <tt>CONTOSO\\\\Domain Admins</tt>, or a SID. "
    "Write the backslash twice. On Linux e.g. <tt>jdoe</tt> or <tt>%linux-admins</tt>."
)


def _parameter_form() -> Dictionary:
    return Dictionary(
        elements={
            "local_users": DictElement(
                parameter_form=Dictionary(
                    title=Title("Local users as members"),
                    help_text=Help(
                        "Set a state for local user accounts that are members of the group. "
                        "Domain accounts and groups are not affected. On Linux a user is "
                        "local if it is listed in <tt>/etc/passwd</tt>."
                    ),
                    elements={
                        "state": DictElement(
                            parameter_form=ServiceState(
                                title=Title("State if a local user is a member"),
                                prefill=DefaultValue(ServiceState.WARN),
                            ),
                            required=True,
                        ),
                        "ignore_builtin_administrator": DictElement(
                            parameter_form=BooleanChoice(
                                label=Label(
                                    "Ignore the built-in Administrator account (RID 500) "
                                    "and, on Linux, root"
                                ),
                                prefill=DefaultValue(True),
                            ),
                            required=True,
                        ),
                    },
                ),
            ),
            "forbidden": DictElement(
                parameter_form=List(
                    title=Title("Unwanted members"),
                    help_text=Help(
                        "Users or groups that must not be members of the group. "
                        "The first matching entry determines the state." + _PATTERN_FORMAT
                    ),
                    add_element_label=Label("Add unwanted member"),
                    element_template=Dictionary(
                        elements={
                            "pattern": DictElement(
                                parameter_form=RegularExpression(
                                    title=Title("User or group"),
                                    help_text=_PATTERN_HELP,
                                    predefined_help_text=MatchingScope.FULL,
                                ),
                                required=True,
                            ),
                            "state": DictElement(
                                parameter_form=ServiceState(
                                    title=Title("State if found"),
                                    prefill=DefaultValue(ServiceState.CRIT),
                                ),
                                required=True,
                            ),
                        },
                    ),
                ),
            ),
            "required": DictElement(
                parameter_form=List(
                    title=Title("Required members"),
                    help_text=Help(
                        "Users or groups that have to be members of the group. For every "
                        "entry that matches no member, the service gets the state of that "
                        "entry. Required members are always OK, like the members on the "
                        "allow list." + _PATTERN_FORMAT
                    ),
                    add_element_label=Label("Add required member"),
                    element_template=Dictionary(
                        elements={
                            "pattern": DictElement(
                                parameter_form=RegularExpression(
                                    title=Title("User or group"),
                                    help_text=_PATTERN_HELP,
                                    predefined_help_text=MatchingScope.FULL,
                                ),
                                required=True,
                            ),
                            "state": DictElement(
                                parameter_form=ServiceState(
                                    title=Title("State if missing"),
                                    prefill=DefaultValue(ServiceState.CRIT),
                                ),
                                required=True,
                            ),
                        },
                    ),
                ),
            ),
            "allowed": DictElement(
                parameter_form=List(
                    title=Title("Allowed members (allow list)"),
                    help_text=Help(
                        "Users and groups that are allowed as members. Members matching "
                        "one of the entries are always OK. They are exempt from all other "
                        "settings of this rule." + _PATTERN_FORMAT
                    ),
                    add_element_label=Label("Add allowed member"),
                    element_template=RegularExpression(
                        label=Label("User or group"),
                        help_text=_PATTERN_HELP,
                        predefined_help_text=MatchingScope.FULL,
                    ),
                ),
            ),
            "allowed_additional": DictElement(
                parameter_form=List(
                    title=Title("Additionally allowed members"),
                    help_text=Help(
                        "Users and groups that are allowed in addition to the allow list. "
                        "Use this in a rule for specific hosts or groups: a more specific "
                        "rule replaces the allow list of a general rule, whereas this list "
                        "is added to it." + _PATTERN_FORMAT
                    ),
                    add_element_label=Label("Add allowed member"),
                    element_template=RegularExpression(
                        label=Label("User or group"),
                        help_text=_PATTERN_HELP,
                        predefined_help_text=MatchingScope.FULL,
                    ),
                ),
            ),
            "not_allowed_state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State for members that are not on the allow list"),
                    help_text=Help(
                        "Without this setting the allow list only exempts members from the "
                        "other settings. With it, every member that is not on the allow list "
                        "gets this state."
                    ),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "membership_changes": DictElement(
                parameter_form=Dictionary(
                    title=Title("Changes since the service discovery"),
                    help_text=Help(
                        "Compare the members with those found during the last service "
                        "discovery. Accept a change by updating the service parameters in "
                        "the service discovery of the host. Members on the allow list may "
                        "be added without notice."
                    ),
                    elements={
                        "added": DictElement(
                            parameter_form=ServiceState(
                                title=Title("State if a member was added"),
                                prefill=DefaultValue(ServiceState.WARN),
                            ),
                            required=True,
                        ),
                        "removed": DictElement(
                            parameter_form=ServiceState(
                                title=Title("State if a member was removed"),
                                prefill=DefaultValue(ServiceState.WARN),
                            ),
                            required=True,
                        ),
                    },
                ),
            ),
            "query_error_state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the group does not exist or cannot be queried"),
                    prefill=DefaultValue(ServiceState.UNKNOWN),
                ),
            ),
        },
    )


rule_spec_local_group_members = CheckParameters(
    name="local_group_members",
    title=Title("Local group members (Windows, Linux)"),
    topic=Topic.OPERATING_SYSTEM,
    parameter_form=_parameter_form,
    condition=HostAndItemCondition(
        item_title=Title("Group"),
        item_form=String(
            help_text=Help(
                "Built-in groups are named in English on all hosts, e.g. "
                "<tt>Administrators</tt> or <tt>Remote Desktop Users</tt>. On Linux the "
                "group name, e.g. <tt>sudo</tt> or <tt>wheel</tt>, or <tt>sudoers</tt> or "
                "<tt>UID 0</tt>."
            ),
        ),
    ),
)
