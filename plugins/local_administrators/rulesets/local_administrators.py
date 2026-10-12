#!/usr/bin/env python3
"""Check parameters for the services "Local group <name>"."""

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

_PATTERN_HELP = Help(
    "Regular expression that has to match the complete member name as shown in the "
    "service details (e.g. <tt>CONTOSO\\\\Domain Admins</tt>, <tt>SRV01\\\\.*</tt>) or the "
    "SID of the member. Upper and lower case are not distinguished. Note that the "
    "backslash between domain and name has to be written twice."
)


def _parameter_form() -> Dictionary:
    return Dictionary(
        elements={
            "local_users": DictElement(
                parameter_form=Dictionary(
                    title=Title("Local users as members"),
                    help_text=Help(
                        "Set a state for local user accounts that are members of the group. "
                        "Domain accounts and groups are not affected."
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
                                label=Label("Ignore the built-in Administrator account (RID 500)"),
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
                        "The first matching entry determines the state."
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
            "allowed": DictElement(
                parameter_form=List(
                    title=Title("Allowed members (allow list)"),
                    help_text=Help(
                        "Members matching one of these patterns are always OK. They are "
                        "exempt from all other settings of this rule."
                    ),
                    add_element_label=Label("Add allowed member"),
                    element_template=RegularExpression(
                        help_text=_PATTERN_HELP,
                        predefined_help_text=MatchingScope.FULL,
                    ),
                ),
            ),
            "allowed_additional": DictElement(
                parameter_form=List(
                    title=Title("Additionally allowed members"),
                    help_text=Help(
                        "These members are allowed in addition to the allow list. Use this "
                        "in a rule for specific hosts or groups: a more specific rule "
                        "replaces the allow list of a general rule, whereas this list is "
                        "added to it."
                    ),
                    add_element_label=Label("Add allowed member"),
                    element_template=RegularExpression(
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


rule_spec_local_administrators = CheckParameters(
    name="local_administrators",
    title=Title("Windows local group members"),
    topic=Topic.OPERATING_SYSTEM,
    parameter_form=_parameter_form,
    condition=HostAndItemCondition(
        item_title=Title("Group"),
        item_form=String(
            help_text=Help(
                "Built-in groups are named in English on all hosts, e.g. "
                "<tt>Administrators</tt> or <tt>Remote Desktop Users</tt>."
            ),
        ),
    ),
)
