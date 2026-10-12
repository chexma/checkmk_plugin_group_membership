#!/usr/bin/env python3
"""Agent bakery rule for the agent plugin local_administrators.ps1."""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    List,
    MultipleChoice,
    MultipleChoiceElement,
    String,
    TimeMagnitude,
    TimeSpan,
    validators,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic
from cmk_addons.plugins.local_administrators.lib import DEFAULT_GROUPS, WELL_KNOWN_GROUPS


def _deployment_form() -> Dictionary:
    return Dictionary(
        elements={
            "builtin_groups": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Built-in groups"),
                    help_text=Help(
                        "These groups are addressed by their well-known SID, so the "
                        "selection works on Windows installations of any language."
                    ),
                    elements=[
                        MultipleChoiceElement(name=ident, title=Title("%s") % name)
                        for ident, (_sid, name) in WELL_KNOWN_GROUPS.items()
                    ],
                    prefill=DefaultValue(DEFAULT_GROUPS),
                ),
                required=True,
            ),
            "custom_groups": DictElement(
                parameter_form=List(
                    title=Title("Other local groups"),
                    help_text=Help(
                        "Names of further local groups, exactly as they are named on the "
                        "host. Groups that do not exist on a host are skipped there."
                    ),
                    add_element_label=Label("Add group"),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=1),),
                    ),
                ),
            ),
            "interval": DictElement(
                parameter_form=TimeSpan(
                    title=Title("Run asynchronously and cache the result"),
                    help_text=Help(
                        "Group memberships rarely change. With this setting the plugin "
                        "runs in the background and its output is reused for the given "
                        "time. Without it the plugin runs on every agent call."
                    ),
                    label=Label("Cache for"),
                    displayed_magnitudes=[TimeMagnitude.HOUR, TimeMagnitude.MINUTE],
                    prefill=DefaultValue(3600.0),
                ),
            ),
        },
    )


def _parameter_form() -> Dictionary:
    return Dictionary(
        help_text=Help(
            "Deploys the agent plugin <tt>local_administrators.ps1</tt>, which reports the "
            "members of local groups on Windows hosts."
        ),
        elements={
            "deployment": DictElement(
                parameter_form=CascadingSingleChoice(
                    title=Title("Deployment"),
                    elements=[
                        CascadingSingleChoiceElement(
                            name="deploy",
                            title=Title("Deploy the plugin"),
                            parameter_form=_deployment_form(),
                        ),
                        CascadingSingleChoiceElement(
                            name="do_not_deploy",
                            title=Title("Do not deploy the plugin"),
                            parameter_form=FixedValue(value=None),
                        ),
                    ],
                    prefill=DefaultValue("deploy"),
                ),
                required=True,
            ),
        },
    )


rule_spec_local_administrators_bakery = AgentConfig(
    name="local_administrators",
    title=Title("Windows local group members"),
    topic=Topic.OPERATING_SYSTEM,
    parameter_form=_parameter_form,
)
