#!/usr/bin/env python3
"""Bakery plugin for the agent plugins local_group_members.ps1 (Windows) and
local_group_members.py (Linux). Uses cmk.bakery.v2_unstable, Checkmk 2.5."""

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Literal

from cmk.bakery.v2_unstable import OS, BakeryPlugin, FileGenerator, Plugin, PluginConfig
from cmk_addons.plugins.local_group_members.lib import WELL_KNOWN_GROUPS
from pydantic import BaseModel

PLUGIN_FILE = "local_group_members.ps1"
LINUX_PLUGIN_FILE = "local_group_members.py"
CONFIG_FILE = "local_group_members.cfg"


class LinuxDeployment(BaseModel):
    groups: Sequence[str] = ()
    custom_groups: Sequence[str] = ()
    sudoers: bool = True
    uid0: bool = True


class Deployment(BaseModel):
    builtin_groups: Sequence[str]
    custom_groups: Sequence[str] = ()
    # Linux hosts get the plugin only if the rule says so: rules made before
    # the Linux plugin existed must not start to deploy it.
    linux: LinuxDeployment | None = None
    interval: float | None = None


class Config(BaseModel):
    deployment: tuple[Literal["deploy"], Deployment] | tuple[Literal["do_not_deploy"], None]


def config_lines(deployment: Deployment) -> Iterable[str]:
    """One line per group: the SID of a built-in group or the name of a custom one."""
    for ident in deployment.builtin_groups:
        if ident in WELL_KNOWN_GROUPS:
            yield f"group={WELL_KNOWN_GROUPS[ident][0]}"
    for name in deployment.custom_groups:
        if name.strip():
            yield f"group={name.strip()}"


def linux_config_lines(linux: LinuxDeployment) -> Iterable[str]:
    """One line per group name; @sudoers and @uid0 are the plugin's pseudo groups."""
    for name in (*linux.groups, *linux.custom_groups):
        if name.strip():
            yield f"group={name.strip()}"
    if linux.sudoers:
        yield "group=@sudoers"
    if linux.uid0:
        yield "group=@uid0"


def get_local_group_members_files(conf: Config) -> FileGenerator:
    if conf.deployment[0] != "deploy":
        return
    deployment = conf.deployment[1]

    yield Plugin(
        base_os=OS.WINDOWS,
        source=Path(PLUGIN_FILE),
        interval=int(deployment.interval) if deployment.interval else None,
    )
    yield PluginConfig(
        base_os=OS.WINDOWS,
        lines=list(config_lines(deployment)),
        target=Path(CONFIG_FILE),
        include_header=True,
    )

    if deployment.linux is None:
        return
    yield Plugin(
        base_os=OS.LINUX,
        source=Path(LINUX_PLUGIN_FILE),
        interval=int(deployment.interval) if deployment.interval else None,
    )
    yield PluginConfig(
        base_os=OS.LINUX,
        lines=list(linux_config_lines(deployment.linux)),
        target=Path(CONFIG_FILE),
        include_header=True,
    )


bakery_plugin_local_group_members = BakeryPlugin(
    name="local_group_members",
    parameter_parser=Config.model_validate,
    default_parameters=None,
    files_function=get_local_group_members_files,
)
