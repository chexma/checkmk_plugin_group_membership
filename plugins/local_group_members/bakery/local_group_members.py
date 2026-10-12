#!/usr/bin/env python3
"""Bakery plugin for local_group_members.ps1 (cmk.bakery.v2_unstable, Checkmk 2.5)."""

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Literal

from cmk.bakery.v2_unstable import OS, BakeryPlugin, FileGenerator, Plugin, PluginConfig
from cmk_addons.plugins.local_group_members.lib import WELL_KNOWN_GROUPS
from pydantic import BaseModel

PLUGIN_FILE = "local_group_members.ps1"
CONFIG_FILE = "local_group_members.cfg"


class Deployment(BaseModel):
    builtin_groups: Sequence[str]
    custom_groups: Sequence[str] = ()
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


bakery_plugin_local_group_members = BakeryPlugin(
    name="local_group_members",
    parameter_parser=Config.model_validate,
    default_parameters=None,
    files_function=get_local_group_members_files,
)
