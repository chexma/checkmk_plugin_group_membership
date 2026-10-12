#!/usr/bin/env python3
"""Metrics, graph and perfometer for the services "Local group <name>"."""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph, MinimalRange
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, StrictPrecision, Unit
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer

_UNIT_COUNT = Unit(DecimalNotation(""), StrictPrecision(0))

metric_local_group_member_users = Metric(
    name="local_group_member_users",
    title=Title("Users"),
    unit=_UNIT_COUNT,
    color=Color.BLUE,
)

metric_local_group_member_groups = Metric(
    name="local_group_member_groups",
    title=Title("Groups"),
    unit=_UNIT_COUNT,
    color=Color.ORANGE,
)

graph_local_group_members = Graph(
    name="local_group_members",
    title=Title("Members of the local group"),
    minimal_range=MinimalRange(0, 5),
    compound_lines=["local_group_member_users", "local_group_member_groups"],
)

perfometer_local_group_members = Perfometer(
    name="local_group_members",
    focus_range=FocusRange(Closed(0), Open(20)),
    segments=["local_group_member_users", "local_group_member_groups"],
)
