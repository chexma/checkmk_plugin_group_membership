#!/usr/bin/env python3
"""Inventory table of the group members: column titles and the views based on it.

The View makes the table a data source for views and dashboards ("Inventory
table: Group memberships") and creates the views invlocalgroupmembers_search
(all hosts) and invlocalgroupmembers_of_host.
"""

from cmk.inventory_ui.v1_unstable import Node, Table, TextField, Title, View

node_software_os_local_group_members = Node(
    name="software_os_local_group_members",
    path=["software", "os", "local_group_members"],
    title=Title("Group memberships"),
    table=Table(
        view=View(name="invlocalgroupmembers", title=Title("Group memberships")),
        columns={
            "group": TextField(Title("Group")),
            "member": TextField(Title("Member")),
            "type": TextField(Title("Type")),
            "source": TextField(Title("Source")),
            "details": TextField(Title("Details")),
            "sid": TextField(Title("SID / ID")),
            "group_local_name": TextField(Title("Group name on the host")),
        },
    ),
)
