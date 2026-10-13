# Changelog

All notable changes to this plugin. Versions match `version` in `package`
and the release tags `v<version>`. The first two numbers are the Checkmk
version the plugin is made for (2.5); only the third one counts up.

## [Unreleased]

- New script `tools/New-GroupMemberAllowRule.ps1` (not part of the MKP): reads
  the members reported by services in the state WARN and creates one disabled
  rule per host and group with them in "Additionally allowed members", ready
  to be reviewed and enabled.

## [2.5.3] - 2026-10-13

- Linux: new agent plugin `local_group_members.py`. It reports the members of
  privileged groups (`sudo`, `wheel`, ...), the users and groups named in the
  sudoers files (service `Group Membership sudoers`, with `ALL` or
  `restricted` and `NOPASSWD` in the details) and the accounts with UID 0
  (service `Group Membership UID 0`). Check, rule, metrics and inventory are
  the same as for Windows.
- Agent bakery rule: new setting "Linux hosts". Existing rules stay valid and
  keep deploying to Windows hosts only.
- The option to ignore the built-in Administrator also covers root on Linux.
- Both rules are now titled "Local group members (Windows, Linux)".
- The services are now named `Group Membership <name>` instead of
  `Local group <name>`. After the update run a service discovery on the
  hosts: the old services vanish and the new ones start without history.
  Rules that match on the item (the group name) keep working; views, BI
  rules or notification rules that match the service name need the new name.
- The inventory table is now available for views and dashboards: data source
  "Inventory table: Group memberships", the views "Search Group memberships"
  (all hosts) and "Group memberships" of a host, and readable column titles
  in the inventory tree.

## [2.5.2] - 2026-10-12

- Rule option "Required members": users or groups that have to be members of
  the group, each with the state the service gets if it is missing. Required
  members are always OK, like the members on the allow list. `$HOSTNAME$` is
  supported.
- Metrics for the number of users and of groups among the members, with a
  graph and a Perf-O-Meter.

## [2.5.1] - 2026-10-12

- Placeholder `$HOSTNAME$` in the patterns of allowed, additionally allowed
  and unwanted members: replaced by the Windows computer name, which the
  agent plugin now reports in a `computer` line.
- Rule help: format of the patterns, examples and the note that the backslash
  has to be written twice now appear at the lists themselves.
- The service details no longer show how the group was queried
  ("queried with Get-LocalGroupMember").

## [2.5.0] - 2026-10-12

- Renamed the package and everything in it from `local_administrators` to
  `local_group_members`: plugin family, agent section, check plugin, both
  rulesets, bakery plugin, agent plugin `local_group_members.ps1` and its
  configuration file `local_group_members.cfg`. Not compatible with 1.0.0:
  remove the old package, recreate the rules, bake and deploy the agents and
  rediscover the services.

## [1.0.0] - 2026-10-12

- Agent plugin `local_administrators.ps1`: members of local groups via
  `Get-LocalGroupMember` with ADSI fallback, independent of the OS language.
- Check `Local group <name>` with rule "Windows local group members": local
  users, unwanted members, allow list, changes since discovery, error state.
- HW/SW inventory of the members.
- Agent bakery rule and plugin (bakery API v2): groups and cache interval.
- Rule option "Additionally allowed members" so that a rule for specific
  hosts can extend the general allow list.
