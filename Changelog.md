# Changelog

All notable changes to this plugin. Versions match `version` in `package`
and the release tags `v<version>`.

## [Unreleased]

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
