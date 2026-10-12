# Changelog

All notable changes to this plugin. Versions match `version` in `package`
and the release tags `v<version>`.

## [Unreleased]

## [1.0.0] - 2026-10-12

- Agent plugin `local_administrators.ps1`: members of local groups via
  `Get-LocalGroupMember` with ADSI fallback, independent of the OS language.
- Check `Local group <name>` with rule "Windows local group members": local
  users, unwanted members, allow list, changes since discovery, error state.
- HW/SW inventory of the members.
- Agent bakery rule and plugin (bakery API v2): groups and cache interval.
- Rule option "Additionally allowed members" so that a rule for specific
  hosts can extend the general allow list.
