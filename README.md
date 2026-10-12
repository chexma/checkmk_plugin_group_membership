# Checkmk plugin: Windows local group members

Monitors which users and groups are members of local groups on Windows
hosts, by default the local Administrators group. One service
`Local group <name>` per group, an agent bakery rule to deploy and configure
the agent plugin, and the members in the HW/SW inventory.

Requires Checkmk 2.5 (the bakery plugin uses the bakery API v2,
`cmk.bakery.v2_unstable`, which may still change until Checkmk 3.0).

> **Status:** the check, the rules and the bakery plugin are tested in a
> Checkmk 2.5.0p15 site with canned agent output. The PowerShell agent plugin
> has not been verified on real Windows hosts yet.

## How it works

The agent plugin `local_administrators.ps1` reads the members with
`Get-LocalGroupMember`. If the cmdlet is missing or fails (it does so when a
group contains orphaned SIDs and, on some builds, Entra ID members), the
plugin falls back to ADSI.

Built-in groups are addressed by their well-known SID, and their service is
named in English on every host (`Local group Administrators`, also on a German
Windows where the group is called `Administratoren`). Rules therefore match
hosts of any language. The localized object classes (`Benutzer`, `Gruppe`) are
normalized to `User` and `Group`.

Domain controllers have no local groups: the plugin reports nothing there and
no services are created.

## Installation

Download the MKP from the
[releases](https://github.com/chexma/checkmk_plugin_local_administrators/releases) and install it under
*Setup > Maintenance > Extension packages*, or on the command line as site
user:

```bash
mkp add local_administrators-<version>.mkp
mkp enable local_administrators <version>
```

## Deploying the agent plugin

**With the agent bakery** (commercial editions): rule
*Setup > Agents > Windows, Linux, Solaris, AIX > Agent rules >
Windows local group members*.

| Setting | Meaning |
|---|---|
| Built-in groups | Groups to monitor, selected from 15 built-in groups (Administrators, Remote Desktop Users, Backup Operators, Hyper-V Administrators, ...). Default: Administrators |
| Other local groups | Names of further local groups, as they are named on the host |
| Run asynchronously and cache the result | Run the plugin in the background and reuse its output for the given time |

**Manually:** copy
`plugins/local_administrators/agents/local_administrators.ps1` to
`C:\ProgramData\checkmk\agent\plugins\`. Without a configuration file the
plugin reports the Administrators group. To monitor other groups, create
`C:\ProgramData\checkmk\agent\config\local_administrators.cfg` with one line
per group:

```
group=S-1-5-32-544
group=S-1-5-32-555
group=My local group
```

Use the SID for built-in groups and the name for all others.

After the first agent output, run a service discovery. A configured group
that does not exist on a host gets no service there.

## Check parameters

Without a rule the services are always OK and list the members in the
service details. Rule *Setup > Services > Service monitoring rules >
Windows local group members*:

| Setting | Effect |
|---|---|
| Local users as members | WARN or CRIT if a local user account is a member. The built-in Administrator (RID 500) can be ignored |
| Unwanted members | List of pattern and state: WARN or CRIT if a matching user or group is a member |
| Allowed members (allow list) | Matching members are always OK and exempt from all other settings |
| Additionally allowed members | Added to the allow list, see below |
| State for members that are not on the allow list | Makes the allow list strict: every other member gets this state |
| Changes since the service discovery | State for members added or removed since the last discovery. Accept a change by updating the service parameters in the service discovery. Members on the allow list may be added without notice |
| State if the group does not exist or cannot be queried | Default UNKNOWN |

**Patterns** are regular expressions that must match the complete member name
as shown in the service details, or the SID of the member. Upper and lower
case are not distinguished. Write the backslash between domain and name
twice:

```
CONTOSO\\Domain Admins
SRV01\\.*
.*\\svc_.*
S-1-5-21-.*-500
```

**Overriding settings for specific hosts:** the rule can be restricted to
hosts, folders, labels and groups like any Checkmk rule. A more specific rule
above a general one overrides only the settings it contains. A list is
replaced as a whole, though: to allow one more account on some hosts, set
*Additionally allowed members* in the specific rule and leave the allow list
to the general rule. If several rules with *Additionally allowed members*
match a service, only the first one applies.

## Inventory

With the HW/SW inventory enabled, the members of all monitored groups are
stored in the table `software > os > local_group_members` (group, member,
type, source, SID), so they can be searched across hosts.

## Section format

```
<<<local_administrators:sep(124)>>>
group|<key>|<group SID>|<group name>|<status>|<method>|<message>
member|<key>|<member SID>|<member name>|<object class>|<principal source>
```

`<status>` is `ok`, `missing` (the group does not exist) or `error` (the
members could not be read). `<principal source>` is `Local`,
`ActiveDirectory`, `AzureAD`, `MicrosoftAccount` or `Unknown`.

## Development

This repository is based on the
[Checkmk plugin development template](https://github.com/chexma/checkmk-plugin-template)
(devcontainer with a Checkmk site, see its README for the environment).

```bash
.devcontainer/ci.sh                                   # lint, tests, plugin validation
.devcontainer/test-host.sh winsrv temp/winsrv.txt     # host with canned agent output
cmk -vI --detect-plugins=local_administrators winsrv
cmk -v --detect-plugins=local_administrators winsrv
.devcontainer/build.sh                                # build the MKP from ./package
```

| Component | Location |
|---|---|
| Agent plugin | `plugins/local_administrators/agents/local_administrators.ps1` |
| Section, check and inventory plugin | `plugins/local_administrators/agent_based/local_administrators.py` |
| Check parameters | `plugins/local_administrators/rulesets/local_administrators.py` |
| Bakery rule | `plugins/local_administrators/rulesets/agent_config.py` |
| Bakery plugin | `plugins/local_administrators/bakery/local_administrators.py` |
| Built-in group table | `plugins/local_administrators/lib.py` |
| Tests | `tests/test_local_administrators.py` |

Releases are documented in `Changelog.md`. To release: bump `version` in
`package`, commit, then `git tag v<version> && git push origin v<version>`;
CI builds the MKP and attaches it to a GitHub release.
