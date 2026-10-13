# Checkmk plugin: local group members (Windows, Linux)

Monitors who has administrative rights on a server:

- **Windows:** the users and groups that are members of local groups, by
  default the local Administrators group.
- **Linux:** the members of privileged groups (`sudo`, `wheel`, ...), the
  users and groups named in the sudoers files and the accounts with UID 0.

One service `Group Membership <name>` per group, an agent bakery rule to deploy
and configure the agent plugins, and the members in the HW/SW inventory.

Requires Checkmk 2.5 (the bakery plugin uses the bakery API v2,
`cmk.bakery.v2_unstable`, which may still change until Checkmk 3.0).

> **Status:** the check, the rules and the bakery plugin are tested in a
> Checkmk 2.5.0p15 site. The PowerShell agent plugin has run on one German
> Windows server (domain member, deployed by the bakery with caching). Not
> verified yet: English Windows, the ADSI fallback (groups with orphaned
> SIDs), Entra ID members, domain controllers and custom group names.
> The Linux agent plugin is covered by unit tests and has run in the
> development container only: not on a real server, not with SSSD or LDAP
> accounts and not against a real sudoers file yet.

## How it works

### Windows

The agent plugin `local_group_members.ps1` reads the members with
`Get-LocalGroupMember`. If the cmdlet is missing or fails (it does so when a
group contains orphaned SIDs and, on some builds, Entra ID members), the
plugin falls back to ADSI.

Built-in groups are addressed by their well-known SID, and their service is
named in English on every host (`Group Membership Administrators`, also on a German
Windows where the group is called `Administratoren`). Rules therefore match
hosts of any language. The localized object classes (`Benutzer`, `Gruppe`) are
normalized to `User` and `Group`.

Domain controllers have no local groups: the plugin reports nothing there and
no services are created.

### Linux

Linux has no single group of administrators, so the agent plugin
`local_group_members.py` (Python 3.4 or newer, standard library only) reports
three things, each as a service:

| Service | Members |
|---|---|
| `Group Membership sudo`, `Group Membership wheel`, ... | The members of the group and the users that have it as primary group. Read through NSS, so accounts from SSSD or LDAP are included |
| `Group Membership sudoers` | Every user and `%group` that `/etc/sudoers` and the files it includes grant commands to. The details say `ALL` (every command as root) or `restricted`, and `NOPASSWD` |
| `Group Membership UID 0` | All accounts with UID 0 |

A member is identified by `uid:<number>` or `gid:<number>` where Windows has a
SID. Its source is `Local` (listed in `/etc/passwd` or `/etc/group`),
`Directory` (known only through NSS) or `Unknown` (the name cannot be
resolved, e.g. a deleted user that is still listed in a group).

Limits:

- sudo rules that come from LDAP or SSSD (`sudoers: sss` in
  `nsswitch.conf`) are not read, only the files.
- A `%group` in the sudoers files is not expanded to its members. Monitor
  that group as well.
- With SSSD the members of a directory group are missing if
  `ignore_group_members` is set, and users that have the group as primary
  group are only found for local accounts unless enumeration is enabled.
- The sudoers parser does not evaluate host lists: a rule counts on every
  host.

## Installation

Download the MKP from the
[releases](https://github.com/chexma/checkmk_plugin_local_administrators/releases) and install it under
*Setup > Maintenance > Extension packages*, or on the command line as site
user:

```bash
mkp add local_group_members-<version>.mkp
mkp enable local_group_members <version>
```

## Deploying the agent plugin

**With the agent bakery** (commercial editions): rule
*Setup > Agents > Windows, Linux, Solaris, AIX > Agent rules >
Local group members (Windows, Linux)*.

| Setting | Meaning |
|---|---|
| Windows: built-in groups | Groups to monitor, selected from 15 built-in groups (Administrators, Remote Desktop Users, Backup Operators, Hyper-V Administrators, ...). Default: Administrators |
| Windows: other local groups | Names of further local groups, as they are named on the host |
| Linux hosts | Deploy the plugin to Linux hosts as well: groups to monitor (default `sudo`, `wheel`, `admin`, `root`; also `adm`, `docker`, `lxd`, `libvirt`, `disk`, `shadow` and any other name), the sudoers entries and the accounts with UID 0. Without this setting only Windows hosts get the plugin |
| Run asynchronously and cache the result | Run the plugin in the background and reuse its output for the given time |

**Manually, Windows:** copy
`plugins/local_group_members/agents/local_group_members.ps1` to
`C:\ProgramData\checkmk\agent\plugins\`. Without a configuration file the
plugin reports the Administrators group. To monitor other groups, create
`C:\ProgramData\checkmk\agent\config\local_group_members.cfg` with one line
per group:

```
group=S-1-5-32-544
group=S-1-5-32-555
group=My local group
```

Use the SID for built-in groups and the name for all others.

**Manually, Linux:** copy
`plugins/local_group_members/agents/local_group_members.py` to
`/usr/lib/check_mk_agent/plugins/` (or into a subdirectory named after the
cache time in seconds, e.g. `plugins/3600/`) and make it executable. Without
a configuration file the plugin reports the groups `sudo`, `wheel`, `admin`
and `root`, the sudoers entries and the accounts with UID 0. To change that,
create `/etc/check_mk/local_group_members.cfg`:

```
group=sudo
group=docker
group=@sudoers
group=@uid0
```

After the first agent output, run a service discovery. A configured group
that does not exist on a host gets no service there.

## Check parameters

Without a rule the services are always OK and list the members in the
service details. Rule *Setup > Services > Service monitoring rules >
Local group members (Windows, Linux)*:

| Setting | Effect |
|---|---|
| Local users as members | WARN or CRIT if a local user account is a member. The built-in Administrator (RID 500) and, on Linux, root can be ignored |
| Unwanted members | List of pattern and state: WARN or CRIT if a matching user or group is a member |
| Required members | List of pattern and state: WARN or CRIT for every entry that matches no member. Required members are always OK, like those on the allow list |
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

On Linux the names have no domain, groups in the service `sudoers` start with
a percent sign, and `uid:<number>` or `gid:<number>` takes the place of the
SID:

```
jdoe
%linux-admins
svc_.*
uid:0
```

The item of the rule is the group name (`sudo`, `wheel`), `sudoers` or
`UID 0`. A typical rule for `UID 0` allows `root` and sets a state for
members that are not on the allow list.

**Placeholder for the host name:** `$HOSTNAME$` in a pattern is replaced by
the Windows computer name of the host, on Linux by its short host name (as
reported by the agent plugin, not the host name in Checkmk). One rule then covers accounts that carry the name
of their server:

```
CONTOSO\\srvadmins_$HOSTNAME$     on SRV01: the domain group srvadmins_SRV01
$HOSTNAME$\\adm_$HOSTNAME$        on SRV01: the local user adm_SRV01
$HOSTNAME$\\.*                    all local accounts of the host
```

**Overriding settings for specific hosts:** the rule can be restricted to
hosts, folders, labels and groups like any Checkmk rule. A more specific rule
above a general one overrides only the settings it contains. A list is
replaced as a whole, though: to allow one more account on some hosts, set
*Additionally allowed members* in the specific rule and leave the allow list
to the general rule. If several rules with *Additionally allowed members*
match a service, only the first one applies.

## Metrics

Every service reports the number of users and of groups among the members
(`local_group_member_users`, `local_group_member_groups`), with a graph and a
Perf-O-Meter.

## Inventory

With the HW/SW inventory enabled, the members of all monitored groups are
stored in the table `software > os > local_group_members` (group, member,
type, source, SID, and for sudoers entries the details).

The table is available as *Group memberships* in three places:

- in the inventory tree of a host, below *Software > Operating system*,
- as the views *Inventory > Search Group memberships* (all hosts; it shows
  rows after you apply a filter, an empty one is enough) and
  *Group memberships* of a single host,
- as data source *Inventory table: Group memberships* for your own views,
  which can then be put on a dashboard.

The HW/SW inventory has to be enabled for the hosts with the rule
*Setup > Hosts > HW/SW inventory rules > Do hardware/software inventory*. The
rules that Checkmk ships only cover a few kinds of hosts (Checkmk servers,
Docker, Kubernetes, Azure), so Windows and Linux servers need a rule of their
own. The data appears after the service *Check_MK HW/SW Inventory* has run.

## Section format

```
<<<local_group_members:sep(124)>>>
computer|<computer name>
group|<key>|<group SID>|<group name>|<status>|<method>|<message>
member|<key>|<member SID>|<member name>|<object class>|<principal source>
```

`<status>` is `ok`, `missing` (the group does not exist) or `error` (the
members could not be read). `<principal source>` is `Local`,
`ActiveDirectory`, `AzureAD`, `MicrosoftAccount` or `Unknown`.

Linux hosts send the same section with `uid:<n>`, `gid:<n>` or `name:<name>`
in place of the SIDs, the sources `Local`, `Directory` or `Unknown`, and a
further field with the details of sudoers entries:

```
member|<key>|<uid:N or gid:N>|<member name>|<object class>|<source>|<details>
```

## Development

This repository is based on the
[Checkmk plugin development template](https://github.com/chexma/checkmk-plugin-template)
(devcontainer with a Checkmk site, see its README for the environment).

```bash
.devcontainer/ci.sh                                   # lint, tests, plugin validation
.devcontainer/test-host.sh winsrv temp/winsrv.txt     # host with canned agent output
cmk -vI --detect-plugins=local_group_members winsrv
cmk -v --detect-plugins=local_group_members winsrv
python3 plugins/local_group_members/agents/local_group_members.py   # the Linux plugin runs in the container
.devcontainer/build.sh                                # build the MKP from ./package
```

| Component | Location |
|---|---|
| Agent plugin, Windows | `plugins/local_group_members/agents/local_group_members.ps1` |
| Agent plugin, Linux | `plugins/local_group_members/agents/local_group_members.py` |
| Section, check and inventory plugin | `plugins/local_group_members/agent_based/local_group_members.py` |
| Check parameters | `plugins/local_group_members/rulesets/local_group_members.py` |
| Metrics, graph, Perf-O-Meter | `plugins/local_group_members/graphing/local_group_members.py` |
| Inventory table: titles and views | `plugins/local_group_members/inventory_ui/local_group_members.py` |
| Bakery rule | `plugins/local_group_members/rulesets/agent_config.py` |
| Bakery plugin | `plugins/local_group_members/bakery/local_group_members.py` |
| Built-in group table | `plugins/local_group_members/lib.py` |
| Tests | `tests/test_local_group_members.py`, `tests/test_agent_linux.py` |

Releases are documented in `Changelog.md`. The version is `2.5.<n>`: the first
two numbers are the Checkmk version the plugin is made for, only the third
one counts up. To release: bump `version` in `package`, commit, then `git tag v<version> && git push origin v<version>`;
CI builds the MKP and attaches it to a GitHub release.
