#!/usr/bin/env python3
"""Constants shared by the check plugin, the rulesets and the bakery plugin."""

# Built-in local groups: identifier used in the bakery ruleset -> (SID, English name).
# The agent plugin addresses them by SID because the group names are localized
# ("Administrators" / "Administratoren"); the check uses the English name as
# service item so that rules match hosts of any language.
WELL_KNOWN_GROUPS: dict[str, tuple[str, str]] = {
    "administrators": ("S-1-5-32-544", "Administrators"),
    "users": ("S-1-5-32-545", "Users"),
    "guests": ("S-1-5-32-546", "Guests"),
    "power_users": ("S-1-5-32-547", "Power Users"),
    "backup_operators": ("S-1-5-32-551", "Backup Operators"),
    "remote_desktop_users": ("S-1-5-32-555", "Remote Desktop Users"),
    "network_configuration_operators": ("S-1-5-32-556", "Network Configuration Operators"),
    "performance_monitor_users": ("S-1-5-32-558", "Performance Monitor Users"),
    "performance_log_users": ("S-1-5-32-559", "Performance Log Users"),
    "distributed_com_users": ("S-1-5-32-562", "Distributed COM Users"),
    "iis_iusrs": ("S-1-5-32-568", "IIS_IUSRS"),
    "cryptographic_operators": ("S-1-5-32-569", "Cryptographic Operators"),
    "event_log_readers": ("S-1-5-32-573", "Event Log Readers"),
    "hyper_v_administrators": ("S-1-5-32-578", "Hyper-V Administrators"),
    "remote_management_users": ("S-1-5-32-580", "Remote Management Users"),
}

GROUP_NAME_BY_SID: dict[str, str] = {sid: name for sid, name in WELL_KNOWN_GROUPS.values()}

DEFAULT_GROUPS = ["administrators"]

# Linux: the group that grants sudo rights is named differently per distribution
# (sudo on Debian, wheel on Red Hat and SUSE, admin on old Ubuntu). Groups that do
# not exist on a host get no service, so all of them can be configured everywhere.
DEFAULT_LINUX_GROUPS = ["sudo", "wheel", "admin", "root"]

# Offered in the bakery ruleset. Besides the sudo groups: groups whose members
# can become root by other means (containers, virtual machines, raw disks,
# password hashes) or read the system logs.
LINUX_GROUPS = [*DEFAULT_LINUX_GROUPS, "adm", "docker", "lxd", "libvirt", "disk", "shadow"]
