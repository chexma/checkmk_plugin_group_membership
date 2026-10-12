# Checkmk agent plugin: members of local groups on Windows hosts.
#
# Reports the members of the local Administrators group or of the groups listed
# in the configuration file %MK_CONFDIR%\local_group_members.cfg:
#
#   group=S-1-5-32-544           (SID of a built-in group, independent of the OS language)
#   group=My local group         (name of any other local group)
#
# Output (section local_group_members, separated by pipes):
#
#   computer|<computer name>
#   group|<key>|<group SID>|<group name>|<status>|<method>|<message>
#   member|<key>|<member SID>|<member name>|<object class>|<principal source>
#
# <status> is ok, missing (group does not exist) or error (members not readable).
# The members are read with Get-LocalGroupMember. This cmdlet fails completely if
# the group contains orphaned SIDs or, on some builds, Entra ID members; in that
# case, and on systems without the cmdlet, the plugin falls back to ADSI.

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$DefaultGroups = @('S-1-5-32-544')

function Get-ConfiguredGroups {
    $confDir = $env:MK_CONFDIR
    if (-not $confDir) { return $DefaultGroups }
    $confFile = Join-Path $confDir 'local_group_members.cfg'
    if (-not (Test-Path -LiteralPath $confFile)) { return $DefaultGroups }

    $groups = @()
    foreach ($line in Get-Content -LiteralPath $confFile -Encoding UTF8) {
        if ($line -match '^\s*group\s*=\s*(.+?)\s*$') { $groups += $Matches[1] }
    }
    if ($groups.Count -eq 0) { return $DefaultGroups }
    return $groups
}

function Format-Field([object]$Value) {
    # Keep the section parseable: no separators or line breaks inside a field.
    return ([string]$Value) -replace '[|\r\n]+', ' '
}

function Resolve-Group([string]$Spec) {
    # Returns the SID and the (localized) name of a group given by SID or name,
    # or $null if there is no such local group.
    if ($Spec -match '^S-1-') {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($Spec)
            $account = $sid.Translate([System.Security.Principal.NTAccount]).Value
            return @{ Sid = $sid.Value; Name = ($account -split '\\')[-1] }
        } catch {
            return $null
        }
    }
    try {
        $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$Spec,group"
        $bytes = $adsi.objectSid.Value
        if (-not $bytes) { return $null }
        $sid = New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)
        return @{ Sid = $sid.Value; Name = [string]$adsi.Name.Value }
    } catch {
        return $null
    }
}

$script:MachineSid = $null
function Get-MachineSid {
    # SID prefix shared by all local accounts of this computer.
    if ($null -ne $script:MachineSid) { return $script:MachineSid }
    $script:MachineSid = ''
    try {
        $account = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' |
            Select-Object -First 1
        if ($account) { $script:MachineSid = $account.SID -replace '-\d+$', '' }
    } catch { }
    return $script:MachineSid
}

function Get-PrincipalSource([string]$Sid) {
    # Same values as the PrincipalSource property of Get-LocalGroupMember.
    if ($Sid -match '^S-1-12-1-') { return 'AzureAD' }
    if ($Sid -match '^S-1-5-21-') {
        $machineSid = Get-MachineSid
        if ($machineSid -and $Sid.StartsWith("$machineSid-")) { return 'Local' }
        return 'ActiveDirectory'
    }
    return 'Unknown'
}

function Get-MembersWithCmdlet([string]$GroupSid) {
    foreach ($member in @(Get-LocalGroupMember -SID $GroupSid -ErrorAction Stop)) {
        @{
            Sid    = $member.SID.Value
            Name   = $member.Name
            Class  = $member.ObjectClass
            Source = [string]$member.PrincipalSource
        }
    }
}

function Get-MembersWithAdsi([string]$GroupName) {
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"
    foreach ($member in @($group.psbase.Invoke('Members'))) {
        $type = $member.GetType()
        $bytes = $type.InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
        $class = $type.InvokeMember('Class', 'GetProperty', $null, $member, $null)
        $sid = New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)
        try {
            $name = $sid.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            # Orphaned SID: the account no longer exists.
            $name = $sid.Value
        }
        @{
            Sid    = $sid.Value
            Name   = $name
            Class  = $class
            Source = Get-PrincipalSource $sid.Value
        }
    }
}

Write-Output '<<<local_group_members:sep(124)>>>'
# The check replaces $HOSTNAME$ in rule patterns by this name.
Write-Output "computer|$env:COMPUTERNAME"

# Domain controllers have no local groups.
try {
    if ((Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4) { exit 0 }
} catch { }

$key = 0
foreach ($spec in Get-ConfiguredGroups) {
    $key++
    $group = Resolve-Group $spec
    if ($null -eq $group) {
        $sid = ''
        if ($spec -match '^S-1-') { $sid = $spec }
        Write-Output ("group|$key|$sid|" + (Format-Field $spec) + '|missing||')
        continue
    }

    $members = $null
    $method = 'Get-LocalGroupMember'
    $message = ''
    try {
        $members = @(Get-MembersWithCmdlet $group.Sid)
    } catch {
        $cmdletError = $_.Exception.Message
        $method = 'ADSI'
        try {
            $members = @(Get-MembersWithAdsi $group.Name)
        } catch {
            $message = "Get-LocalGroupMember: $cmdletError / ADSI: $($_.Exception.Message)"
        }
    }

    if ($null -eq $members) {
        Write-Output ("group|$key|$($group.Sid)|" + (Format-Field $group.Name) + '|error||' + (Format-Field $message))
        continue
    }

    Write-Output ("group|$key|$($group.Sid)|" + (Format-Field $group.Name) + "|ok|$method|")
    foreach ($member in $members) {
        Write-Output ("member|$key|$($member.Sid)|" + (Format-Field $member.Name) + '|' +
            (Format-Field $member.Class) + '|' + (Format-Field $member.Source))
    }
}
