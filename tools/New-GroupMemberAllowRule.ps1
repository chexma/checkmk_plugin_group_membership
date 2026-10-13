<#
.SYNOPSIS
Proposes "Additionally allowed members" rules for the services "Group Membership <name>".

.DESCRIPTION
Reads the services "Group Membership <name>" of the Checkmk plugin local_group_members
that are in the state WARN, takes the reported members from the service details and
creates one DISABLED rule per host and group in the ruleset "Local group members
(Windows, Linux)". The rule holds the members in "Additionally allowed members", as
exact names. Review the rule in Setup, enable it and activate the changes.

Members reported as "unwanted member" are never proposed.

Checkmk uses only the first matching rule that has "Additionally allowed members".
The script therefore keeps one rule per host and group:

  * no rule yet:              a new disabled rule is created
  * a disabled rule exists:   the new members are added to it
  * an enabled rule exists:   it is not touched. A disabled rule with the old and the
                              new members is created in front of it. Enable it after
                              the review and delete the old one.

Nothing is activated. Use -WhatIf to see what would be done.

.PARAMETER Server
Name of the Checkmk server, with a port if needed (monitoring.example.com:8443).

.PARAMETER Site
Name of the Checkmk site.

.PARAMETER User
Checkmk user, usually an automation user. It needs access to the services and the
permission to edit rules.

.PARAMETER Secret
Password or automation secret. Default: the environment variable CMK_SECRET; without
it the script asks.

.PARAMETER Protocol
https (default) or http.

.PARAMETER HostFilter
Regular expression: only hosts whose name matches (case-insensitive, anywhere in the name).

.PARAMETER Group
Only this group, e.g. Administrators. Default: all groups.

.PARAMETER State
Service states to read: WARN (default) and/or CRIT.

.PARAMETER Folder
Folder for new rules, e.g. "/" (default, main folder) or "/windows/servers". A rule
that replaces an enabled one is created in the folder of that rule.

.PARAMETER SkipCertificateCheck
Do not validate the TLS certificate of the server.

.EXAMPLE
.\New-GroupMemberAllowRule.ps1 -Server monitoring.example.com -Site prod -User automation -WhatIf

Shows the rules that would be created.

.EXAMPLE
.\New-GroupMemberAllowRule.ps1 -Server monitoring.example.com -Site prod -User automation |
    Export-Csv proposed.csv -NoTypeInformation -Encoding UTF8

Creates the disabled rules and keeps a list of the proposed members.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Site,
    [Parameter(Mandatory = $true)][string]$User,
    [string]$Secret = $env:CMK_SECRET,
    [ValidateSet('https', 'http')][string]$Protocol = 'https',
    [string]$HostFilter,
    [string]$Group,
    [ValidateSet('WARN', 'CRIT')][string[]]$State = @('WARN'),
    [string]$Folder = '/',
    [switch]$SkipCertificateCheck
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$Ruleset = 'checkgroup_parameters:local_group_members'
$ServicePrefix = 'Group Membership '
$ScriptName = 'New-GroupMemberAllowRule.ps1'

# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

function ConvertTo-RegexLiteral {
    # Escapes only what has a meaning in a regular expression. [regex]::Escape also
    # escapes blanks, which makes names like "Domain Admins" hard to read in the rule.
    param([string]$Text)
    return [regex]::Replace($Text, '[\\.^$|?*+()\[\]{}]', '\$0')
}

function ConvertTo-PythonString {
    param([string]$Text)
    $escaped = $Text.Replace('\', '\\')
    if ($escaped.Contains("'") -and -not $escaped.Contains('"')) {
        return '"' + $escaped + '"'
    }
    return "'" + $escaped.Replace("'", "\'") + "'"
}

function ConvertTo-PythonList {
    param([string[]]$Items)
    return '[' + ((@($Items) | ForEach-Object { ConvertTo-PythonString $_ }) -join ', ') + ']'
}

function Get-AllowedAdditional {
    # Finds the list 'allowed_additional' in the value of a rule (a Python literal).
    # Returns $null if the value cannot be read, otherwise Found, Start, Length, Items.
    param([string]$ValueRaw)

    $match = [regex]::Match($ValueRaw, '[''"]allowed_additional[''"]\s*:\s*\[')
    if (-not $match.Success) {
        return @{ Found = $false; Items = @() }
    }
    $items = New-Object System.Collections.Generic.List[string]
    $pos = $match.Index + $match.Length
    while ($pos -lt $ValueRaw.Length) {
        $char = $ValueRaw[$pos]
        if ($char -eq ']') {
            return @{
                Found  = $true
                Start  = $match.Index + $match.Length - 1
                Length = $pos - ($match.Index + $match.Length - 1) + 1
                Items  = $items.ToArray()
            }
        }
        if ($char -eq ',' -or [char]::IsWhiteSpace($char)) {
            $pos++
            continue
        }
        if ($char -ne "'" -and $char -ne '"') {
            return $null
        }
        $quote = $char
        $text = New-Object System.Text.StringBuilder
        $pos++
        while ($pos -lt $ValueRaw.Length -and $ValueRaw[$pos] -ne $quote) {
            if ($ValueRaw[$pos] -eq '\' -and $pos + 1 -lt $ValueRaw.Length) {
                $next = $ValueRaw[$pos + 1]
                if ($next -eq '\' -or $next -eq "'" -or $next -eq '"') {
                    [void]$text.Append($next)
                }
                else {
                    [void]$text.Append('\').Append($next)
                }
                $pos += 2
                continue
            }
            [void]$text.Append($ValueRaw[$pos])
            $pos++
        }
        if ($pos -ge $ValueRaw.Length) {
            return $null
        }
        $items.Add($text.ToString())
        $pos++
    }
    return $null
}

function Set-AllowedAdditional {
    # Returns the value of a rule with the list 'allowed_additional' replaced.
    param([string]$ValueRaw, $Parsed, [string[]]$Items)

    $list = ConvertTo-PythonList $Items
    if ($Parsed.Found) {
        return $ValueRaw.Substring(0, $Parsed.Start) + $list +
            $ValueRaw.Substring($Parsed.Start + $Parsed.Length)
    }
    $rest = $ValueRaw.Trim()
    if ($rest -notmatch '^\{[\s\S]*\}$') {
        return $null
    }
    $inner = $rest.Substring(1, $rest.Length - 2).Trim()
    if ($inner) {
        return "{'allowed_additional': $list, $inner}"
    }
    return "{'allowed_additional': $list}"
}

$MemberLine = [regex]('^(?<name>.+) \((?<class>[^,()]+), (?<source>[^,()]+)(?:, [^()]*)?\)' +
    '(?:: (?<reasons>.*?))?(?<marker>\(!!?\))?$')
$OtherLine = [regex]('^(Members: |Group: |Invalid regular expression|Members could not be queried|' +
    'Group does not exist)')
$TrailerLine = [regex]'(^Required member missing: |: removed since service discovery(\(!!?\))?$)'

function Get-ReportedMember {
    # Returns the members of one service that have a non-OK state: Name, Reasons.
    param([string]$Details)

    # Livestatus separates the lines by a backslash and an "n" and does not escape the
    # backslashes of the names, so CONTOSO\nagios looks like a line break. A piece that
    # is no complete line is therefore joined with the next one.
    $pending = $null
    foreach ($piece in [regex]::Split($Details, '\\n|\r?\n')) {
        if ($null -ne $pending) {
            $line = $pending + '\n' + $piece
        }
        else {
            $line = $piece
        }
        # The lines after the members can no longer belong to a member.
        if ($TrailerLine.IsMatch($line)) {
            break
        }
        if ($OtherLine.IsMatch($line)) {
            $pending = $null
            continue
        }
        $match = $MemberLine.Match($line)
        if (-not $match.Success) {
            $pending = $line
            continue
        }
        $pending = $null
        if (-not $match.Groups['marker'].Success) {
            continue
        }
        [pscustomobject]@{
            Name    = $match.Groups['name'].Value
            Reasons = @($match.Groups['reasons'].Value -split ', ' | Where-Object { $_ })
        }
    }
}

# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

if (-not $Secret) {
    $secure = Read-Host -AsSecureString "Password or automation secret of $User"
    $Secret = (New-Object System.Net.NetworkCredential('', $secure)).Password
}

$ApiUrl = '{0}://{1}/{2}/check_mk/api/1.0' -f $Protocol, $Server, $Site
$WebOptions = @{ UseBasicParsing = $true }
if ($PSVersionTable.PSVersion.Major -ge 6) {
    if ($SkipCertificateCheck) {
        $WebOptions['SkipCertificateCheck'] = $true
    }
}
else {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    if ($SkipCertificateCheck) {
        if (-not ('TrustAllCertsPolicy' -as [type])) {
            Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint point, X509Certificate certificate,
                                      WebRequest request, int problem) { return true; }
}
'@
        }
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
}

function Invoke-Checkmk {
    # Returns Data (the parsed JSON answer) and ETag.
    param([string]$Method, [string]$Path, $Body, [string]$IfMatch)

    $headers = @{ Authorization = "Bearer $User $Secret"; Accept = 'application/json' }
    if ($IfMatch) {
        $headers['If-Match'] = $IfMatch
    }
    $request = @{ Method = $Method; Uri = $ApiUrl + $Path; Headers = $headers }
    if ($null -ne $Body) {
        # As bytes: Windows PowerShell 5.1 would send a string as ISO-8859-1.
        $json = ConvertTo-Json -InputObject $Body -Depth 10 -Compress
        $request['Body'] = [System.Text.Encoding]::UTF8.GetBytes($json)
        $request['ContentType'] = 'application/json; charset=utf-8'
    }
    try {
        $response = Invoke-WebRequest @request @WebOptions
    }
    catch {
        $detail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $detail = $_.ErrorDetails.Message
        }
        throw "$Method $Path failed: $detail"
    }
    # Decode the bytes: Windows PowerShell 5.1 would read the answer as ISO-8859-1.
    $text = [System.Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray())
    $data = $null
    if ($text) {
        $data = ConvertFrom-Json -InputObject $text
    }
    $etag = $null
    if ($response.Headers.ContainsKey('ETag')) {
        $etag = @($response.Headers['ETag'])[0]
    }
    return @{ Data = $data; ETag = $etag }
}

function Get-ConditionList {
    # Returns the values of a rule condition if it is a plain "one of" list.
    param($Conditions, [string]$Name)

    $property = $Conditions.PSObject.Properties[$Name]
    if ($property -and $property.Value -and $property.Value.operator -eq 'one_of') {
        $property.Value.match_on
    }
}

# ---------------------------------------------------------------------------
# 1. Services
# ---------------------------------------------------------------------------

$stateNumber = @{ WARN = '1'; CRIT = '2' }
$stateFilter = @($State | Select-Object -Unique | ForEach-Object {
        @{ op = '='; left = 'state'; right = $stateNumber[$_] }
    })
if ($Group) {
    $filters = @(@{ op = '='; left = 'description'; right = $ServicePrefix + $Group })
}
else {
    $filters = @(@{ op = '~'; left = 'description'; right = '^' + $ServicePrefix })
}
$filters += @{ op = 'or'; expr = $stateFilter }
if ($HostFilter) {
    $filters += @{ op = '~~'; left = 'host_name'; right = $HostFilter }
}
$services = Invoke-Checkmk -Method Post -Path '/domain-types/service/collections/all' -Body @{
    query   = @{ op = 'and'; expr = $filters }
    columns = @('host_name', 'description', 'long_plugin_output')
}

# One entry per host and group: Host, Group, Members (name -> reasons), Skipped.
$proposals = @(foreach ($service in @($services.Data.value)) {
        $entry = $service.extensions
        $members = [ordered]@{}
        $skipped = @()
        foreach ($member in @(Get-ReportedMember $entry.long_plugin_output)) {
            if ($member.Reasons -contains 'unwanted member') {
                $skipped += $member
            }
            else {
                $members[$member.Name] = $member.Reasons -join ', '
            }
        }
        [pscustomobject]@{
            Host    = $entry.host_name
            Group   = $entry.description.Substring($ServicePrefix.Length)
            Members = $members
            Skipped = $skipped
        }
    })

# ---------------------------------------------------------------------------
# 2. Existing rules
# ---------------------------------------------------------------------------

$rules = Invoke-Checkmk -Method Get -Path (
    '/domain-types/rule/collections/all?ruleset_name=' + [uri]::EscapeDataString($Ruleset))
$existingRules = @($rules.Data.value)

function Find-OwnRule {
    # The rules for exactly this host and this group, in the order of evaluation.
    param([string]$HostName, [string]$ItemPattern)

    foreach ($rule in $existingRules) {
        $hosts = @(Get-ConditionList $rule.extensions.conditions 'host_name')
        $items = @(Get-ConditionList $rule.extensions.conditions 'service_description')
        if ($hosts.Count -eq 1 -and $hosts[0] -eq $HostName -and
            $items.Count -eq 1 -and $items[0] -eq $ItemPattern) {
            $rule
        }
    }
}

# ---------------------------------------------------------------------------
# 3. One rule per host and group
# ---------------------------------------------------------------------------

$today = Get-Date -Format 'yyyy-MM-dd'

foreach ($proposal in ($proposals | Sort-Object Host, Group)) {
    $target = '{0} / {1}' -f $proposal.Host, $proposal.Group

    foreach ($member in $proposal.Skipped) {
        [pscustomobject]@{
            Host = $proposal.Host; Group = $proposal.Group; Account = $member.Name
            Reason = $member.Reasons -join ', '; Action = 'skipped: unwanted member'; RuleId = ''
        }
    }
    if ($proposal.Members.Count -eq 0) {
        continue
    }

    $itemPattern = (ConvertTo-RegexLiteral $proposal.Group) + '$'
    $ownRules = @(Find-OwnRule $proposal.Host $itemPattern)
    $disabledRule = $ownRules | Where-Object { $_.extensions.properties.disabled } | Select-Object -First 1
    $enabledRule = $ownRules | Where-Object { -not $_.extensions.properties.disabled } | Select-Object -First 1
    $baseRule = $disabledRule
    if (-not $baseRule) {
        $baseRule = $enabledRule
    }

    $parsed = @{ Found = $false; Items = @() }
    if ($baseRule) {
        $parsed = Get-AllowedAdditional $baseRule.extensions.value_raw
        if ($null -eq $parsed) {
            Write-Warning "${target}: cannot read the value of rule $($baseRule.id), skipped."
            continue
        }
    }

    # -notcontains compares case-insensitively, like the check does.
    $newNames = @($proposal.Members.Keys | Where-Object {
            @($parsed.Items) -notcontains (ConvertTo-RegexLiteral $_)
        })
    $action = 'already in rule'
    $ruleId = ''
    if ($baseRule) {
        $ruleId = $baseRule.id
    }

    if ($newNames.Count -gt 0) {
        $patterns = @($parsed.Items) + @($newNames | ForEach-Object { ConvertTo-RegexLiteral $_ })
        $note = "$today ${ScriptName}: " +
            (($newNames | ForEach-Object { '{0} ({1})' -f $_, $proposal.Members[$_] }) -join '; ')

        if ($disabledRule) {
            # Not reviewed yet: add the new members to it.
            $action = 'added to disabled rule'
            $value = Set-AllowedAdditional $disabledRule.extensions.value_raw $parsed $patterns
            if ($null -eq $value) {
                Write-Warning "${target}: cannot change the value of rule $($disabledRule.id), skipped."
                continue
            }
            if ($PSCmdlet.ShouldProcess($target, "Add $($newNames.Count) member(s) to rule $($disabledRule.id)")) {
                $current = Invoke-Checkmk -Method Get -Path "/objects/rule/$($disabledRule.id)"
                $properties = @{}
                foreach ($property in $current.Data.extensions.properties.PSObject.Properties) {
                    $properties[$property.Name] = $property.Value
                }
                $comment = ''
                if ($properties.ContainsKey('comment')) {
                    $comment = [string]$properties['comment']
                }
                $properties['comment'] = ($comment.TrimEnd() + "`n" + $note).Trim()
                [void](Invoke-Checkmk -Method Put -Path "/objects/rule/$($disabledRule.id)" -IfMatch $current.ETag -Body @{
                        properties = $properties
                        value_raw  = $value
                        conditions = $current.Data.extensions.conditions
                    })
            }
        }
        else {
            $ruleFolder = $Folder
            $action = 'new disabled rule'
            if ($enabledRule) {
                # Already approved: propose a rule with the old and the new members instead.
                $ruleFolder = $enabledRule.extensions.folder
                $action = "new disabled rule, replaces $($enabledRule.id)"
                $note += "`nReplaces rule $($enabledRule.id): enable this rule, then delete the old one."
            }
            $ruleId = ''
            if ($PSCmdlet.ShouldProcess($target, "Create disabled rule with $($newNames.Count) new member(s)")) {
                $created = Invoke-Checkmk -Method Post -Path '/domain-types/rule/collections/all' -Body @{
                    ruleset    = $Ruleset
                    folder     = $ruleFolder
                    properties = @{
                        disabled    = $true
                        description = "Group members: $target"
                        comment     = $note
                    }
                    value_raw  = "{'allowed_additional': $(ConvertTo-PythonList $patterns)}"
                    conditions = @{
                        host_name           = @{ match_on = @($proposal.Host); operator = 'one_of' }
                        service_description = @{ match_on = @($itemPattern); operator = 'one_of' }
                    }
                }
                $ruleId = $created.Data.id
                if ($enabledRule) {
                    # In front of the old rule: the first matching rule wins.
                    [void](Invoke-Checkmk -Method Post -Path "/objects/rule/$ruleId/actions/move/invoke" -Body @{
                            position = 'before_specific_rule'
                            rule_id  = $enabledRule.id
                        })
                }
            }
        }
    }

    foreach ($name in $proposal.Members.Keys) {
        $memberAction = 'already in rule'
        if ($newNames -contains $name) {
            $memberAction = $action
        }
        [pscustomobject]@{
            Host = $proposal.Host; Group = $proposal.Group; Account = $name
            Reason = $proposal.Members[$name]; Action = $memberAction; RuleId = $ruleId
        }
    }
}
