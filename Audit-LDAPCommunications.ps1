#Requires -Version 5.1
<#
.SYNOPSIS
    Audits LDAP/LDAPS communications from Windows Firewall event logs.

.DESCRIPTION
    Parses Windows Filtering Platform Connection Permitted events (Event ID 5156) to identify:
      - Client IP addresses communicating with domain controllers over secure LDAP ports
      - Domain controllers not observed handling any secure LDAP (636/3269) traffic

    Two subnet-scoping modes are available (mutually exclusive):
      ExcludedSubnetPath (default) - audit all clients EXCEPT those inside specified subnets
      IncludedSubnetPath           - audit only clients INSIDE specified subnets

    Two event log source modes are available (mutually exclusive):
      Path (default) - read from a pre-exported .evtx file
      LogName        - query a live Windows event log by name

    The event log file is read exactly once. Event property values are accessed by index
    rather than per-event XML deserialisation for maximum throughput on large log files.

.PARAMETER EventId
    Windows Filtering Platform event ID to parse. Defaults to 5156
    (Filtering Platform Connection Permitted).

.PARAMETER ExcludedIPPath
    Path to a newline-delimited list of individual DC IP addresses.
    Lines beginning with '#' and blank lines are ignored.

.PARAMETER ExcludedSubnetPath
    Path to a newline-delimited text file of CIDR subnets. Client IPs that fall within
    any listed subnet are excluded from results. Mutually exclusive with IncludedSubnetPath.

    File syntax:
      - One CIDR range per line in the format <address>/<prefix-length>
      - Lines beginning with '#' and blank lines are ignored

    Example file contents:
      # Corporate headquarters
      10.0.0.0/8
      192.168.1.0/24
      172.16.32.0/20

.PARAMETER IncludedSubnetPath
    Path to a newline-delimited text file of CIDR subnets. Only client IPs that fall within
    at least one listed subnet are included in results. Mutually exclusive with ExcludedSubnetPath.

    File syntax:
      - One CIDR range per line in the format <address>/<prefix-length>
      - Lines beginning with '#' and blank lines are ignored

    Example file contents:
      # Branch office range
      10.10.0.0/16
      192.168.50.0/24

.PARAMETER Path
    Path to the .evtx event log file to analyse. Mutually exclusive with -LogName.

.PARAMETER LogName
    Name of a live Windows event log to query (e.g. 'Security' or
    'ForwardedEvents'). Mutually exclusive with -Path.

    Note: querying a live log may be significantly slower than using a
    pre-exported .evtx file, particularly on busy domain controllers where
    the Security log is large and actively being written to.

.PARAMETER LdapsPorts
    Destination port numbers considered secure LDAP. Defaults to 636 and 3269.
    Pass an empty array (@()) to skip port filtering when the EVTX is already pre-filtered.

.PARAMETER PassThru
    Emit the structured [LdapAuditResult] object to the pipeline instead of the
    formatted console report.  Useful for downstream processing or export.
    When specified, the console report is suppressed.

.EXAMPLE
    .\Audit-LDAPCommunications.ps1

    Runs with defaults: ExcludeSubnets.txt, ExcludeDCIPs.txt, ForwardedEvents.evtx.

.EXAMPLE
    .\Audit-LDAPCommunications.ps1 -IncludedSubnetPath C:\LDAPAudit\IncludeSubnets.txt

    Scopes results to clients inside the specified subnets.

.EXAMPLE
    .\Audit-LDAPCommunications.ps1 -LogName Security

    Queries the live Security log on the local machine instead of an .evtx file.
    A performance warning is emitted before querying begins.

.EXAMPLE
    $result = .\Audit-LDAPCommunications.ps1 -PassThru
    $result.ClientIPs | Export-Csv -Path .\LdapClients.csv -NoTypeInformation

    Captures the structured result object and exports the client IP list.

.OUTPUTS
    PSCustomObject  - emitted only when -PassThru is specified.
    TypeName: LdapAuditResult
#>

[CmdletBinding(DefaultParameterSetName = 'ExcludedSubnetFilePath')]
param (
    [ValidateRange(1, 65535)]
    [int] $EventId = 5156,

    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { $true }
        else { throw "File not found: $_" }
    })]
    [string] $ExcludedIPPath = (Join-Path $PSScriptRoot 'ExcludeDCIPs.txt'),

    [Parameter(ParameterSetName = 'ExcludedSubnetFilePath')]
    [Parameter(ParameterSetName = 'ExcludedSubnetLiveLog')]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { $true }
        else { throw "File not found: $_" }
    })]
    [string] $ExcludedSubnetPath = (Join-Path $PSScriptRoot 'ExcludeSubnets.txt'),

    [Parameter(ParameterSetName = 'IncludedSubnetFilePath')]
    [Parameter(ParameterSetName = 'IncludedSubnetLiveLog')]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { $true }
        else { throw "File not found: $_" }
    })]
    [string] $IncludedSubnetPath = (Join-Path $PSScriptRoot 'IncludeSubnets.txt'),

    [Parameter(ParameterSetName = 'ExcludedSubnetFilePath')]
    [Parameter(ParameterSetName = 'IncludedSubnetFilePath')]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { $true }
        else { throw "File not found: $_" }
    })]
    [string] $Path = (Join-Path $PSScriptRoot 'ForwardedEvents.evtx'),

    [Parameter(ParameterSetName = 'ExcludedSubnetLiveLog', Mandatory)]
    [Parameter(ParameterSetName = 'IncludedSubnetLiveLog', Mandatory)]
    [string] $LogName,

    [int[]]  $LdapsPorts = @(636, 3269),

    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region HelperFunctions

function ConvertTo-DecimalIP {
    <#
    .SYNOPSIS
        Converts an IPAddress into an unsigned 32-bit integer.
    #>
    [CmdletBinding()]
    [OutputType([UInt32])]
    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [IPAddress]$IPAddress
    )
    process {
        [UInt32]([IPAddress]::HostToNetworkOrder($IPAddress.Address) -shr 32 -band [UInt32]::MaxValue)
    }
}

function ConvertToNetwork {
    <#
    .SYNOPSIS
        Normalises IP/subnet input into a consistent network descriptor object.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string] $IPAddress,

        [Parameter(Position = 1)]
        [AllowNull()]
        [string] $SubnetMask
    )

    $validSubnetMaskValues = @(
        '0.0.0.0',       '128.0.0.0',     '192.0.0.0',     '224.0.0.0',
        '240.0.0.0',     '248.0.0.0',     '252.0.0.0',     '254.0.0.0',
        '255.0.0.0',     '255.128.0.0',   '255.192.0.0',   '255.224.0.0',
        '255.240.0.0',   '255.248.0.0',   '255.252.0.0',   '255.254.0.0',
        '255.255.0.0',   '255.255.128.0', '255.255.192.0', '255.255.224.0',
        '255.255.240.0', '255.255.248.0', '255.255.252.0', '255.255.254.0',
        '255.255.255.0',     '255.255.255.128', '255.255.255.192',
        '255.255.255.224',   '255.255.255.240', '255.255.255.248',
        '255.255.255.252',   '255.255.255.254', '255.255.255.255'
    )

    $network = [PSCustomObject]@{
        IPAddress  = $null
        SubnetMask = $null
        MaskLength = 0
    }
    $network | Add-Member -MemberType ScriptMethod -Name ToString -Force -Value {
        '{0}/{1}' -f $this.IPAddress, $this.MaskLength
    }

    if (-not $PSBoundParameters.ContainsKey('SubnetMask') -or $SubnetMask -eq '') {
        $IPAddress, $SubnetMask = $IPAddress.Split([char[]]'\/ ', [StringSplitOptions]::RemoveEmptyEntries)
    }

    while ($IPAddress.Split('.').Count -lt 4) { $IPAddress += '.0' }

    if ([IPAddress]::TryParse($IPAddress, [ref]$null)) {
        $network.IPAddress = [IPAddress]$IPAddress
    }
    else {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [ArgumentException]'Invalid IP address.',
                'InvalidIPAddress',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $IPAddress
            )
        )
    }

    if ($null -eq $SubnetMask -or $SubnetMask -eq '') {
        $network.SubnetMask = [IPAddress]$validSubnetMaskValues[32]
        $network.MaskLength = 32
    }
    else {
        $maskLength = 0
        if ([int32]::TryParse($SubnetMask, [ref]$maskLength)) {
            if ($maskLength -ge 0 -and $maskLength -le 32) {
                $network.SubnetMask = [IPAddress]$validSubnetMaskValues[$maskLength]
                $network.MaskLength = $maskLength
            }
            else {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [ArgumentException]'Mask length out of range (expecting 0 to 32).',
                        'InvalidMaskLength',
                        [System.Management.Automation.ErrorCategory]::InvalidArgument,
                        $SubnetMask
                    )
                )
            }
        }
        else {
            while ($SubnetMask.Split('.').Count -lt 4) { $SubnetMask += '.0' }
            $maskLength = $validSubnetMaskValues.IndexOf($SubnetMask)
            if ($maskLength -ge 0) {
                $network.SubnetMask = [IPAddress]$SubnetMask
                $network.MaskLength = $maskLength
            }
            else {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [ArgumentException]'Invalid subnet mask.',
                        'InvalidSubnetMask',
                        [System.Management.Automation.ErrorCategory]::InvalidArgument,
                        $SubnetMask
                    )
                )
            }
        }
    }

    $network
}

function Get-NetworkRange {
    <#
    .SYNOPSIS
        Enumerates individual IP addresses within a CIDR range or start/end pair.
    .EXAMPLE
        Get-NetworkRange '192.168.1.0/24'
    .EXAMPLE
        Get-NetworkRange '10.0.0.0' '255.255.0.0'
    #>
    [CmdletBinding(DefaultParameterSetName = 'FromIPAndMask')]
    [OutputType([IPAddress])]
    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = 'FromIPAndMask')]
        [string] $IPAddress,

        [Parameter(Position = 1, ParameterSetName = 'FromIPAndMask')]
        [string] $SubnetMask,

        [Parameter(ParameterSetName = 'FromIPAndMask')]
        [switch] $IncludeNetworkAndBroadcast,

        [Parameter(Mandatory, ParameterSetName = 'FromStartAndEnd')]
        [IPAddress] $Start,

        [Parameter(Mandatory, ParameterSetName = 'FromStartAndEnd')]
        [IPAddress] $End
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'FromIPAndMask') {
            try {
                $null = $PSBoundParameters.Remove('IncludeNetworkAndBroadcast')
                $network = ConvertToNetwork @PSBoundParameters
            }
            catch {
                $PSCmdlet.ThrowTerminatingError($_)
            }
            $decimalIP    = ConvertTo-DecimalIP $network.IPAddress
            $decimalMask  = ConvertTo-DecimalIP $network.SubnetMask
            $startDecimal = $decimalIP -band $decimalMask
            $endDecimal   = $decimalIP -bor (-bnot $decimalMask -band [UInt32]::MaxValue)
            if (-not $IncludeNetworkAndBroadcast) {
                $startDecimal++
                $endDecimal--
            }
        }
        else {
            $startDecimal = ConvertTo-DecimalIP $Start
            $endDecimal   = ConvertTo-DecimalIP $End
        }

        for ($i = $startDecimal; $i -le $endDecimal; $i++) {
            [IPAddress]([IPAddress]::NetworkToHostOrder([Int64]$i) -shr 32 -band [UInt32]::MaxValue)
        }
    }
}

#endregion HelperFunctions

#region DataProcessing

function Invoke-LdapAudit {
    <#
    .SYNOPSIS
        Performs a single-pass analysis of LDAP event data and returns a structured result.

    .DESCRIPTION
        Reads the event log once, collecting source/destination addresses and DC-involved
        connection pairs. Subnet filtering and DC-activity analysis are then performed
        in memory, eliminating the second event log read present in the original script.

        Performance characteristics:
          - Event properties are accessed by positional index to avoid [xml] deserialisation
            overhead per event. Assumes Event ID 5156 property layout:
              [0] ProcessID  [1] Application  [2] Direction
              [3] SourceAddress  [4] SourcePort  [5] DestAddress  [6] DestPort
          - All IP/subnet lookups use HashSet<string> for O(1) membership tests.
          - Only DC-involved connection pairs are stored in memory; client-only pairs
            are irrelevant to the DC-activity check and are discarded.

    .OUTPUTS
        PSCustomObject  (TypeName: LdapAuditResult)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)] [string]   $EventLogPath,
        [Parameter(Mandatory)] [string]   $FilterXPath,
        [Parameter(Mandatory)] [string[]] $DcIpList,
        [Parameter(Mandatory)] [string[]] $SubnetIpList,
        [Parameter(Mandatory)]
        [ValidateSet('Exclude', 'Include')]
                               [string]   $SubnetFilterMode,
                               [int[]]    $LdapsPorts = @(),
                               [switch]   $IsLiveLog
    )

    # Build O(1) lookup structures
    $dcHashSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$DcIpList, [StringComparer]::OrdinalIgnoreCase)

    $subnetHashSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$SubnetIpList, [StringComparer]::OrdinalIgnoreCase)

    # Store ports as int to match the UInt16 value from event Properties
    $portHashSet = [System.Collections.Generic.HashSet[int]]::new([int[]]$LdapsPorts)

    # Single-pass event log read
    $allAddresses      = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $dcConnectionPairs = [System.Collections.Generic.List[System.Tuple[string, string]]]::new()
    $eventCount        = 0

    try {
        if ($IsLiveLog) {
            Write-Warning "Querying a live event log may be significantly slower than using a pre-exported .evtx file, particularly on busy domain controllers where the log is large and actively being written to."
            $winEvents = Get-WinEvent -LogName $EventLogPath -FilterXPath $FilterXPath -ErrorAction Stop
        }
        else {
            $winEvents = Get-WinEvent -Path $EventLogPath -FilterXPath $FilterXPath -ErrorAction Stop
        }
    }
    catch {
        if ($_.Exception.Message -like '*No events*') {
            Write-Warning "No events matching the XPath filter were found in '$EventLogPath'."
            $winEvents = [object[]]@()
        }
        else {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }

    foreach ($wfpEvent in $winEvents) {
        # Index-based property access - avoids [xml] round-trip for every event.
        # Event 5156: [3] SourceAddress  [4] SourcePort  [5] DestAddress  [6] DestPort
        $srcAddr  = [string]$wfpEvent.Properties[3].Value
        $destAddr = [string]$wfpEvent.Properties[5].Value
        $destPort = [int]$wfpEvent.Properties[6].Value

        # Port filter - skipped when portHashSet is empty (no port restriction)
        if ($portHashSet.Count -gt 0 -and -not $portHashSet.Contains($destPort)) { continue }

        $eventCount++
        if ($srcAddr)  { [void]$allAddresses.Add($srcAddr) }
        if ($destAddr) { [void]$allAddresses.Add($destAddr) }

        # Retain only pairs where a monitored DC is involved
        if ($dcHashSet.Contains($destAddr) -or $dcHashSet.Contains($srcAddr)) {
            [void]$dcConnectionPairs.Add([System.Tuple]::Create($destAddr, $srcAddr))
        }
    }

    Write-Verbose "Events matched (after port filter): $eventCount"

    # Apply subnet filter to produce the set of client IPs
    $clientIPs = [System.Collections.Generic.HashSet[string]]::new(
        $allAddresses, [StringComparer]::OrdinalIgnoreCase)

    if ($SubnetFilterMode -eq 'Exclude') {
        # Remove excluded IPs (subnets + explicit DC IPs are combined before being passed in)
        $clientIPs.ExceptWith($subnetHashSet)
    }
    else {
        # Retain only IPs within the specified subnets, then strip DC IPs
        $clientIPs.IntersectWith($subnetHashSet)
        $clientIPs.ExceptWith($dcHashSet)
    }

    Write-Verbose "Unique client IPs after subnet filter: $($clientIPs.Count)"

    # Identify active DCs (communicated with at least one client IP)
    $activeDcIPs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($pair in $dcConnectionPairs) {
        if ($clientIPs.Contains($pair.Item1) -or $clientIPs.Contains($pair.Item2)) {
            if ($dcHashSet.Contains($pair.Item1)) { [void]$activeDcIPs.Add($pair.Item1) }
            if ($dcHashSet.Contains($pair.Item2)) { [void]$activeDcIPs.Add($pair.Item2) }
        }
    }

    # Collect DCs absent from secure LDAP traffic
    $inactiveDcs = [System.Collections.Generic.List[string]]::new()
    foreach ($dcIp in $DcIpList) {
        if (-not $activeDcIPs.Contains($dcIp)) { $inactiveDcs.Add($dcIp) }
    }

    # Return pure data - no Write-Host, no formatting
    [PSCustomObject]@{
        PSTypeName       = 'LdapAuditResult'
        EventLogPath     = $EventLogPath
        SubnetFilterMode = $SubnetFilterMode
        LdapsPorts       = $LdapsPorts
        EventsProcessed  = $eventCount
        ClientIPs        = [string[]]($clientIPs   | Sort-Object { [version]$_ })
        ClientIPCount    = $clientIPs.Count
        InactiveDcs      = [string[]]($inactiveDcs | Sort-Object { [version]$_ })
        InactiveDcCount  = $inactiveDcs.Count
        ActiveDcCount    = $activeDcIPs.Count
        TotalDcCount     = $DcIpList.Count
    }
}

#endregion DataProcessing

#region FormattedOutput

function Write-LdapAuditReport {
    <#
    .SYNOPSIS
        Renders a human-readable LDAP audit report to the host.

    .DESCRIPTION
        Accepts an [LdapAuditResult] object from Invoke-LdapAudit and writes a structured
        console report using Write-Host.  No pipeline output is emitted by this function;
        pipeline output is the caller's responsibility.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject] $AuditResult
    )
    process {
        $hr         = '-' * 64
        $portsLabel = if ($AuditResult.LdapsPorts.Count -gt 0) {
            ($AuditResult.LdapsPorts | Sort-Object) -join '/'
        }
        else { 'all ports' }

        Write-Host ''
        Write-Host $hr -ForegroundColor DarkCyan
        Write-Host ('  LDAP Communications Audit  {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
        Write-Host $hr -ForegroundColor DarkCyan
        Write-Host ('  Log Source    : {0}' -f $AuditResult.EventLogPath)
        Write-Host ('  Filter Mode   : {0}' -f $AuditResult.SubnetFilterMode)
        Write-Host ('  Ports Scoped  : {0}' -f $portsLabel)
        Write-Host ('  Events Parsed : {0:N0}' -f $AuditResult.EventsProcessed)

        # Client IPs section
        Write-Host ''
        Write-Host $hr -ForegroundColor DarkCyan
        Write-Host ('  Client IPs on port {0}  [{1} unique addresses]' -f $portsLabel, $AuditResult.ClientIPCount) -ForegroundColor Yellow
        Write-Host $hr -ForegroundColor DarkCyan

        if ($AuditResult.ClientIPCount -gt 0) {
            $AuditResult.ClientIPs | ForEach-Object { Write-Host ('    {0}' -f $_) }
        }
        else {
            Write-Host '    (no client IPs matched the filter criteria)' -ForegroundColor DarkGray
        }

        # DC status section
        Write-Host ''
        Write-Host $hr -ForegroundColor DarkCyan
        $dcStatusColor = if ($AuditResult.InactiveDcCount -gt 0) { 'Red' } else { 'Green' }
        Write-Host (
            '  DCs with NO observed LDAPS/{0} traffic  [{1} of {2} monitored DCs]' -f
            $portsLabel, $AuditResult.InactiveDcCount, $AuditResult.TotalDcCount
        ) -ForegroundColor $dcStatusColor
        Write-Host $hr -ForegroundColor DarkCyan

        if ($AuditResult.InactiveDcCount -gt 0) {
            $AuditResult.InactiveDcs | ForEach-Object {
                Write-Host ('    {0}' -f $_) -ForegroundColor Red
            }
        }
        else {
            Write-Host '    All monitored DCs observed handling secure LDAP traffic.' -ForegroundColor Green
        }

        Write-Host $hr -ForegroundColor DarkCyan
        Write-Host ''
    }
}

#endregion FormattedOutput

# Main

# Load DC IP list - blank lines and comment lines are stripped
[string[]]$dcIpList = Get-Content -Path $ExcludedIPPath |
    Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }

Write-Verbose "DC IPs loaded: $($dcIpList.Count) entries from '$ExcludedIPPath'"

# Expand subnet file to individual IP strings and build the appropriate filter set
if ($PSCmdlet.ParameterSetName -in 'ExcludedSubnetFilePath', 'ExcludedSubnetLiveLog') {
    Write-Verbose "Subnet mode: Exclude  ('$ExcludedSubnetPath')"

    [string[]]$subnetIPs = Get-Content -Path $ExcludedSubnetPath |
        Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' } |
        Get-NetworkRange -IncludeNetworkAndBroadcast |
        ForEach-Object { $_.IPAddressToString }

    # Merge explicit DC IPs into the exclusion set (preserves original behaviour)
    $subnetIPs  += $dcIpList
    $filterMode  = 'Exclude'

    Write-Verbose "Exclusion IP set size (subnets + DC IPs): $($subnetIPs.Count)"
}
else {
    Write-Verbose "Subnet mode: Include  ('$IncludedSubnetPath')"

    [string[]]$subnetIPs = Get-Content -Path $IncludedSubnetPath |
        Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' } |
        Get-NetworkRange -IncludeNetworkAndBroadcast |
        ForEach-Object { $_.IPAddressToString }

    $filterMode = 'Include'

    Write-Verbose "Inclusion IP set size: $($subnetIPs.Count)"
}

$filterXPath = "*/System/EventID=$EventId"

$isLiveLog  = $PSCmdlet.ParameterSetName -like '*LiveLog*'
$logSource  = if ($isLiveLog) { $LogName } else { $Path }

# Compute (pure data, no formatting)
$auditResult = Invoke-LdapAudit `
    -EventLogPath     $logSource `
    -FilterXPath      $filterXPath `
    -DcIpList         $dcIpList `
    -SubnetIpList     $subnetIPs `
    -SubnetFilterMode $filterMode `
    -LdapsPorts       $LdapsPorts `
    -IsLiveLog:$isLiveLog `
    -Verbose:($VerbosePreference -ne 'SilentlyContinue')

# Format and display (suppressed when -PassThru is set)
if (-not $PassThru) { $auditResult | Write-LdapAuditReport }

# Optional pipeline output
if ($PassThru) { $auditResult }
