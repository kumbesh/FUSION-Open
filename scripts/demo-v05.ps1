[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9][a-z0-9_-]*$')]
    [string] $ComposeProjectName,

    [string] $LinuxTarget,

    [string] $SuricataSshTarget,

    [string] $SuricataIcmpTarget,

    [switch] $SuricataRuleReady,

    [ValidateRange(15, 600)]
    [int] $DetectionTimeoutSeconds = 120,

    [switch] $PreflightOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

$script:DemoDocker = $null
$script:DemoPassCount = 0
$script:DemoFailCount = 0
$script:DemoSkipCount = 0
$script:DemoDetectionIds = [Collections.Generic.List[string]]::new()
$script:DemoPollSeconds = 5

function Write-DemoResult {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("PASS", "FAIL", "SKIPPED")]
        [string] $Status,

        [Parameter(Mandatory = $true)]
        [string] $Message
    )

    switch ($Status) {
        "PASS" {
            $script:DemoPassCount++
            Write-Host "[PASS] $Message" -ForegroundColor Green
        }
        "FAIL" {
            $script:DemoFailCount++
            Write-Host "[FAIL] $Message" -ForegroundColor Red
        }
        "SKIPPED" {
            $script:DemoSkipCount++
            Write-Host "[SKIPPED] $Message" -ForegroundColor Yellow
        }
    }
}

function ConvertTo-LabIPAddress {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Value,

        [Parameter(Mandatory = $true)]
        [string] $ParameterName
    )

    $address = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref] $address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$ParameterName must be a literal private IPv4 lab address; hostnames, IPv6, and public addresses are not accepted."
    }

    $bytes = $address.GetAddressBytes()
    $isPrivate = $false

    $isPrivate =
        ($bytes[0] -eq 10) -or
        ($bytes[0] -eq 127) -or
        ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31)

    if (-not $isPrivate) {
        throw "$ParameterName must identify an RFC1918, loopback, or link-local IPv4 lab address. Public targets are refused."
    }

    return $address.ToString()
}

function Test-DemoTcpPort {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Target,

        [Parameter(Mandatory = $true)]
        [int] $Port,

        [int] $TimeoutMilliseconds = 3000
    )

    $client = [Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }

        $client.EndConnect($pending)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Invoke-DemoCompose {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $ComposeArguments
    )

    $output = & $script:DemoDocker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile @ComposeArguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $message = ($output | Out-String).Trim()
        throw "docker compose failed with exit code $LASTEXITCODE. $message"
    }

    return $output
}

function Invoke-DemoClickHouseQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Query
    )

    # Credentials remain inside the ClickHouse container. They are neither read
    # from the host .env file nor placed on this process's command line.
    $containerCommand = 'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD"'
    $output = $Query | & $script:DemoDocker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile `
        exec -T clickhouse sh -c $containerCommand 2>&1
    if ($LASTEXITCODE -ne 0) {
        $message = ($output | Out-String).Trim()
        throw "ClickHouse query failed with exit code $LASTEXITCODE. $message"
    }

    return (($output | Out-String).Trim())
}

function Get-DemoComposeRows {
    $rawLines = @(Invoke-DemoCompose ps --format json)
    $raw = ($rawLines -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @()
    }

    try {
        return @($raw | ConvertFrom-Json)
    }
    catch {
        $rows = @()
        foreach ($line in $rawLines) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                $rows += $line | ConvertFrom-Json
            }
        }
        return @($rows)
    }
}

function Assert-DemoServicesHealthy {
    $requiredServices = @("clickhouse", "vector", "fusion-detection-engine", "grafana")
    $rows = @(Get-DemoComposeRows)

    foreach ($service in $requiredServices) {
        $row = @($rows | Where-Object { $_.Service -eq $service } | Select-Object -First 1)
        if ($row.Count -eq 0) {
            throw "Required service '$service' is not present. Start Fusion with .\scripts\deploy.ps1."
        }

        $state = [string] $row[0].State
        $health = [string] $row[0].Health
        $status = [string] $row[0].Status
        if ($state -ne "running") {
            throw "Required service '$service' is '$state', not running."
        }
        if ($health -ne "healthy" -and $status -notmatch '\(healthy\)') {
            throw "Required service '$service' is running but not healthy (health='$health')."
        }
    }
}

function Get-ClickHouseClockMilliseconds {
    $value = Invoke-DemoClickHouseQuery "SELECT toUnixTimestamp64Milli(now64(3)) FORMAT TSVRaw"
    return [long] $value
}

function Wait-DemoJsonRow {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock] $QueryFactory,

        [Parameter(Mandatory = $true)]
        [int] $TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $query = & $QueryFactory
        $json = Invoke-DemoClickHouseQuery $query
        if (-not [string]::IsNullOrWhiteSpace($json)) {
            return ($json | ConvertFrom-Json)
        }

        if ([DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds $script:DemoPollSeconds
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    return $null
}

function Assert-DemoDetectionEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Detection,

        [Parameter(Mandatory = $true)]
        [string] $ExpectedRule,

        [Parameter(Mandatory = $true)]
        [string] $ExpectedSeverity,

        [Parameter(Mandatory = $true)]
        [string] $ExpectedPlatform,

        [string] $ExpectedTechnique,

        [string] $ExpectedTactic
    )

    if ($Detection.rule_id -ne $ExpectedRule) {
        throw "Expected rule '$ExpectedRule'; received '$($Detection.rule_id)'."
    }
    if ($Detection.severity -ne $ExpectedSeverity) {
        throw "Expected severity '$ExpectedSeverity'; received '$($Detection.severity)'."
    }
    if ($Detection.platform -ne $ExpectedPlatform) {
        throw "Expected platform '$ExpectedPlatform'; received '$($Detection.platform)'."
    }
    if ([string] $Detection.source_event_uid -notmatch '^[0-9a-f]{64}$') {
        throw "source_event_uid was missing or malformed."
    }
    if ([string] $Detection.detection_id -notmatch '^[0-9a-f]{64}$') {
        throw "detection_id was missing or malformed."
    }
    if ($ExpectedTechnique -and -not (@($Detection.mitre_technique_ids) -contains $ExpectedTechnique)) {
        throw "Expected MITRE technique '$ExpectedTechnique' was not present."
    }
    if ($ExpectedTactic -and -not (@($Detection.mitre_tactics) -contains $ExpectedTactic)) {
        throw "Expected MITRE tactic '$ExpectedTactic' was not present."
    }
}

function Get-WindowsDemoPrerequisiteError {
    if ($env:OS -ne "Windows_NT") {
        return "The Windows demo must run on the Windows endpoint that has Sysmon and the Fusion Vector agent."
    }

    $sysmon = @(
        Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq "Running" } |
            Select-Object -First 1
    )
    if ($sysmon.Count -eq 0) {
        return "Sysmon/Sysmon64 is not installed and running. Install Sysmon separately before this demo."
    }

    $channelEnabled = $false
    try {
        $channel = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
        $channelEnabled = [bool] $channel.IsEnabled
    }
    catch {
        # Non-administrators may be denied log metadata through Get-WinEvent even
        # while the channel is enabled. wevtutil can confirm that state without
        # reading or changing event records.
        $channelMetadata = & wevtutil.exe gl "Microsoft-Windows-Sysmon/Operational" 2>$null | Out-String
        $channelEnabled = ($LASTEXITCODE -eq 0 -and $channelMetadata -match '(?m)^enabled:\s*true\s*$')
    }
    if (-not $channelEnabled) {
        return "The Microsoft-Windows-Sysmon/Operational channel is unavailable or disabled."
    }

    $agent = Get-Service -Name "FusionVectorAgent" -ErrorAction SilentlyContinue
    if (-not $agent -or $agent.Status -ne "Running") {
        return "FusionVectorAgent is not installed and running on this Windows endpoint."
    }

    return $null
}

function Invoke-WindowsEncodedPowerShellDemo {
    Write-Host ""
    Write-Host "A. Windows encoded PowerShell" -ForegroundColor Cyan

    $prerequisiteError = Get-WindowsDemoPrerequisiteError
    if ($prerequisiteError) {
        Write-DemoResult "FAIL" $prerequisiteError
        return
    }

    if ($PreflightOnly) {
        Write-DemoResult "PASS" "Sysmon, its Operational channel, and FusionVectorAgent are ready. No event was generated."
        return
    }

    try {
        $startedAt = Get-ClickHouseClockMilliseconds
        $marker = "FUSION-V05-WINDOWS-DEMO-$([Guid]::NewGuid().ToString('N'))"
        $payload = "Write-Output '$marker'"
        $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
        $windowsPowerShell = (Get-Command "powershell.exe" -ErrorAction Stop).Source

        & $windowsPowerShell -NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedPayload *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "The harmless encoded PowerShell process exited with code $LASTEXITCODE."
        }

        $queryFactory = {
            @"
SELECT
    rule_id, severity, platform, host_name, mitre_tactics, mitre_technique_ids,
    source_event_uid, detection_id
FROM fusion.detections FINAL
WHERE rule_id = 'fusion-windows-encoded-powershell'
  AND toUnixTimestamp64Milli(detected_at) >= $startedAt
  AND position(command_line, '$encodedPayload') > 0
ORDER BY detected_at DESC
LIMIT 1
FORMAT JSONEachRow
"@
        }
        $detection = Wait-DemoJsonRow $queryFactory $DetectionTimeoutSeconds
        if (-not $detection) {
            throw "No matching detection appeared within $DetectionTimeoutSeconds seconds. Check Sysmon Event ID 1, FusionVectorAgent, and detection-engine logs."
        }

        Assert-DemoDetectionEvidence $detection `
            "fusion-windows-encoded-powershell" "high" "windows" "T1059.001" "Execution"
        [void] $script:DemoDetectionIds.Add([string] $detection.detection_id)
        Write-DemoResult "PASS" "fusion-windows-encoded-powershell detected with MITRE T1059.001."
    }
    catch {
        Write-DemoResult "FAIL" $_.Exception.Message
    }
}

function Invoke-LinuxFailedSshDemo {
    Write-Host ""
    Write-Host "B. Linux failed SSH authentication" -ForegroundColor Cyan

    if ([string]::IsNullOrWhiteSpace($LinuxTarget)) {
        Write-DemoResult "SKIPPED" "No -LinuxTarget was supplied. See docs/demo-v05.md for the one-attempt lab procedure."
        return
    }

    try {
        $target = ConvertTo-LabIPAddress $LinuxTarget "LinuxTarget"
    }
    catch {
        Write-DemoResult "FAIL" $_.Exception.Message
        return
    }

    $ssh = Get-Command "ssh.exe" -ErrorAction SilentlyContinue
    if (-not $ssh) {
        $ssh = Get-Command "ssh" -ErrorAction SilentlyContinue
    }
    if (-not $ssh) {
        Write-DemoResult "SKIPPED" "OpenSSH client is unavailable. Install it explicitly, then rerun with -LinuxTarget $target."
        return
    }
    if (-not (Test-DemoTcpPort $target 22)) {
        Write-DemoResult "SKIPPED" "TCP 22 is not reachable at $target. Start SSH in the isolated Linux lab and verify VMware/Hyper-V networking."
        return
    }

    if ($PreflightOnly) {
        Write-DemoResult "PASS" "OpenSSH is available and TCP 22 is reachable at $target. No authentication was attempted."
        return
    }

    $knownHostsPath = [IO.Path]::GetTempFileName()
    try {
        $startedAt = Get-ClickHouseClockMilliseconds
        Write-Host "Enter one intentionally incorrect lab password at the SSH prompt. Do not retry it." -ForegroundColor Yellow

        $sshArguments = @(
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "ConnectionAttempts=1",
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=$knownHostsPath",
            "-o", "LogLevel=ERROR",
            "definitely-not-a-user@$target",
            "true"
        )

        & $ssh.Source @sshArguments
        $sshExitCode = $LASTEXITCODE
        if ($sshExitCode -eq 0) {
            throw "The deliberately invalid account authenticated unexpectedly; the required failed-authentication event was not produced."
        }

        $queryFactory = {
            @"
SELECT
    rule_id, severity, platform, host_name, mitre_tactics, mitre_technique_ids,
    source_event_uid, detection_id
FROM fusion.detections FINAL
WHERE rule_id = 'fusion-linux-authentication-failure'
  AND user_name = 'definitely-not-a-user'
  AND toUnixTimestamp64Milli(detected_at) >= $startedAt
ORDER BY detected_at DESC
LIMIT 1
FORMAT JSONEachRow
"@
        }
        $detection = Wait-DemoJsonRow $queryFactory $DetectionTimeoutSeconds
        if (-not $detection) {
            throw "The single failed login produced no detection within $DetectionTimeoutSeconds seconds. Check sshd/journald and the Linux Fusion agent."
        }

        Assert-DemoDetectionEvidence $detection `
            "fusion-linux-authentication-failure" "low" "linux" "T1110" "Credential Access"
        [void] $script:DemoDetectionIds.Add([string] $detection.detection_id)
        Write-DemoResult "PASS" "fusion-linux-authentication-failure detected with MITRE T1110 after one controlled attempt."
    }
    catch {
        Write-DemoResult "FAIL" $_.Exception.Message
    }
    finally {
        Remove-Item -LiteralPath $knownHostsPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-SuricataSshParts {
    if ($SuricataSshTarget -notmatch '^([A-Za-z_][A-Za-z0-9._-]*)@(.+)$') {
        throw "SuricataSshTarget must use user@private-ip form."
    }

    $user = $matches[1]
    $target = ConvertTo-LabIPAddress $matches[2] "SuricataSshTarget"
    return [PSCustomObject]@{
        User = $user
        Target = $target
        Destination = "$user@$target"
    }
}

function Invoke-SuricataControlledAlertDemo {
    Write-Host ""
    Write-Host "C. Suricata controlled acceptance alert" -ForegroundColor Cyan

    if (-not $SuricataRuleReady) {
        Write-DemoResult "SKIPPED" "-SuricataRuleReady was not supplied. Prepare and validate SID 9000001 only as documented in docs/demo-v05.md."
        return
    }
    if ([string]::IsNullOrWhiteSpace($SuricataSshTarget) -or [string]::IsNullOrWhiteSpace($SuricataIcmpTarget)) {
        Write-DemoResult "FAIL" "-SuricataRuleReady requires both -SuricataSshTarget user@private-ip and -SuricataIcmpTarget private-ip."
        return
    }

    try {
        $sshParts = Get-SuricataSshParts
        $icmpTarget = ConvertTo-LabIPAddress $SuricataIcmpTarget "SuricataIcmpTarget"
    }
    catch {
        Write-DemoResult "FAIL" $_.Exception.Message
        return
    }

    $ssh = Get-Command "ssh.exe" -ErrorAction SilentlyContinue
    if (-not $ssh) {
        $ssh = Get-Command "ssh" -ErrorAction SilentlyContinue
    }
    if (-not $ssh) {
        Write-DemoResult "SKIPPED" "OpenSSH client is unavailable. Install it explicitly before the Suricata lab demo."
        return
    }
    if (-not (Test-DemoTcpPort $sshParts.Target 22)) {
        Write-DemoResult "SKIPPED" "TCP 22 is not reachable at $($sshParts.Target). Check isolated-lab networking."
        return
    }

    if ($PreflightOnly) {
        Write-DemoResult "PASS" "OpenSSH is available and TCP 22 is reachable at $($sshParts.Target). No SSH session or ICMP request was made."
        return
    }

    $knownHostsPath = [IO.Path]::GetTempFileName()
    $sshBaseArguments = @(
        "-o", "BatchMode=yes",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "ConnectionAttempts=1",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=$knownHostsPath",
        "-o", "LogLevel=ERROR"
    )

    try {
        & $ssh.Source @sshBaseArguments $sshParts.Destination `
            "command -v ping >/dev/null 2>&1 && systemctl is-active --quiet suricata && systemctl is-active --quiet fusion-suricata-vector"
        if ($LASTEXITCODE -ne 0) {
            Write-DemoResult "SKIPPED" "Key-based SSH, ping, Suricata, or fusion-suricata-vector is unavailable. Complete the prerequisites in docs/demo-v05.md."
            return
        }

        $startedAt = Get-ClickHouseClockMilliseconds
        & $ssh.Source @sshBaseArguments $sshParts.Destination `
            "ping -I $($sshParts.Target) -c 1 -W 3 -- $icmpTarget >/dev/null 2>&1"
        $pingExitCode = $LASTEXITCODE
        if ($pingExitCode -gt 1) {
            throw "The remote ping command could not run (exit $pingExitCode). No acceptance packet was confirmed."
        }

        $eveQueryFactory = {
            @"
SELECT event_uid, host_name, signature, signature_id
FROM fusion.sysmon_events
WHERE source_type = 'suricata_eve'
  AND event_kind = 'alert'
  AND signature_id = '9000001'
  AND startsWith(signature, 'FUSION TEST')
  AND protocol = 'icmp'
  AND ((source_ip = '$($sshParts.Target)' AND destination_ip = '$icmpTarget')
    OR (source_ip = '$icmpTarget' AND destination_ip = '$($sshParts.Target)'))
  AND toUnixTimestamp64Milli(ingested_at) >= $startedAt
ORDER BY ingested_at DESC
LIMIT 1
FORMAT JSONEachRow
"@
        }
        $eveEvent = Wait-DemoJsonRow $eveQueryFactory $DetectionTimeoutSeconds
        if (-not $eveEvent) {
            throw "No new SID 9000001 EVE alert reached Fusion within $DetectionTimeoutSeconds seconds. Inspect /var/log/suricata/eve.json and the Suricata Vector service."
        }
        if ([string] $eveEvent.event_uid -notmatch '^[0-9a-f]{64}$') {
            throw "The stored EVE alert has a missing or malformed event_uid."
        }
        Write-DemoResult "PASS" "A new Suricata EVE alert for local SID 9000001 reached Fusion storage."

        $detectionQueryFactory = {
            @"
SELECT
    rule_id, severity, platform, host_name, mitre_tactics, mitre_technique_ids,
    source_event_uid, detection_id
FROM fusion.detections FINAL
WHERE rule_id = 'fusion-network-controlled-suricata-signature'
  AND source_event_uid = '$($eveEvent.event_uid)'
  AND signature_id = '9000001'
  AND startsWith(signature, 'FUSION TEST')
  AND toUnixTimestamp64Milli(detected_at) >= $startedAt
ORDER BY detected_at DESC
LIMIT 1
FORMAT JSONEachRow
"@
        }
        $detection = Wait-DemoJsonRow $detectionQueryFactory $DetectionTimeoutSeconds
        if (-not $detection) {
            throw "The EVE alert was stored, but no Fusion detection appeared within $DetectionTimeoutSeconds seconds."
        }

        Assert-DemoDetectionEvidence $detection `
            "fusion-network-controlled-suricata-signature" "medium" "network" $null "Command and Control"
        [void] $script:DemoDetectionIds.Add([string] $detection.detection_id)
        Write-DemoResult "PASS" "fusion-network-controlled-suricata-signature detected the controlled real alert."
    }
    catch {
        Write-DemoResult "FAIL" $_.Exception.Message
    }
    finally {
        Remove-Item -LiteralPath $knownHostsPath -Force -ErrorAction SilentlyContinue
    }
}

function Show-DemoDetections {
    if ($script:DemoDetectionIds.Count -eq 0) {
        return
    }

    $quotedIds = @($script:DemoDetectionIds | ForEach-Object { "'$_'" }) -join ","
    $query = @"
SELECT
    rule_id,
    severity,
    platform,
    host_name,
    mitre_technique_ids,
    source_event_uid,
    detection_id
FROM fusion.detections FINAL
WHERE detection_id IN ($quotedIds)
ORDER BY detected_at ASC
FORMAT PrettyCompactMonoBlock
"@

    Write-Host ""
    Write-Host "Resulting Fusion detections" -ForegroundColor Cyan
    Write-Host (Invoke-DemoClickHouseQuery $query)
}

$composeProjectWasSet = Test-Path Env:COMPOSE_PROJECT_NAME
$previousComposeProject = $env:COMPOSE_PROJECT_NAME
$demoExitCode = 0

try {
    if ($PSBoundParameters.ContainsKey("ComposeProjectName")) {
        $env:COMPOSE_PROJECT_NAME = $ComposeProjectName
    }

    Write-Host "Fusion v0.5 repeatable detection demo" -ForegroundColor Cyan
    if ($env:COMPOSE_PROJECT_NAME) {
        Write-Host "Compose project: $($env:COMPOSE_PROJECT_NAME)"
    }
    else {
        Write-Host "Compose project: current Compose default (fusion)"
    }
    if ($PreflightOnly) {
        Write-Host "Mode: preflight only; no controlled detection event will be generated."
    }

    try {
        $script:DemoDocker = Get-FusionDocker
        & $script:DemoDocker compose version *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Docker Compose is unavailable."
        }
        Assert-FusionEngine
        Assert-DemoServicesHealthy
        Invoke-DemoClickHouseQuery "SELECT 1 FORMAT TSVRaw" | Out-Null
        Write-DemoResult "PASS" "Docker Compose and all four Fusion services are running and healthy."
    }
    catch {
        Write-DemoResult "FAIL" $_.Exception.Message
        throw "Required Fusion infrastructure validation failed."
    }

    Invoke-WindowsEncodedPowerShellDemo
    Invoke-LinuxFailedSshDemo
    Invoke-SuricataControlledAlertDemo

    if (-not $PreflightOnly) {
        try {
            Show-DemoDetections
        }
        catch {
            Write-DemoResult "FAIL" "Could not display the resulting detections: $($_.Exception.Message)"
        }
    }
}
catch {
    if ($script:DemoFailCount -eq 0) {
        Write-DemoResult "FAIL" $_.Exception.Message
    }
}
finally {
    if ($SuricataRuleReady) {
        Write-Host "IMPORTANT: restore the temporary Suricata local rule using the mandatory cleanup in docs/demo-v05.md." -ForegroundColor Yellow
    }

    if ($composeProjectWasSet) {
        $env:COMPOSE_PROJECT_NAME = $previousComposeProject
    }
    else {
        Remove-Item Env:COMPOSE_PROJECT_NAME -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "Summary: PASS=$($script:DemoPassCount) FAIL=$($script:DemoFailCount) SKIPPED=$($script:DemoSkipCount)"
    if ($script:DemoFailCount -gt 0) {
        $demoExitCode = 1
    }
}

exit $demoExitCode
