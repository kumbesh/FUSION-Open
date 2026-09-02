[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot "FusionAgent.Common.ps1")

$service = Get-FusionAgentService
if (-not $service) {
    Write-Host "Service: not installed"
    exit 1
}

$service.Refresh()
Write-Host "Service: $($service.Status)"
Write-Host "Configuration: $script:FusionAgentConfig"
if (Test-Path -LiteralPath $script:FusionAgentMetadata) {
    $metadata = Get-Content -LiteralPath $script:FusionAgentMetadata -Raw | ConvertFrom-Json
    Write-Host "Collector: $($metadata.collector_url)"
}

$sysmon = Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Host "Sysmon: $(if ($sysmon) { $sysmon.Status } else { 'not found' })"

$channel = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
if ($channel) {
    Write-Host "Sysmon channel: enabled=$($channel.IsEnabled), records=$($channel.RecordCount)"
} else {
    Write-Host "Sysmon channel: not found"
}

$latestLog = Get-ChildItem -LiteralPath $script:FusionAgentLogs -Filter "vector-*.log" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($latestLog) {
    Write-Host "Recent Vector log: $($latestLog.FullName)"
    Get-Content -LiteralPath $latestLog.FullName -Tail 10
}

if ($service.Status -ne "Running") {
    exit 1
}
