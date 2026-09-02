[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot "FusionAgent.Common.ps1")

Assert-FusionAgentAdministrator
$service = Get-FusionAgentService
if (-not $service) {
    throw "The $script:FusionAgentServiceName service is not installed."
}
if ($service.Status -eq "Stopped") {
    Write-Host "Fusion Windows Vector agent is already stopped."
    exit 0
}

Invoke-FusionVector service stop --name $script:FusionAgentServiceName --stop-timeout 30
Write-Host "Fusion Windows Vector agent stopped."
