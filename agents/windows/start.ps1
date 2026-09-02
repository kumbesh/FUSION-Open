[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot "FusionAgent.Common.ps1")

Assert-FusionAgentAdministrator
$service = Get-FusionAgentService
if (-not $service) {
    throw "The $script:FusionAgentServiceName service is not installed. Run install.ps1 first."
}
if ($service.Status -eq "Running") {
    Write-Host "Fusion Windows Vector agent is already running."
    exit 0
}

Invoke-FusionVector service start --name $script:FusionAgentServiceName
Write-Host "Fusion Windows Vector agent started."
