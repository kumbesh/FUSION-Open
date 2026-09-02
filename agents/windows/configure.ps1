[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = "Full receiver URL, for example http://192.168.56.1:8686/sysmon")]
    [uri] $CollectorUrl,
    [switch] $NoRestart
)

. (Join-Path $PSScriptRoot "FusionAgent.Common.ps1")

Assert-FusionAgentAdministrator
Assert-FusionSysmonPrerequisites
Assert-FusionCollectorUrl -CollectorUrl $CollectorUrl
if ($CollectorUrl.Scheme -eq "http") {
    Write-Warning "Fusion v0.2 ingestion has no TLS or authentication. Use this URL only on an isolated, firewall-restricted lab network."
}
if (-not (Get-FusionAgentService)) {
    throw "The $script:FusionAgentServiceName service is not installed. Run install.ps1 first."
}

Write-FusionAgentConfiguration -CollectorUrl $CollectorUrl
Invoke-FusionVector validate --no-environment --config-yaml $script:FusionAgentConfig

if (-not $NoRestart) {
    $service = Get-FusionAgentService
    if ($service.Status -eq "Running") {
        Invoke-FusionVector service stop --name $script:FusionAgentServiceName --stop-timeout 30
    }
    Invoke-FusionVector service start --name $script:FusionAgentServiceName
}

Write-Host "Fusion Windows Vector agent configured for $($CollectorUrl.AbsoluteUri)."
