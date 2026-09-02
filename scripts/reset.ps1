[CmdletBinding()]
param(
    [switch] $Force,
    [switch] $SkipPull
)

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine

if (-not $Force) {
    $answer = Read-Host "Reset permanently deletes all Fusion ClickHouse, Grafana, and Vector data. Continue? [y/N]"
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host "Reset cancelled."
        exit 0
    }
}

Write-Host "Removing Fusion containers and data volumes..."
Invoke-FusionCompose down --volumes --remove-orphans

if ($SkipPull) {
    & (Join-Path $PSScriptRoot "deploy.ps1") -SkipPull
} else {
    & (Join-Path $PSScriptRoot "deploy.ps1")
}
if ($LASTEXITCODE -ne 0) {
    throw "Fusion reset completed, but redeployment failed."
}
