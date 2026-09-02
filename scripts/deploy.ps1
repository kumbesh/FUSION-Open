[CmdletBinding()]
param(
    [switch] $SkipPull,
    [switch] $SkipValidate
)

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine
Initialize-FusionEnvironment
Invoke-FusionCompose config --quiet

if (-not $SkipPull) {
    Write-Host "Pulling pinned Fusion images..."
    Invoke-FusionCompose pull
}

Write-Host "Starting Fusion..."
Invoke-FusionCompose up --detach --wait --wait-timeout 300 --remove-orphans

if (-not $SkipValidate) {
    & (Join-Path $PSScriptRoot "validate.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Fusion started, but validation failed."
    }
}

$settings = Get-FusionSettings
Write-Host "Fusion is ready."
Write-Host "Grafana: http://localhost:$($settings.FUSION_GRAFANA_PORT)"
Write-Host "Ingest: http://localhost:$($settings.FUSION_INGEST_PORT)/sysmon"

