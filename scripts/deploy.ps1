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

Write-Host "Starting ClickHouse..."
Invoke-FusionCompose up --detach --wait --wait-timeout 300 clickhouse
Invoke-FusionMigrations

Write-Host "Starting Fusion..."
Invoke-FusionCompose up --detach --force-recreate --no-deps vector grafana
Invoke-FusionCompose up --detach --wait --wait-timeout 300 --remove-orphans

if (-not $SkipValidate) {
    & (Join-Path $PSScriptRoot "validate.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Fusion started, but validation failed."
    }
}

$settings = Get-FusionSettings
$bindAddress = if ($settings.ContainsKey("FUSION_BIND_ADDRESS") -and $settings.FUSION_BIND_ADDRESS) { $settings.FUSION_BIND_ADDRESS } else { "127.0.0.1" }
Write-Host "Fusion is ready."
Write-Host "Grafana: http://localhost:$($settings.FUSION_GRAFANA_PORT)"
Write-Host "Ingest: http://$bindAddress`:$($settings.FUSION_INGEST_PORT)/sysmon"
if ($bindAddress -ne "127.0.0.1") {
    Write-Warning "Ingestion is reachable beyond localhost and has no TLS or authentication. Restrict TCP $($settings.FUSION_INGEST_PORT) to the isolated test VM or lab subnet."
}
