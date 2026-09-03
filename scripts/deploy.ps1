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
$ingestPort = if ($settings.ContainsKey("FUSION_INGEST_PORT") -and $settings.FUSION_INGEST_PORT) { $settings.FUSION_INGEST_PORT } else { "8686" }
$syslogBindAddress = if ($settings.ContainsKey("FUSION_SYSLOG_BIND_ADDRESS") -and $settings.FUSION_SYSLOG_BIND_ADDRESS) { $settings.FUSION_SYSLOG_BIND_ADDRESS } else { "127.0.0.1" }
$syslogTcpPort = if ($settings.ContainsKey("FUSION_SYSLOG_TCP_PORT") -and $settings.FUSION_SYSLOG_TCP_PORT) { $settings.FUSION_SYSLOG_TCP_PORT } else { "5514" }
$syslogUdpPort = if ($settings.ContainsKey("FUSION_SYSLOG_UDP_PORT") -and $settings.FUSION_SYSLOG_UDP_PORT) { $settings.FUSION_SYSLOG_UDP_PORT } else { "5514" }
$grafanaPort = if ($settings.ContainsKey("FUSION_GRAFANA_PORT") -and $settings.FUSION_GRAFANA_PORT) { $settings.FUSION_GRAFANA_PORT } else { "3000" }
Write-Host "Fusion is ready."
Write-Host "Detection engine: running without a host port"
Write-Host "Grafana:         http://localhost:$grafanaPort"
Write-Host "Windows ingest:  http://$bindAddress`:$ingestPort/sysmon"
Write-Host "Linux ingest:    http://$bindAddress`:$ingestPort/linux"
Write-Host "Security ingest: http://$bindAddress`:$ingestPort/security"
Write-Host "Syslog TCP:      $syslogBindAddress`:$syslogTcpPort"
Write-Host "Syslog UDP:      $syslogBindAddress`:$syslogUdpPort"
if ($bindAddress -ne "127.0.0.1") {
    Write-Warning "HTTP ingestion is reachable beyond localhost and has no TLS or authentication. Restrict TCP $ingestPort to the isolated test VM or lab subnet."
}
if ($syslogBindAddress -ne "127.0.0.1") {
    Write-Warning "Syslog is reachable beyond localhost and is plaintext/unauthenticated. Restrict TCP/UDP $syslogTcpPort/$syslogUdpPort to the isolated test devices or lab subnet."
}
