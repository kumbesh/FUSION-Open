[CmdletBinding()]
param(
    [switch] $SkipSamples
)

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine
$settings = Get-FusionSettings
$docker = Get-FusionDocker

Write-Host "[1/8] Validating Docker Compose and both ingestion bind modes..."
Invoke-FusionCompose config --quiet
$hadBindAddress = Test-Path Env:FUSION_BIND_ADDRESS
$originalBindAddress = if ($hadBindAddress) { $env:FUSION_BIND_ADDRESS } else { $null }
try {
    foreach ($binding in @("127.0.0.1", "192.0.2.10")) {
        $env:FUSION_BIND_ADDRESS = $binding
        $json = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile config --format json
        if ($LASTEXITCODE -ne 0) {
            throw "Compose rendering failed for FUSION_BIND_ADDRESS=$binding."
        }
        $model = $json | ConvertFrom-Json
        $ingestPort = $model.services.vector.ports | Where-Object { $_.target -eq 8686 } | Select-Object -First 1
        if (-not $ingestPort -or $ingestPort.host_ip -ne $binding) {
            throw "Expected ingestion to bind to $binding; rendered port was $($ingestPort | ConvertTo-Json -Compress)."
        }
    }
} finally {
    if ($hadBindAddress) {
        $env:FUSION_BIND_ADDRESS = $originalBindAddress
    } else {
        Remove-Item Env:FUSION_BIND_ADDRESS -ErrorAction SilentlyContinue
    }
}

Write-Host "[2/8] Running collector Vector configuration and VRL unit tests..."
Invoke-FusionCompose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml
Invoke-FusionCompose run --rm --no-deps vector test /etc/vector/vector.yaml

Write-Host "[3/8] Checking the backward-compatible ClickHouse migration..."
$requiredColumns = @("provider_name", "record_id", "image_loaded", "query_name", "query_status", "query_results", "target_filename", "target_object", "registry_details", "message")
$quotedColumns = ($requiredColumns | ForEach-Object { "'$_'" }) -join ","
$schemaQuery = "SELECT count() FROM system.columns WHERE database = 'fusion' AND table = 'sysmon_events' AND name IN ($quotedColumns)"
$schemaCount = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $schemaQuery
if ($LASTEXITCODE -ne 0 -or [int]$schemaCount.Trim() -ne $requiredColumns.Count) {
    throw "ClickHouse v0.2 columns are missing. Run scripts/deploy.ps1 to apply migrations."
}

Write-Host "[4/8] Checking container health..."
foreach ($service in @("clickhouse", "vector", "grafana")) {
    $containerId = (& $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile ps -q $service).Trim()
    if (-not $containerId) {
        throw "Service '$service' is not running. Run scripts/deploy.ps1 first."
    }
    $state = (& $docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' $containerId).Trim()
    if ($state -ne "running healthy") {
        throw "Service '$service' is not healthy (state: $state)."
    }
}

$runId = [Guid]::NewGuid().ToString()
$v01SampleFiles = @(Get-ChildItem -LiteralPath (Join-Path $script:FusionRoot "samples\sysmon") -Filter "*.json" | Sort-Object Name)
$windowsSampleFiles = @(Get-ChildItem -LiteralPath (Join-Path $script:FusionRoot "samples\windows-agent") -Filter "*.json" | Sort-Object Name)
$sampleFiles = @($v01SampleFiles) + @($windowsSampleFiles)

if (-not $SkipSamples) {
    Write-Host "[5/8] Sending v0.1 and Windows-agent-shaped Sysmon events..."
    $ingestHost = if ($settings.ContainsKey("FUSION_BIND_ADDRESS") -and $settings.FUSION_BIND_ADDRESS) { $settings.FUSION_BIND_ADDRESS } else { "127.0.0.1" }
    $ingestUri = "http://$ingestHost`:$($settings.FUSION_INGEST_PORT)/sysmon"
    $headers = @{ "X-Fusion-Validation-Id" = $runId }

    foreach ($sampleFile in $v01SampleFiles) {
        $payload = Get-Content -LiteralPath $sampleFile.FullName -Raw | ConvertFrom-Json
        $now = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        if (($payload.PSObject.Properties.Name -contains "Event") -and $payload.Event.EventData) {
            $payload.Event.EventData.UtcTime = $now
        }
        $body = $payload | ConvertTo-Json -Depth 20 -Compress
        $response = Invoke-WebRequest -Uri $ingestUri -Method Post -Headers $headers -ContentType "application/json" -Body $body
        if ($response.StatusCode -ne 202) {
            throw "Vector rejected $($sampleFile.Name) with HTTP $($response.StatusCode)."
        }
    }

    foreach ($sampleFile in $windowsSampleFiles) {
        $payload = Get-Content -LiteralPath $sampleFile.FullName -Raw | ConvertFrom-Json
        $now = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $payload.timestamp = $now
        if ($payload.event_data.UtcTime) {
            $payload.event_data.UtcTime = $now
        }
        $body = $payload | ConvertTo-Json -Depth 20 -Compress
        $response = Invoke-WebRequest -Uri $ingestUri -Method Post -Headers $headers -ContentType "application/json" -Body $body
        if ($response.StatusCode -ne 202) {
            throw "Vector rejected $($sampleFile.Name) with HTTP $($response.StatusCode)."
        }
    }
} else {
    Write-Host "[5/8] Sample ingestion skipped."
}

Write-Host "[6/8] Verifying v0.1 compatibility and Event IDs 1, 3, and 22..."
if (-not $SkipSamples) {
    $query = "SELECT count(), countIf(event_id = 1), countIf(event_id = 1 AND (positionCaseInsensitiveUTF8(image, 'powershell.exe') > 0 OR positionCaseInsensitiveUTF8(image, 'pwsh.exe') > 0)), countIf(event_id = 3), countIf(event_id = 22), countIf(event_id = 22 AND query_name = 'example.com'), countIf(position(raw_json, 'windows_event_log') > 0), countIf(position(raw_json, '<Event') > 0) FROM fusion.sysmon_events WHERE validation_id = '$runId' FORMAT TSV"
    $queryResult = $null
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $queryResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $query
        if ($LASTEXITCODE -ne 0) {
            throw "ClickHouse validation query failed."
        }
        $values = ($queryResult.Trim() -split "`t")
        if ($values.Count -eq 8 -and [int]$values[0] -ge $sampleFiles.Count) {
            break
        }
        Start-Sleep -Seconds 1
    }

    $values = ($queryResult.Trim() -split "`t")
    if ($values.Count -ne 8 -or [int]$values[0] -lt $sampleFiles.Count -or [int]$values[1] -lt 3 -or [int]$values[2] -lt 1 -or [int]$values[3] -lt 2 -or [int]$values[4] -lt 1 -or [int]$values[5] -lt 1 -or [int]$values[6] -lt 3 -or [int]$values[7] -lt 3) {
        throw "Unexpected ClickHouse counts: $queryResult"
    }
    Write-Host "  Rows=$($values[0]), Process=$($values[1]), PowerShell=$($values[2]), Network=$($values[3]), DNS=$($values[4]), RawWindows=$($values[6]), RawXML=$($values[7])"
}

Write-Host "[7/8] Validating v0.2 dashboard panels and their stored-telemetry queries..."
$dashboardPath = Join-Path $script:FusionRoot "grafana\dashboards\fusion-security-overview.json"
$dashboard = Get-Content -LiteralPath $dashboardPath -Raw | ConvertFrom-Json
$panelTitles = @($dashboard.panels | ForEach-Object { $_.title })
foreach ($requiredTitle in @("Top DNS queries", "Top executed processes", "External network destinations", "Sysmon events by Event ID")) {
    if ($panelTitles -notcontains $requiredTitle) {
        throw "Grafana dashboard is missing the '$requiredTitle' panel."
    }
}
if (-not $SkipSamples) {
    foreach ($requiredTitle in @("Top DNS queries", "Top executed processes", "External network destinations", "Sysmon events by Event ID")) {
        $panel = $dashboard.panels | Where-Object { $_.title -eq $requiredTitle } | Select-Object -First 1
        $panelQuery = $panel.targets[0].rawSql.Replace('$__timeFilter(event_time)', "event_time >= now() - INTERVAL 1 DAY")
        $panelQuery = $panelQuery.Replace('match(computer, ''${computer:regex}'')', '1')
        $panelResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $panelQuery
        if ($LASTEXITCODE -ne 0 -or -not ($panelResult | Out-String).Trim()) {
            throw "The '$requiredTitle' dashboard query failed or returned no stored telemetry."
        }
    }
}

Write-Host "[8/8] Checking Grafana and the provisioned ClickHouse data source..."
$grafanaBase = "http://127.0.0.1:$($settings.FUSION_GRAFANA_PORT)"
$health = Invoke-RestMethod -Uri "$grafanaBase/api/health"
if ($health.database -ne "ok") {
    throw "Grafana database health is '$($health.database)'."
}

$credentialText = "$($settings.GRAFANA_ADMIN_USER):$($settings.GRAFANA_ADMIN_PASSWORD)"
$basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($credentialText))
$authHeaders = @{ Authorization = "Basic $basicAuth" }
$dataSourceHealth = Invoke-RestMethod -Uri "$grafanaBase/api/datasources/uid/fusion-clickhouse/health" -Headers $authHeaders
if ($dataSourceHealth.status -ne "OK") {
    throw "Grafana ClickHouse data source is unhealthy: $($dataSourceHealth.message)"
}

$dashboards = Invoke-RestMethod -Uri "$grafanaBase/api/search?query=Fusion%20Security%20Overview" -Headers $authHeaders
if (-not ($dashboards | Where-Object { $_.uid -eq "fusion-security-overview" })) {
    throw "Fusion Security Overview dashboard was not provisioned."
}

Write-Host "Validation passed: bindings, v0.1 compatibility, v0.2 normalization, storage, data source, and dashboard are healthy."
