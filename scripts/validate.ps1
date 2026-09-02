[CmdletBinding()]
param(
    [switch] $SkipSamples
)

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine
$settings = Get-FusionSettings
$docker = Get-FusionDocker

Write-Host "[1/6] Validating Docker Compose configuration..."
Invoke-FusionCompose config --quiet

Write-Host "[2/6] Running Vector configuration and VRL unit tests..."
Invoke-FusionCompose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml
Invoke-FusionCompose run --rm --no-deps vector test /etc/vector/vector.yaml

Write-Host "[3/6] Checking container health..."
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
if (-not $SkipSamples) {
    Write-Host "[4/6] Sending sample Sysmon events..."
    $ingestUri = "http://127.0.0.1:$($settings.FUSION_INGEST_PORT)/sysmon"
    $headers = @{ "X-Fusion-Validation-Id" = $runId }
    $sampleFiles = Get-ChildItem -LiteralPath (Join-Path $script:FusionRoot "samples\sysmon") -Filter "*.json" | Sort-Object Name

    foreach ($sampleFile in $sampleFiles) {
        $payload = Get-Content -LiteralPath $sampleFile.FullName -Raw | ConvertFrom-Json
        $payload.Event.EventData.UtcTime = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $body = $payload | ConvertTo-Json -Depth 20 -Compress
        $response = Invoke-WebRequest -Uri $ingestUri -Method Post -Headers $headers -ContentType "application/json" -Body $body
        if ($response.StatusCode -ne 202) {
            throw "Vector rejected $($sampleFile.Name) with HTTP $($response.StatusCode)."
        }
    }
} else {
    Write-Host "[4/6] Sample ingestion skipped."
}

Write-Host "[5/6] Verifying normalized rows in ClickHouse..."
if (-not $SkipSamples) {
    $query = "SELECT count(), countIf(event_id = 1), countIf(event_id = 1 AND (positionCaseInsensitiveUTF8(image, 'powershell.exe') > 0 OR positionCaseInsensitiveUTF8(image, 'pwsh.exe') > 0)), countIf(event_id = 3) FROM fusion.sysmon_events WHERE validation_id = '$runId' FORMAT TSV"
    $queryResult = $null
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $queryResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $query
        if ($LASTEXITCODE -ne 0) {
            throw "ClickHouse validation query failed."
        }
        $values = ($queryResult.Trim() -split "`t")
        if ($values.Count -eq 4 -and [int]$values[0] -ge 3) {
            break
        }
        Start-Sleep -Seconds 1
    }

    $values = ($queryResult.Trim() -split "`t")
    if ($values.Count -ne 4 -or [int]$values[0] -lt 3 -or [int]$values[1] -lt 2 -or [int]$values[2] -lt 1 -or [int]$values[3] -lt 1) {
        throw "Unexpected ClickHouse counts: $queryResult"
    }
    Write-Host "  Rows=$($values[0]), Process=$($values[1]), PowerShell=$($values[2]), Network=$($values[3])"
}

Write-Host "[6/6] Checking Grafana and the provisioned ClickHouse data source..."
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

Write-Host "Validation passed: ingestion, normalization, storage, data source, and dashboard are healthy."

