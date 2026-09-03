[CmdletBinding()]
param(
    [switch] $SkipSamples
)

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine
$settings = Get-FusionSettings
$docker = Get-FusionDocker

Write-Host "[1/9] Validating Docker Compose and both ingestion bind modes..."
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

Write-Host "[2/9] Running collector Vector configuration and VRL unit tests..."
Invoke-FusionCompose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml
Invoke-FusionCompose run --rm --no-deps vector test /etc/vector/vector.yaml

Write-Host "[3/9] Checking the live common ClickHouse schema..."
$requiredColumns = @(
    "provider_name", "record_id", "image_loaded", "query_name", "query_status", "query_results",
    "target_filename", "target_object", "registry_details", "message", "host_name", "platform",
    "source_type", "event_category", "event_action", "event_code", "source_event_id", "user_name",
    "user_id", "process_name", "process_path", "parent_process_name", "parent_process_id", "service_name",
    "outcome", "severity"
)
$quotedColumns = ($requiredColumns | ForEach-Object { "'$_'" }) -join ","
$schemaQuery = "SELECT count() FROM system.columns WHERE database = 'fusion' AND table = 'sysmon_events' AND name IN ($quotedColumns)"
$schemaCount = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $schemaQuery
if ($LASTEXITCODE -ne 0 -or [int]$schemaCount.Trim() -ne $requiredColumns.Count) {
    throw "ClickHouse common event columns are missing. Run scripts/deploy.ps1 to apply migrations."
}

Write-Host "[4/9] Proving the v0.2-to-v0.3 migration preserves Windows rows..."
$v02Schema = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\tests\002_v02_schema.sql"))
$v02Schema | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
if ($LASTEXITCODE -ne 0) { throw "Could not create the isolated v0.2 migration fixture." }
try {
    $migration = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\migrations\003_common_security_events_v03.sql"))
    $isolatedMigration = $migration.Replace("fusion.sysmon_events", "fusion_v03_migration_test.sysmon_events")
    $isolatedMigration | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
    if ($LASTEXITCODE -ne 0) { throw "The isolated v0.2-to-v0.3 migration failed." }
    $migrationQuery = "SELECT count(), countIf(platform = 'windows' AND host_name = 'V02-HOST' AND endsWith(process_path, 'cmd.exe') AND raw_json = '{`"v`":`"0.2`"}') FROM fusion_v03_migration_test.sysmon_events FORMAT TSV"
    $migrationResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $migrationQuery
    if ($LASTEXITCODE -ne 0 -or $migrationResult.Trim() -ne "1`t1") {
        throw "Existing v0.2 data was not preserved with compatible defaults: $migrationResult"
    }
} finally {
    & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query "DROP DATABASE IF EXISTS fusion_v03_migration_test" | Out-Null
}

Write-Host "[5/9] Checking container health..."
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
$linuxSampleFiles = @(Get-ChildItem -LiteralPath (Join-Path $script:FusionRoot "samples\linux-agent") -Filter "*.json" | Sort-Object Name)
$sampleFiles = @($v01SampleFiles) + @($windowsSampleFiles)

if (-not $SkipSamples) {
    Write-Host "[6/9] Sending Windows Sysmon and Linux auditd/journald fixtures..."
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
    $linuxIngestUri = "http://$ingestHost`:$($settings.FUSION_INGEST_PORT)/linux"
    $epochSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($sampleFile in $linuxSampleFiles) {
        $body = Get-Content -LiteralPath $sampleFile.FullName -Raw
        $body = [regex]::Replace($body, '"timestamp"\s*:\s*"[^"]+"', ('"timestamp":"{0}"' -f ([DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))))
        $body = [regex]::Replace($body, 'audit\([0-9]+(?:\.[0-9]+)?:', "audit($epochSeconds.125:")
        $response = Invoke-WebRequest -Uri $linuxIngestUri -Method Post -Headers $headers -ContentType "application/json" -Body $body
        if ($response.StatusCode -ne 202) {
            throw "Vector rejected $($sampleFile.Name) with HTTP $($response.StatusCode)."
        }
    }
} else {
    Write-Host "[6/9] Sample ingestion skipped."
}

Write-Host "[7/9] Verifying Windows compatibility and normalized Linux telemetry..."
if (-not $SkipSamples) {
    $query = "SELECT count(), countIf(event_id = 1), countIf(event_id = 1 AND (positionCaseInsensitiveUTF8(image, 'powershell.exe') > 0 OR positionCaseInsensitiveUTF8(image, 'pwsh.exe') > 0)), countIf(event_id = 3), countIf(event_id = 22), countIf(event_id = 22 AND query_name = 'example.com'), countIf(position(raw_json, 'windows_event_log') > 0), countIf(position(raw_json, '<Event') > 0) FROM fusion.sysmon_events WHERE validation_id = '$runId' AND platform = 'windows' FORMAT TSV"
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

    $linuxQuery = "SELECT count(), countIf(source_type = 'linux_auditd'), countIf(source_type = 'linux_journald'), countIf(event_action = 'process_execute' AND process_path = '/usr/bin/curl' AND command_line = '/usr/bin/curl https://example.com' AND user_id = '1000'), countIf(event_action = 'sudo_command'), countIf(event_category = 'authentication'), countIf(outcome = 'failure'), countIf(service_name = 'fusion-lab.service'), countIf(position(raw_json, 'type=SYSCALL') > 0 AND position(raw_json, 'type=EOE') > 0), countIf(position(raw_json, 'Accepted publickey') > 0) FROM fusion.sysmon_events WHERE validation_id = '$runId' AND platform = 'linux' FORMAT TSV"
    $linuxResult = $null
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $linuxResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $linuxQuery
        if ($LASTEXITCODE -ne 0) { throw "ClickHouse Linux validation query failed." }
        $linuxValues = ($linuxResult.Trim() -split "`t")
        if ($linuxValues.Count -eq 10 -and [int]$linuxValues[0] -ge $linuxSampleFiles.Count) { break }
        Start-Sleep -Seconds 1
    }
    $linuxValues = ($linuxResult.Trim() -split "`t")
    if ($linuxValues.Count -ne 10 -or [int]$linuxValues[0] -ne $linuxSampleFiles.Count -or [int]$linuxValues[1] -ne 2 -or [int]$linuxValues[2] -ne 3 -or [int]$linuxValues[3] -lt 1 -or [int]$linuxValues[4] -lt 1 -or [int]$linuxValues[5] -lt 2 -or [int]$linuxValues[6] -lt 1 -or [int]$linuxValues[7] -lt 1 -or [int]$linuxValues[8] -lt 1 -or [int]$linuxValues[9] -lt 1) {
        throw "Unexpected normalized Linux telemetry: $linuxResult"
    }
    Write-Host "  LinuxRows=$($linuxValues[0]), Auditd=$($linuxValues[1]), Journald=$($linuxValues[2]), Auth=$($linuxValues[5]), Failures=$($linuxValues[6])"
}

Write-Host "[8/9] Validating multi-platform dashboard panels and stored-telemetry queries..."
$dashboardPath = Join-Path $script:FusionRoot "grafana\dashboards\fusion-security-overview.json"
$dashboard = Get-Content -LiteralPath $dashboardPath -Raw | ConvertFrom-Json
$panelTitles = @($dashboard.panels | ForEach-Object { $_.title })
foreach ($requiredTitle in @("Top DNS queries", "Top executed processes", "External network destinations", "Sysmon events by Event ID", "Events by platform", "Top Linux executed processes", "Events by source type", "Failed authentication attempts", "Authentication activity", "sudo activity", "Linux process executions")) {
    if ($panelTitles -notcontains $requiredTitle) {
        throw "Grafana dashboard is missing the '$requiredTitle' panel."
    }
}
if (-not $SkipSamples) {
    $queryBackedPanels = @("Top DNS queries", "Top executed processes", "External network destinations", "Sysmon events by Event ID", "Events by platform", "Top Linux executed processes", "Events by source type", "Failed authentication attempts", "Authentication activity", "sudo activity", "Linux process executions")
    foreach ($requiredTitle in $queryBackedPanels) {
        $panel = $dashboard.panels | Where-Object { $_.title -eq $requiredTitle } | Select-Object -First 1
        $panelQuery = $panel.targets[0].rawSql.Replace('$__timeFilter(event_time)', "event_time >= now() - INTERVAL 1 DAY")
        $panelQuery = $panelQuery.Replace('$__timeInterval(event_time)', 'toStartOfMinute(event_time)')
        $panelQuery = $panelQuery.Replace('match(host_name, ''${computer:regex}'')', '1').Replace('match(computer, ''${computer:regex}'')', '1').Replace('match(platform, ''${platform:regex}'')', '1')
        $panelResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $panelQuery
        if ($LASTEXITCODE -ne 0 -or -not ($panelResult | Out-String).Trim()) {
            throw "The '$requiredTitle' dashboard query failed or returned no stored telemetry."
        }
    }
    $linuxDashboardResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query "SELECT countIf(event_action = 'process_execute'), countIf(event_category = 'authentication'), countIf(event_action = 'sudo_command'), uniqExact(source_type) FROM fusion.sysmon_events WHERE validation_id = '$runId' AND platform = 'linux' FORMAT TSV"
    $linuxDashboardValues = $linuxDashboardResult.Trim() -split "`t"
    if ($LASTEXITCODE -ne 0 -or $linuxDashboardValues.Count -ne 4 -or [int]$linuxDashboardValues[0] -lt 1 -or [int]$linuxDashboardValues[1] -lt 2 -or [int]$linuxDashboardValues[2] -lt 1 -or [int]$linuxDashboardValues[3] -lt 2) {
        throw "Linux dashboard query checks did not return the expected telemetry: $linuxDashboardResult"
    }
}

Write-Host "[9/9] Checking Grafana and the provisioned ClickHouse data source..."
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
$provisionedDashboard = (Invoke-RestMethod -Uri "$grafanaBase/api/dashboards/uid/fusion-security-overview" -Headers $authHeaders).dashboard
foreach ($requiredTitle in @("Events by platform", "Top Linux executed processes", "Events by source type", "Failed authentication attempts", "Authentication activity", "sudo activity", "Linux process executions")) {
    if (@($provisionedDashboard.panels.title) -notcontains $requiredTitle) {
        throw "The provisioned Grafana dashboard is missing '$requiredTitle'."
    }
}
if (@($provisionedDashboard.templating.list.name) -notcontains "platform") {
    throw "The provisioned Grafana dashboard is missing the Platform filter."
}

Write-Host "Validation passed: bindings, v0.1/v0.2 compatibility, v0.3 Windows/Linux normalization, storage, data source, and dashboard are healthy."
