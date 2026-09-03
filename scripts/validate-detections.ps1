[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine
$settings = Get-FusionSettings
$docker = Get-FusionDocker

function Invoke-DetectionQuery {
    param([Parameter(Mandatory = $true)][string] $Query)
    $output = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $Query
    if ($LASTEXITCODE -ne 0) { throw "ClickHouse detection query failed." }
    return ($output | Out-String).Trim()
}

$runId = "fusion-v05-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))-$PID"
$secondRunId = "$runId-restart"
$engineId = "fusion-validation-$runId"

Write-Host "[detections 1/7] Validating curated Sigma rules and positive/negative fixtures..."
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine validate-rules
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine validate-fixtures

Write-Host "[detections 2/7] Seeding controlled normalized Windows, Linux, and Suricata fixtures..."
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine seed-fixtures --run-id $runId
Invoke-DetectionQuery "INSERT INTO fusion.detection_checkpoints (engine_id, checkpoint_time, checkpoint_uid, updated_at) VALUES ('$engineId', now64(3), '', now64(3))" | Out-Null

Write-Host "[detections 3/7] Evaluating fixtures and verifying platform coverage..."
Invoke-FusionCompose -ComposeArguments @("run", "--rm", "--no-deps", "-e", "FUSION_DETECTION_ENGINE_ID=$engineId", "-e", "FUSION_DETECTION_BATCH_SIZE=10000", "-e", "FUSION_DETECTION_LOOKBACK_SECONDS=300", "fusion-detection-engine", "run", "--once")
$result = Invoke-DetectionQuery "SELECT count(), uniqExact(rule_id), uniqExact(platform), countIf(source_event_uid IN (SELECT event_uid FROM fusion.sysmon_events WHERE validation_id = '$runId' AND JSONExtractString(raw_json, 'fixture_polarity') = 'negative')) FROM fusion.detections FINAL WHERE validation_id = '$runId' FORMAT TSV"
if ($result -ne "9`t9`t3`t0") { throw "Unexpected synthetic detection result: $result" }

Write-Host "[detections 4/7] Replaying the lookback window without creating duplicates..."
Invoke-FusionCompose -ComposeArguments @("run", "--rm", "--no-deps", "-e", "FUSION_DETECTION_ENGINE_ID=$engineId", "-e", "FUSION_DETECTION_BATCH_SIZE=10000", "-e", "FUSION_DETECTION_LOOKBACK_SECONDS=300", "fusion-detection-engine", "run", "--once")
$physicalCount = [int](Invoke-DetectionQuery "SELECT count() FROM fusion.detections WHERE validation_id = '$runId'")
if ($physicalCount -ne 9) { throw "Detection replay created duplicates: $physicalCount rows" }

Write-Host "[detections 5/7] Restarting the engine and checking checkpoint continuity..."
Invoke-FusionCompose restart fusion-detection-engine
Invoke-FusionCompose up --detach --wait --wait-timeout 180 fusion-detection-engine
$postRestartCount = [int](Invoke-DetectionQuery "SELECT count() FROM fusion.detections WHERE validation_id = '$runId'")
if ($postRestartCount -ne 9) { throw "Detection restart changed existing detections: $postRestartCount rows" }
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine seed-fixtures --run-id $secondRunId
Invoke-FusionCompose -ComposeArguments @("run", "--rm", "--no-deps", "-e", "FUSION_DETECTION_ENGINE_ID=$engineId", "-e", "FUSION_DETECTION_BATCH_SIZE=10000", "-e", "FUSION_DETECTION_LOOKBACK_SECONDS=300", "fusion-detection-engine", "run", "--once")
$newCount = Invoke-DetectionQuery "SELECT count(), uniqExact(rule_id), uniqExact(platform) FROM fusion.detections FINAL WHERE validation_id = '$secondRunId' FORMAT TSV"
if ($newCount -ne "9`t9`t3") { throw "New events after restart did not produce expected detections: $newCount" }

Write-Host "[detections 6/7] Proving telemetry ingestion continues while detection is stopped..."
$ingestionRunId = "$runId-engine-stopped"
$engineStopped = $false
try {
    Invoke-FusionCompose stop fusion-detection-engine
    $engineStopped = $true
    $bindAddress = if ($settings.FUSION_BIND_ADDRESS) { $settings.FUSION_BIND_ADDRESS } else { "127.0.0.1" }
    $ingestPort = if ($settings.FUSION_INGEST_PORT) { $settings.FUSION_INGEST_PORT } else { "8686" }
    $payload = Get-Content -Raw -LiteralPath (Join-Path $script:FusionRoot "samples\security-tools\suricata-flow.json") | ConvertFrom-Json
    $payload.event.timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $response = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "http://$bindAddress`:$ingestPort/security" -ContentType "application/json" -Headers @{ "X-Fusion-Validation-Id" = $ingestionRunId } -Body ($payload | ConvertTo-Json -Depth 20 -Compress)
    if ($response.StatusCode -ne 202) { throw "Vector rejected telemetry while detection was stopped with HTTP $($response.StatusCode)." }
    $ingested = 0
    foreach ($attempt in 1..20) {
        $ingested = [int](Invoke-DetectionQuery "SELECT count() FROM fusion.sysmon_events WHERE validation_id = '$ingestionRunId'")
        if ($ingested -ge 1) { break }
        Start-Sleep -Seconds 1
    }
    if ($ingested -lt 1) { throw "Telemetry did not reach ClickHouse while detection was stopped." }
} finally {
    if ($engineStopped) {
        Invoke-FusionCompose start fusion-detection-engine
        Invoke-FusionCompose up --detach --wait --wait-timeout 180 fusion-detection-engine
    }
}

Write-Host "[detections 7/7] Validating the bounded dry-run plan and detection dashboard SQL..."
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine test-rule /rules/windows/encoded-powershell.yml --hours 1 --limit 100 | Out-Null
$dashboardPath = Join-Path $script:FusionRoot "grafana\dashboards\fusion-detections.json"
$dashboard = Get-Content -Raw -LiteralPath $dashboardPath | ConvertFrom-Json
$requiredPanels = @("Total detections", "New detections", "High/Critical detections", "Detections over time", "Detections by severity", "Detections by rule", "Detections by platform", "Detections by source type", "Detections by host", "Top affected users", "Top source IPs", "Top destination IPs", "MITRE tactics", "MITRE techniques", "Recent detections")
foreach ($title in $requiredPanels) {
    if (@($dashboard.panels.title) -notcontains $title) { throw "Fusion Detections dashboard is missing '$title'." }
}
foreach ($variable in @("severity", "status", "platform", "host", "rule", "tactic", "technique")) {
    if (@($dashboard.templating.list.name) -notcontains $variable) { throw "Fusion Detections dashboard is missing '$variable'." }
}
foreach ($panel in $dashboard.panels) {
    $panelQuery = $panel.targets[0].rawSql.Replace('$__timeFilter(detected_at)', "detected_at >= now() - INTERVAL 1 DAY")
    $panelQuery = $panelQuery.Replace('$__timeInterval(detected_at)', 'toStartOfMinute(detected_at)')
    foreach ($filter in @(
        "match(severity, '`${severity:regex}')", "match(status, '`${status:regex}')",
        "match(platform, '`${platform:regex}')", "match(host_name, '`${host:regex}')",
        "match(rule_id, '`${rule:regex}')",
        "arrayExists(item -> match(item, '`${tactic:regex}'), mitre_tactics)",
        "arrayExists(item -> match(item, '`${technique:regex}'), mitre_technique_ids)"
    )) {
        $panelQuery = $panelQuery.Replace($filter, "1")
    }
    $panelResult = Invoke-DetectionQuery $panelQuery
    if (-not $panelResult) { throw "The '$($panel.title)' detection dashboard query returned no synthetic telemetry." }
}
foreach ($query in @(
    "SELECT count() FROM fusion.detections FINAL",
    "SELECT severity, count() FROM fusion.detections FINAL GROUP BY severity",
    "SELECT rule_name, count() FROM fusion.detections FINAL GROUP BY rule_name",
    "SELECT platform, count() FROM fusion.detections FINAL GROUP BY platform",
    "SELECT source_type, count() FROM fusion.detections FINAL GROUP BY source_type",
    "SELECT arrayJoin(mitre_tactics), count() FROM fusion.detections FINAL GROUP BY arrayJoin(mitre_tactics)",
    "SELECT arrayJoin(mitre_techniques), count() FROM fusion.detections FINAL GROUP BY arrayJoin(mitre_techniques)"
)) {
    Invoke-DetectionQuery $query | Out-Null
}

Write-Host "Detection validation passed: rules, fixtures, deduplication, restart, ingestion isolation, dry-run, and dashboard queries are healthy."
