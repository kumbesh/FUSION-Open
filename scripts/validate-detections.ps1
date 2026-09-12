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

function Invoke-DetectionAdminInsert {
    param([Parameter(Mandatory = $true)][string] $Query)
    $output = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --async_insert=0 --query $Query
    if ($LASTEXITCODE -ne 0) { throw "ClickHouse detection admin insert failed." }
    return ($output | Out-String).Trim()
}

$runId = "fusion-v05-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))-$PID"
$secondRunId = "$runId-restart"
$engineId = "fusion-validation-$runId"
$ledgerRunId = "$runId-ledger-1001"
$ledgerEngineId = "fusion-validation-ledger-$runId"

Write-Host "[detections 1/8] Validating curated Sigma rules and positive/negative fixtures..."
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine validate-rules
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine validate-fixtures

Write-Host "[detections 2/8] Seeding controlled normalized Windows, Linux, and Suricata fixtures..."
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine seed-fixtures --run-id $runId
Invoke-DetectionAdminInsert "INSERT INTO fusion.detection_checkpoints (engine_id, checkpoint_time, checkpoint_uid, updated_at) VALUES ('$engineId', now64(3), '', now64(3))" | Out-Null

Write-Host "[detections 3/8] Evaluating fixtures and verifying platform coverage..."
Invoke-FusionCompose -ComposeArguments @("run", "--rm", "--no-deps", "-e", "FUSION_DETECTION_ENGINE_ID=$engineId", "-e", "FUSION_DETECTION_BATCH_SIZE=10000", "-e", "FUSION_DETECTION_LOOKBACK_SECONDS=0", "fusion-detection-engine", "run", "--once")
$result = Invoke-DetectionQuery "SELECT count(), uniqExact(rule_id), uniqExact(platform), countIf(source_event_uid IN (SELECT event_uid FROM fusion.sysmon_events WHERE validation_id = '$runId' AND JSONExtractString(raw_json, 'fixture_polarity') = 'negative')) FROM fusion.detections FINAL WHERE validation_id = '$runId' FORMAT TSV"
if ($result -ne "9`t9`t3`t0") { throw "Unexpected synthetic detection result: $result" }
$telemetry = Invoke-DetectionQuery "SELECT count(), countIf(length(ruleset_fingerprint) = 64 AND length(checkpoint_uid) = 64 AND isNotNull(evaluation_floor_time) AND isNotNull(newest_eligible_event_time) AND events_evaluated > 0 AND new_events_processed > 0 AND processing_duration_seconds > 0 AND evaluated_events_per_second > 0 AND checkpoint_lag_seconds >= 0 AND unevaluated_event_count >= 0 AND oldest_unevaluated_age_seconds >= 0) FROM fusion.detection_checkpoints FINAL WHERE engine_id = '$engineId' FORMAT TSV"
if ($telemetry -ne "1`t1") { throw "Detection checkpoint telemetry is incomplete: $telemetry" }
$scopeTelemetry = Invoke-DetectionQuery "SELECT countIf(isNotNull(candidate_cursor_time) AND length(candidate_cursor_uid) = 64) FROM fusion.detection_evaluation_scopes FINAL WHERE engine_id = '$engineId'"
if ($scopeTelemetry -ne "1") { throw "Detection candidate scheduling cursor is incomplete: $scopeTelemetry" }
$ledgerCoverage = Invoke-DetectionQuery "SELECT count(), uniqExact(ledger.event_uid) FROM fusion.detection_evaluated_events AS ledger INNER JOIN fusion.sysmon_events AS source ON ledger.event_uid = source.event_uid WHERE ledger.engine_id = '$engineId' AND source.validation_id = '$runId' FORMAT TSV"
if ($ledgerCoverage -ne "18`t18") { throw "Detection evaluation ledger did not cover every fixture: $ledgerCoverage" }

Write-Host "[detections 4/8] Replaying the lookback window without creating duplicates..."
Invoke-FusionCompose -ComposeArguments @("run", "--rm", "--no-deps", "-e", "FUSION_DETECTION_ENGINE_ID=$engineId", "-e", "FUSION_DETECTION_BATCH_SIZE=10000", "-e", "FUSION_DETECTION_LOOKBACK_SECONDS=0", "fusion-detection-engine", "run", "--once")
$physicalCount = [int](Invoke-DetectionQuery "SELECT count() FROM fusion.detections WHERE validation_id = '$runId'")
if ($physicalCount -ne 9) { throw "Detection replay created duplicates: $physicalCount rows" }
$replayLedgerCount = [int](Invoke-DetectionQuery "SELECT count() FROM fusion.detection_evaluated_events WHERE engine_id = '$engineId' AND validation_id = '$runId'")
if ($replayLedgerCount -ne 18) { throw "Detection replay amplified evaluation-ledger rows: $replayLedgerCount" }

Write-Host "[detections 5/8] Restarting the engine and checking checkpoint continuity..."
Invoke-FusionCompose restart fusion-detection-engine
Invoke-FusionCompose up --detach --wait --wait-timeout 180 fusion-detection-engine
$postRestartCount = [int](Invoke-DetectionQuery "SELECT count() FROM fusion.detections WHERE validation_id = '$runId'")
if ($postRestartCount -ne 9) { throw "Detection restart changed existing detections: $postRestartCount rows" }
Invoke-FusionCompose run --rm --no-deps fusion-detection-engine seed-fixtures --run-id $secondRunId
Invoke-FusionCompose -ComposeArguments @("run", "--rm", "--no-deps", "-e", "FUSION_DETECTION_ENGINE_ID=$engineId", "-e", "FUSION_DETECTION_BATCH_SIZE=10000", "-e", "FUSION_DETECTION_LOOKBACK_SECONDS=0", "fusion-detection-engine", "run", "--once")
$newCount = Invoke-DetectionQuery "SELECT count(), uniqExact(rule_id), uniqExact(platform) FROM fusion.detections FINAL WHERE validation_id = '$secondRunId' FORMAT TSV"
if ($newCount -ne "9`t9`t3") { throw "New events after restart did not produce expected detections: $newCount" }
$newLedgerCoverage = Invoke-DetectionQuery "SELECT count(), uniqExact(event_uid) FROM fusion.detection_evaluated_events WHERE engine_id = '$engineId' AND validation_id = '$secondRunId' FORMAT TSV"
if ($newLedgerCoverage -ne "18`t18") { throw "Events after restart were not completely ledgered: $newLedgerCoverage" }

Write-Host "[detections 6/8] Proving 1,001 same-timestamp events cannot hide behind the watermark..."
$ledgerEventTime = [DateTime]::UtcNow.AddSeconds(5).ToString("yyyy-MM-dd HH:mm:ss.fff", [Globalization.CultureInfo]::InvariantCulture)
$ledgerInsert = @"
INSERT INTO fusion.sysmon_events
    (event_time, event_id, event_type, computer, record_id, process_guid,
     platform, source_type, host_name, source_event_id, event_code,
     event_category, event_action, event_kind, vendor, product,
     validation_id, raw_json)
SELECT
    toDateTime64('$ledgerEventTime', 3, 'UTC'), 0, 'ledger_validation',
    'fusion-validation', number, '', 'network', 'fusion_validation',
    'fusion-validation', toString(number), 'ledger-v052', 'validation',
    'evaluate', 'event', 'Fusion', 'LedgerValidation', '$ledgerRunId',
    concat('{"ledger_index":', toString(number), '}')
FROM (SELECT number FROM numbers(1001) UNION ALL SELECT toUInt64(0) AS number)
"@
Invoke-DetectionAdminInsert $ledgerInsert | Out-Null
$ledgerSourceRows = Invoke-DetectionQuery "SELECT count(), uniqExact(event_uid) FROM fusion.sysmon_events WHERE validation_id = '$ledgerRunId' FORMAT TSV"
if ($ledgerSourceRows -ne "1002`t1001") { throw "The duplicate-source ledger fixture is incomplete: $ledgerSourceRows" }
Invoke-DetectionAdminInsert "INSERT INTO fusion.detection_checkpoints (engine_id, checkpoint_time, checkpoint_uid, updated_at) VALUES ('$ledgerEngineId', toDateTime64('$ledgerEventTime', 3, 'UTC'), repeat('f', 64), now64(3))" | Out-Null
$ledgerRunArguments = @("run", "--rm", "--no-deps", "-e", "FUSION_DETECTION_ENGINE_ID=$ledgerEngineId", "-e", "FUSION_DETECTION_BATCH_SIZE=1000", "-e", "FUSION_DETECTION_LOOKBACK_SECONDS=0", "fusion-detection-engine", "run", "--once")
Invoke-FusionCompose -ComposeArguments $ledgerRunArguments
$firstLedgerPage = Invoke-DetectionQuery "SELECT count(), uniqExact(event_uid) FROM fusion.detection_evaluated_events WHERE engine_id = '$ledgerEngineId' AND validation_id = '$ledgerRunId' FORMAT TSV"
$firstMissing = Invoke-DetectionQuery "SELECT uniqExact(source.event_uid) FROM fusion.sysmon_events AS source LEFT ANTI JOIN (SELECT event_uid FROM fusion.detection_evaluated_events WHERE engine_id = '$ledgerEngineId') AS evaluated ON source.event_uid = evaluated.event_uid WHERE source.validation_id = '$ledgerRunId'"
if ($firstLedgerPage -ne "1000`t1000" -or $firstMissing -ne "1") {
    throw "The first bounded ledger page was not exactly 1,000/1 pending: ledger=$firstLedgerPage missing=$firstMissing"
}
Invoke-FusionCompose -ComposeArguments $ledgerRunArguments
$completeLedger = Invoke-DetectionQuery "SELECT count(), uniqExact(event_uid) FROM fusion.detection_evaluated_events WHERE engine_id = '$ledgerEngineId' AND validation_id = '$ledgerRunId' FORMAT TSV"
$completeMissing = Invoke-DetectionQuery "SELECT uniqExact(source.event_uid) FROM fusion.sysmon_events AS source LEFT ANTI JOIN (SELECT event_uid FROM fusion.detection_evaluated_events WHERE engine_id = '$ledgerEngineId') AS evaluated ON source.event_uid = evaluated.event_uid WHERE source.validation_id = '$ledgerRunId'"
$ledgerDetections = Invoke-DetectionQuery "SELECT count() FROM fusion.detections WHERE validation_id = '$ledgerRunId'"
$ledgerCheckpoint = Invoke-DetectionQuery "SELECT countIf(length(ruleset_fingerprint) = 64 AND isNotNull(evaluation_floor_time) AND checkpoint_uid = repeat('f', 64) AND unevaluated_event_count = 0) FROM fusion.detection_checkpoints FINAL WHERE engine_id = '$ledgerEngineId'"
if ($completeLedger -ne "1001`t1001" -or $completeMissing -ne "0" -or $ledgerDetections -ne "0" -or $ledgerCheckpoint -ne "1") {
    throw "Same-timestamp ledger recovery failed: ledger=$completeLedger missing=$completeMissing detections=$ledgerDetections checkpoint=$ledgerCheckpoint"
}
Invoke-FusionCompose -ComposeArguments $ledgerRunArguments
$replayLedger = Invoke-DetectionQuery "SELECT count(), uniqExact(event_uid) FROM fusion.detection_evaluated_events WHERE engine_id = '$ledgerEngineId' AND validation_id = '$ledgerRunId' FORMAT TSV"
if ($replayLedger -ne "1001`t1001") { throw "Same-timestamp replay amplified ledger rows: $replayLedger" }

Write-Host "[detections 7/8] Proving telemetry ingestion continues while detection is stopped..."
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

Write-Host "[detections 8/8] Validating the bounded dry-run plan and detection dashboard SQL..."
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

Write-Host "Cleaning synthetic detection validation rows..."
$cleanupStopped = $false
try {
    Invoke-FusionCompose stop fusion-detection-engine
    $cleanupStopped = $true
    Invoke-DetectionQuery "ALTER TABLE fusion.detection_evaluated_events DELETE WHERE validation_id IN ('$runId', '$secondRunId', '$ingestionRunId', '$ledgerRunId') SETTINGS mutations_sync = 2" | Out-Null
    Invoke-DetectionQuery "ALTER TABLE fusion.sysmon_events DELETE WHERE validation_id IN ('$runId', '$secondRunId', '$ingestionRunId', '$ledgerRunId') SETTINGS mutations_sync = 2" | Out-Null
    Invoke-DetectionQuery "ALTER TABLE fusion.detections DELETE WHERE validation_id IN ('$runId', '$secondRunId') SETTINGS mutations_sync = 2" | Out-Null
    Invoke-DetectionQuery "ALTER TABLE fusion.detection_checkpoints DELETE WHERE engine_id = '$engineId' SETTINGS mutations_sync = 2" | Out-Null
    Invoke-DetectionQuery "ALTER TABLE fusion.detection_checkpoints DELETE WHERE engine_id = '$ledgerEngineId' SETTINGS mutations_sync = 2" | Out-Null
    Invoke-DetectionQuery "ALTER TABLE fusion.detection_evaluation_scopes DELETE WHERE engine_id IN ('$engineId', '$ledgerEngineId') SETTINGS mutations_sync = 2" | Out-Null
} finally {
    if ($cleanupStopped) {
        Invoke-FusionCompose start fusion-detection-engine
        Invoke-FusionCompose up --detach --wait --wait-timeout 180 fusion-detection-engine
    }
}

Write-Host "Detection validation passed: rules, fixtures, 1,001-row ledger completeness, checkpoint telemetry, deduplication, restart, ingestion isolation, dry-run, and dashboard queries are healthy."
