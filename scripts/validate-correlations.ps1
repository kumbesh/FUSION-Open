[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine
$settings = Get-FusionSettings
$docker = Get-FusionDocker

function Invoke-CorrelationQuery {
    param([Parameter(Mandatory = $true)][string] $Query)
    $output = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $Query
    if ($LASTEXITCODE -ne 0) { throw "ClickHouse correlation query failed." }
    return ($output | Out-String).Trim()
}

function Invoke-CorrelationAdmin {
    param([Parameter(Mandatory = $true)][string] $Query)
    $output = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --async_insert=0 --query $Query
    if ($LASTEXITCODE -ne 0) { throw "ClickHouse correlation admin command failed." }
    return ($output | Out-String).Trim()
}

$runId = "fusion-v06-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))-$PID"
$engineId = "fusion-correlation-validation-$runId"
$hostName = "$runId.invalid"
$firstDetection = "$runId-detection-1"
$secondDetection = "$runId-detection-2"
$schemaDatabase = "fusion_v06_validation_$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))_$PID"
$serviceStopped = $false
$smokeSeeded = $false
$schemaDatabaseCreated = $false

try {
    Write-Host "[correlations 1/5] Validating exactly four frozen correlation rules offline..."
    Invoke-FusionCompose -ComposeArguments @("run", "--rm", "--no-deps", "fusion-correlation-engine", "validate-rules", "--expected-count", "4")

    Write-Host "[correlations 2/5] Running Python correlation tests in an ephemeral built-image container..."
    $testCommand = "python -m pip install --quiet --target /tmp/fusion-pytest pytest==9.1.1 && PYTHONPATH=/tmp/fusion-pytest:/work/correlation/engine python -m pytest -p no:cacheprovider /work/correlation/tests /work/tests/grafana"
    Invoke-FusionCompose -ComposeArguments @("run", "--rm", "--no-deps", "--user", "0", "--entrypoint", "/bin/sh", "--workdir", "/work/correlation/engine", "-v", "${script:FusionRoot}:/work:ro", "fusion-correlation-engine", "-c", $testCommand)

    Write-Host "[correlations 3/5] Verifying live and isolated v0.6 schema/view contracts..."
    $liveSchema = Invoke-CorrelationQuery "SELECT countIf(engine NOT IN ('View','MaterializedView')), countIf(engine = 'View'), countIf(engine = 'MaterializedView') FROM system.tables WHERE database = 'fusion' AND name IN ('correlation_detection_input_history','correlation_detection_input_history_mv','correlation_detection_input_witness','correlation_detection_input_witness_mv','correlation_integrity_events','correlation_integrity_scope_state_current','incidents','incident_detection_links','incident_event_links','correlation_evaluated_inputs','correlation_rule_state','correlation_episode_state','correlation_scope_bootstrap_confirmations','correlation_schedule_state','incident_status_transitions','correlation_evaluated_inputs_current','incident_status_transitions_current','correlation_scope_bootstrap_confirmations_current','correlation_rule_state_current','correlation_episode_state_current','correlation_schedule_state_current','incident_detection_links_current','incident_event_links_current','incident_revisions_committed','incidents_current','incident_timeline') FORMAT TSV"
    if ($liveSchema -ne "12`t12`t2") { throw "ClickHouse v0.6 correlation schema is incomplete: $liveSchema" }

    Invoke-CorrelationAdmin "CREATE DATABASE $schemaDatabase" | Out-Null
    $schemaDatabaseCreated = $true
    $sourceFixture = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\tests\010_v06_source_fixture.sql")).Replace("fusion.", "$schemaDatabase.")
    $migration = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\migrations\010_correlation_incidents_v06.sql")).Replace("fusion.", "$schemaDatabase.")
    $integrityMigration = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\migrations\011_correlation_integrity_v06.sql")).Replace("fusion.", "$schemaDatabase.")
    $schemaTest = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\tests\010_v06_correlation_schema.sql")).Replace("fusion.", "$schemaDatabase.")
    $integritySchemaTest = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\tests\011_v06_correlation_integrity_schema.sql")).Replace("fusion.", "$schemaDatabase.")
    $sourceFixture | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --database $schemaDatabase --multiquery | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Isolated v0.6 source fixture failed." }
    foreach ($execution in 1..2) {
        $migration | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --database $schemaDatabase --multiquery | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Isolated v0.6 migration failed on execution $execution." }
    }
    $schemaResult = $schemaTest | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --async_insert=0 --database $schemaDatabase --multiquery
    if ($LASTEXITCODE -ne 0 -or ($schemaResult | Select-Object -Last 1) -ne "v0.6 correlation schema regression passed") {
        throw "The isolated v0.6 schema regression did not report success."
    }
    foreach ($execution in 1..2) {
        $integrityMigration | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --database $schemaDatabase --multiquery | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Isolated v0.6 integrity migration failed on execution $execution." }
    }
    $integritySchemaResult = $integritySchemaTest | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --async_insert=0 --database $schemaDatabase --multiquery
    if ($LASTEXITCODE -ne 0 -or ($integritySchemaResult | Select-Object -Last 1) -ne "v0.6 correlation integrity schema regression passed") {
        throw "The isolated v0.6 correlation-integrity schema regression did not report success."
    }
    foreach ($execution in 3..4) {
        $integrityMigration | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --database $schemaDatabase --multiquery | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Populated v0.6 integrity migration reapplication failed on execution $execution." }
    }
    $postPopulationReapplyQuery = "SELECT (SELECT count() FROM (SELECT DISTINCT detection_id, detected_at, semantic_fingerprint FROM $schemaDatabase.correlation_detection_input_history EXCEPT DISTINCT SELECT DISTINCT detection_id, detected_at, semantic_fingerprint FROM $schemaDatabase.correlation_detection_input_witness)), (SELECT count() FROM (SELECT DISTINCT detection_id, detected_at, semantic_fingerprint FROM $schemaDatabase.correlation_detection_input_witness EXCEPT DISTINCT SELECT DISTINCT detection_id, detected_at, semantic_fingerprint FROM $schemaDatabase.correlation_detection_input_history)), (SELECT count() FROM $schemaDatabase.correlation_integrity_events), (SELECT uniqExact(integrity_event_id) FROM $schemaDatabase.correlation_integrity_events), (SELECT count() FROM $schemaDatabase.correlation_integrity_scope_state_current) FORMAT TSV"
    $postPopulationReapply = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --database $schemaDatabase --query $postPopulationReapplyQuery
    if ($LASTEXITCODE -ne 0 -or ($postPopulationReapply | Out-String).Trim() -ne "0`t0`t6`t5`t1") {
        throw "Populated v0.6 integrity migration reapplication changed logical history or integrity state: $postPopulationReapply"
    }
    Invoke-CorrelationAdmin "DROP DATABASE $schemaDatabase" | Out-Null
    $schemaDatabaseCreated = $false

    Write-Host "[correlations 4/5] Running a tagged synthetic host-correlation smoke..."
    Invoke-FusionCompose stop fusion-correlation-engine
    $serviceStopped = $true
    $seed = @"
INSERT INTO fusion.detections
    (detection_id, detected_at, updated_at, rule_id, rule_name, rule_version,
     severity, status, platform, vendor, product, source_type, host_name,
     source_event_uid, source_event_id, source_event_time, validation_id,
     evidence_json, rule_metadata_json)
VALUES
    ('$firstDetection', now64(3), now64(3), 'fusion-validation-rule-one',
     'Fusion synthetic correlation validation one', '1', 'high', 'new',
     'windows', 'Fusion', 'Validation', 'fusion_validation', '$hostName',
     '$runId-event-1', '$runId-source-1', now64(3) - INTERVAL 2 SECOND,
     '$runId', '{}', '{}'),
    ('$secondDetection', now64(3), now64(3), 'fusion-validation-rule-two',
     'Fusion synthetic correlation validation two', '1', 'medium', 'new',
     'windows', 'Fusion', 'Validation', 'fusion_validation', '$hostName',
     '$runId-event-2', '$runId-source-2', now64(3) - INTERVAL 1 SECOND,
     '$runId', '{}', '{}')
"@
    Invoke-CorrelationAdmin $seed | Out-Null
    $smokeSeeded = $true
    $smokeArguments = @("run", "--rm", "--no-deps", "-e", "FUSION_CORRELATION_ENGINE_ID=$engineId", "-e", "FUSION_CORRELATION_LOOKBACK_SECONDS=60", "-e", "FUSION_CORRELATION_BATCH_SIZE=10000", "fusion-correlation-engine", "run", "--once")
    Invoke-FusionCompose -ComposeArguments $smokeArguments
    $smokeResult = Invoke-CorrelationQuery "SELECT (SELECT count() FROM fusion.incidents_current WHERE validation_id = '$runId' AND correlation_rule_id = 'fusion-correlation-host-suspicious-activity' AND input_count = 2 AND detection_count = 2 AND event_count = 0), (SELECT count() FROM fusion.incident_detection_links_current WHERE validation_id = '$runId'), (SELECT count() FROM fusion.incident_event_links_current WHERE validation_id = '$runId'), (SELECT count() FROM fusion.correlation_evaluated_inputs_current WHERE engine_id = '$engineId' AND validation_id = '$runId'), (SELECT uniqExact(tuple(correlation_rule_id, input_kind, input_id)) FROM fusion.correlation_evaluated_inputs_current WHERE engine_id = '$engineId' AND validation_id = '$runId'), (SELECT countIf(evaluation_action = 'created') FROM fusion.correlation_evaluated_inputs_current WHERE engine_id = '$engineId' AND validation_id = '$runId' AND correlation_rule_id = 'fusion-correlation-host-suspicious-activity'), (SELECT count() FROM fusion.incident_timeline WHERE validation_id = '$runId') FORMAT TSV"
    if ($smokeResult -ne "1`t2`t0`t8`t8`t1`t2") { throw "Unexpected synthetic correlation result: $smokeResult" }

    Write-Host "[correlations 5/5] Replaying the smoke and proving logical idempotence..."
    $beforeReplay = Invoke-CorrelationQuery "SELECT (SELECT count() FROM fusion.incidents WHERE validation_id = '$runId'), (SELECT count() FROM fusion.incident_detection_links WHERE validation_id = '$runId'), (SELECT count() FROM fusion.correlation_evaluated_inputs WHERE engine_id = '$engineId' AND validation_id = '$runId') FORMAT TSV"
    Invoke-FusionCompose -ComposeArguments $smokeArguments
    $afterReplay = Invoke-CorrelationQuery "SELECT (SELECT count() FROM fusion.incidents WHERE validation_id = '$runId'), (SELECT count() FROM fusion.incident_detection_links WHERE validation_id = '$runId'), (SELECT count() FROM fusion.correlation_evaluated_inputs WHERE engine_id = '$engineId' AND validation_id = '$runId') FORMAT TSV"
    if ($afterReplay -ne $beforeReplay -or $afterReplay -ne "1`t2`t8") {
        throw "Correlation replay amplified physical effects: before=$beforeReplay after=$afterReplay"
    }
    $statusOutput = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile run --rm --no-deps -e "FUSION_CORRELATION_ENGINE_ID=$engineId" fusion-correlation-engine status
    if ($LASTEXITCODE -ne 0) { throw "Correlation status query failed." }
    $status = ($statusOutput | Out-String) | ConvertFrom-Json
    if ($status.schema -ne "fusion-correlation-status/v1" -or [int]$status.scope_count -ne 4) {
        throw "Correlation status telemetry is incomplete."
    }
} finally {
    if ($schemaDatabaseCreated) {
        try { Invoke-CorrelationQuery "DROP DATABASE IF EXISTS $schemaDatabase" | Out-Null } catch { Write-Warning $_ }
    }
    if ($smokeSeeded) {
        foreach ($query in @(
            "ALTER TABLE fusion.incident_detection_links DELETE WHERE validation_id = '$runId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.incident_event_links DELETE WHERE validation_id = '$runId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.incidents DELETE WHERE validation_id = '$runId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.correlation_evaluated_inputs DELETE WHERE engine_id = '$engineId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.correlation_episode_state DELETE WHERE engine_id = '$engineId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.correlation_rule_state DELETE WHERE engine_id = '$engineId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.correlation_scope_bootstrap_confirmations DELETE WHERE engine_id = '$engineId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.correlation_schedule_state DELETE WHERE engine_id = '$engineId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.correlation_detection_input_witness DELETE WHERE detection_id IN ('$firstDetection', '$secondDetection') SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.correlation_detection_input_history DELETE WHERE validation_id = '$runId' SETTINGS mutations_sync = 2",
            "ALTER TABLE fusion.detections DELETE WHERE validation_id = '$runId' SETTINGS mutations_sync = 2"
        )) {
            try { Invoke-CorrelationQuery $query | Out-Null } catch { Write-Warning $_ }
        }
    }
    if ($serviceStopped) {
        Invoke-FusionCompose start fusion-correlation-engine
        Invoke-FusionCompose up --detach --wait --wait-timeout 180 fusion-correlation-engine
    }
}

Write-Host "Correlation validation passed: four rules, Python regressions, v0.6 schema/replay contracts, exact ledger coverage, one synthetic host incident, two evidence links, status telemetry, and idempotent replay are healthy. This is synthetic validation, not real v0.6 acceptance evidence."
