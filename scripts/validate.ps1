[CmdletBinding()]
param(
    [switch] $SkipSamples
)

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine
$settings = Get-FusionSettings
$docker = Get-FusionDocker
$ingestPortNumber = if ($settings.ContainsKey("FUSION_INGEST_PORT") -and $settings.FUSION_INGEST_PORT) { [int]$settings.FUSION_INGEST_PORT } else { 8686 }
$syslogTcpPortNumber = if ($settings.ContainsKey("FUSION_SYSLOG_TCP_PORT") -and $settings.FUSION_SYSLOG_TCP_PORT) { [int]$settings.FUSION_SYSLOG_TCP_PORT } else { 5514 }
$syslogUdpPortNumber = if ($settings.ContainsKey("FUSION_SYSLOG_UDP_PORT") -and $settings.FUSION_SYSLOG_UDP_PORT) { [int]$settings.FUSION_SYSLOG_UDP_PORT } else { 5514 }
$grafanaPortNumber = if ($settings.ContainsKey("FUSION_GRAFANA_PORT") -and $settings.FUSION_GRAFANA_PORT) { [int]$settings.FUSION_GRAFANA_PORT } else { 3000 }

Write-Host "[1/12] Validating Docker Compose and secure HTTP/syslog bind modes..."
Invoke-FusionCompose config --quiet
$hadBindAddress = Test-Path Env:FUSION_BIND_ADDRESS
$originalBindAddress = if ($hadBindAddress) { $env:FUSION_BIND_ADDRESS } else { $null }
$hadSyslogBindAddress = Test-Path Env:FUSION_SYSLOG_BIND_ADDRESS
$originalSyslogBindAddress = if ($hadSyslogBindAddress) { $env:FUSION_SYSLOG_BIND_ADDRESS } else { $null }
try {
    foreach ($binding in @("127.0.0.1", "192.0.2.10")) {
        $env:FUSION_BIND_ADDRESS = $binding
        $env:FUSION_SYSLOG_BIND_ADDRESS = $binding
        $json = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile config --format json
        if ($LASTEXITCODE -ne 0) {
            throw "Compose rendering failed for FUSION_BIND_ADDRESS=$binding."
        }
        $model = $json | ConvertFrom-Json
        $ingestPort = $model.services.vector.ports | Where-Object { $_.target -eq 8686 } | Select-Object -First 1
        if (-not $ingestPort -or $ingestPort.host_ip -ne $binding) {
            throw "Expected ingestion to bind to $binding; rendered port was $($ingestPort | ConvertTo-Json -Compress)."
        }
        $syslogTcpPort = $model.services.vector.ports | Where-Object { $_.target -eq 5514 -and $_.protocol -eq "tcp" } | Select-Object -First 1
        $syslogUdpPort = $model.services.vector.ports | Where-Object { $_.target -eq 5514 -and $_.protocol -eq "udp" } | Select-Object -First 1
        if (-not $syslogTcpPort -or $syslogTcpPort.host_ip -ne $binding -or -not $syslogUdpPort -or $syslogUdpPort.host_ip -ne $binding) {
            throw "Expected TCP/UDP syslog to bind to $binding."
        }
    }
} finally {
    if ($hadBindAddress) {
        $env:FUSION_BIND_ADDRESS = $originalBindAddress
    } else {
        Remove-Item Env:FUSION_BIND_ADDRESS -ErrorAction SilentlyContinue
    }
    if ($hadSyslogBindAddress) {
        $env:FUSION_SYSLOG_BIND_ADDRESS = $originalSyslogBindAddress
    } else {
        Remove-Item Env:FUSION_SYSLOG_BIND_ADDRESS -ErrorAction SilentlyContinue
    }
}

Write-Host "[2/12] Running collector Vector configuration and VRL unit tests..."
Invoke-FusionCompose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml
Invoke-FusionCompose run --rm --no-deps vector test /etc/vector/vector.yaml

Write-Host "[3/12] Validating the Suricata EVE Vector integration configuration..."
$suricataTestRoot = Join-Path ([IO.Path]::GetTempPath()) ("fusion-suricata-test-" + [Guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $suricataTestRoot)
try {
    [IO.File]::WriteAllText((Join-Path $suricataTestRoot "eve.json"), "", [Text.UTF8Encoding]::new($false))
    $suricataTemplate = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "integrations\suricata\vector.yaml.template"))
    $suricataRendered = $suricataTemplate.Replace("__FUSION_DATA_DIR__", "/tmp/fusion-suricata-data").Replace("__FUSION_LOG_DIR__", "/tmp/fusion-suricata-logs").Replace("__FUSION_COLLECTOR_URL__", "http://192.0.2.10:8686/security").Replace("__FUSION_COLLECTOR_IP__", "192.0.2.10").Replace("__FUSION_COLLECTOR_PORT__", "8686").Replace("__SURICATA_EVE_PATH__", "/test/eve.json").Replace("__SURICATA_SENSOR_NAME__", "suricata-test-sensor")
    if (-not $suricataRendered.Contains('destination_ip == "192.0.2.10" && destination_port == 8686')) {
        throw "Rendered Suricata configuration is missing the collector feedback-loop exclusion."
    }
    [IO.File]::WriteAllText((Join-Path $suricataTestRoot "vector.yaml"), $suricataRendered, [Text.UTF8Encoding]::new($false))
    & $docker run --rm --volume "$suricataTestRoot`:/test:ro" timberio/vector:0.58.0-alpine validate --no-environment --skip-healthchecks --config-yaml /test/vector.yaml
    if ($LASTEXITCODE -ne 0) { throw "Suricata EVE Vector integration configuration is invalid." }
    & $docker run --rm --volume "$suricataTestRoot`:/test:ro" timberio/vector:0.58.0-alpine test --config-yaml /test/vector.yaml
    if ($LASTEXITCODE -ne 0) { throw "Suricata EVE Vector integration unit tests failed." }
} finally {
    Remove-Item -LiteralPath $suricataTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[4/12] Checking the live common ClickHouse and detection schemas..."
$requiredColumns = @(
    "provider_name", "record_id", "image_loaded", "query_name", "query_status", "query_results",
    "target_filename", "target_object", "registry_details", "message", "host_name", "platform",
    "source_type", "event_category", "event_action", "event_code", "source_event_id", "user_name",
    "user_id", "process_name", "process_path", "parent_process_name", "parent_process_id", "service_name",
    "outcome", "severity", "device_name", "vendor", "product", "event_kind",
    "ingestion_protocol", "ingestion_path", "source_address", "original_format",
    "network_direction", "rule_id", "signature", "signature_id", "url", "domain",
    "syslog_facility", "syslog_application"
)
$quotedColumns = ($requiredColumns | ForEach-Object { "'$_'" }) -join ","
$schemaQuery = "SELECT count() FROM system.columns WHERE database = 'fusion' AND table = 'sysmon_events' AND name IN ($quotedColumns)"
$schemaCount = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $schemaQuery
if ($LASTEXITCODE -ne 0 -or [int]$schemaCount.Trim() -ne $requiredColumns.Count) {
    throw "ClickHouse common event columns are missing. Run scripts/deploy.ps1 to apply migrations."
}
$detectionSchemaQuery = "SELECT countIf(table = 'sysmon_events' AND name = 'event_uid'), countIf(table = 'detections'), countIf(table = 'detection_checkpoints') FROM system.columns WHERE database = 'fusion' FORMAT TSV"
$detectionSchema = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $detectionSchemaQuery
if ($LASTEXITCODE -ne 0 -or $detectionSchema.Trim() -ne "1`t35`t4") {
    throw "ClickHouse v0.5 detection schema is incomplete: $detectionSchema"
}

Write-Host "[5/12] Proving the v0.2-to-v0.3 and v0.3-to-v0.4 migrations preserve rows..."
$v02Schema = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\tests\002_v02_schema.sql"))
$v02Schema | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
if ($LASTEXITCODE -ne 0) { throw "Could not create the isolated v0.2 migration fixture." }
try {
    $migration = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\migrations\003_common_security_events_v03.sql"))
    $isolatedMigration = $migration.Replace("fusion.sysmon_events", "fusion_v03_migration_test.sysmon_events")
    $isolatedMigration | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
    if ($LASTEXITCODE -ne 0) { throw "The isolated v0.2-to-v0.3 migration failed." }
    $migrationQuery = "SELECT count(), countIf(platform = 'windows' AND host_name = 'V02-HOST' AND endsWith(process_path, 'cmd.exe') AND JSONExtractString(raw_json, 'v') = '0.2') FROM fusion_v03_migration_test.sysmon_events FORMAT TSV"
    $migrationResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $migrationQuery
    if ($LASTEXITCODE -ne 0 -or $migrationResult.Trim() -ne "1`t1") {
        throw "Existing v0.2 data was not preserved with compatible defaults: $migrationResult"
    }
} finally {
    & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query "DROP DATABASE IF EXISTS fusion_v03_migration_test" | Out-Null
}

$v03Schema = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\tests\003_v03_schema.sql"))
$v03Schema | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
if ($LASTEXITCODE -ne 0) { throw "Could not create the isolated v0.3 migration fixture." }
try {
    $v04Migration = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\migrations\004_security_tool_ingestion_v04.sql"))
    $isolatedV04Migration = $v04Migration.Replace("fusion.sysmon_events", "fusion_v04_migration_test.sysmon_events")
    $isolatedV04Migration | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
    if ($LASTEXITCODE -ne 0) { throw "The isolated v0.3-to-v0.4 migration failed." }
    $v04MigrationQuery = "SELECT count(), countIf(platform = 'windows' AND vendor = 'Microsoft' AND product = 'Sysmon' AND ingestion_path = '/sysmon' AND JSONExtractString(raw_json, 'version') = '0.3' AND JSONExtractString(raw_json, 'platform') = 'windows'), countIf(platform = 'linux' AND vendor = 'Fusion' AND product = 'Linux' AND ingestion_path = '/linux' AND JSONExtractString(raw_json, 'version') = '0.3' AND JSONExtractString(raw_json, 'platform') = 'linux') FROM fusion_v04_migration_test.sysmon_events FORMAT TSV"
    $v04MigrationResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $v04MigrationQuery
    if ($LASTEXITCODE -ne 0 -or $v04MigrationResult.Trim() -ne "2`t1`t1") {
        throw "Existing v0.3 Windows/Linux data was not preserved with v0.4 defaults: $v04MigrationResult"
    }
} finally {
    & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query "DROP DATABASE IF EXISTS fusion_v04_migration_test" | Out-Null
}

Write-Host "[6/12] Proving the v0.4-to-v0.5 migration is preserving and idempotent..."
$v04Schema = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\tests\004_v04_schema.sql"))
$v04Schema | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
if ($LASTEXITCODE -ne 0) { throw "Could not create the isolated v0.4 migration fixture." }
try {
    $v05Migration = [IO.File]::ReadAllText((Join-Path $script:FusionRoot "clickhouse\migrations\005_detection_engine_v05.sql"))
    $isolatedV05Migration = $v05Migration.Replace("fusion.sysmon_events", "fusion_v05_migration_test.sysmon_events").Replace("fusion.detections", "fusion_v05_migration_test.detections").Replace("fusion.detection_checkpoints", "fusion_v05_migration_test.detection_checkpoints")
    foreach ($execution in 1..2) {
        $isolatedV05Migration | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
        if ($LASTEXITCODE -ne 0) { throw "The isolated v0.4-to-v0.5 migration failed on execution $execution." }
    }
    $v05MigrationQuery = "SELECT count(), countIf(platform = 'windows'), countIf(platform = 'linux'), countIf(source_type = 'suricata_eve'), countIf(source_type = 'generic_syslog'), uniqExact(event_uid), countIf(length(event_uid) = 64) FROM fusion_v05_migration_test.sysmon_events FORMAT TSV"
    $v05MigrationResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $v05MigrationQuery
    if ($LASTEXITCODE -ne 0 -or $v05MigrationResult.Trim() -ne "4`t1`t1`t1`t1`t4`t4") {
        throw "Existing v0.4 data was not preserved with deterministic event identities: $v05MigrationResult"
    }
} finally {
    & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query "DROP DATABASE IF EXISTS fusion_v05_migration_test" | Out-Null
}

Write-Host "[7/12] Checking container health..."
foreach ($service in @("clickhouse", "vector", "grafana", "fusion-detection-engine")) {
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
$securitySampleFiles = @(Get-ChildItem -LiteralPath (Join-Path $script:FusionRoot "samples\security-tools") -Filter "suricata-*.json" | Sort-Object Name)
$sampleFiles = @($v01SampleFiles) + @($windowsSampleFiles)

if (-not $SkipSamples) {
    Write-Host "[8/12] Sending Windows, Linux, security JSON, and TCP/UDP syslog fixtures..."
    $ingestHost = if ($settings.ContainsKey("FUSION_BIND_ADDRESS") -and $settings.FUSION_BIND_ADDRESS) { $settings.FUSION_BIND_ADDRESS } else { "127.0.0.1" }
    $ingestUri = "http://$ingestHost`:$ingestPortNumber/sysmon"
    $headers = @{ "X-Fusion-Validation-Id" = $runId }

    foreach ($sampleFile in $v01SampleFiles) {
        $payload = Get-Content -LiteralPath $sampleFile.FullName -Raw | ConvertFrom-Json
        $now = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        if (($payload.PSObject.Properties.Name -contains "Event") -and $payload.Event.EventData) {
            $payload.Event.EventData.UtcTime = $now
        }
        $body = $payload | ConvertTo-Json -Depth 20 -Compress
        $response = Invoke-WebRequest -UseBasicParsing -Uri $ingestUri -Method Post -Headers $headers -ContentType "application/json" -Body $body
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
        $response = Invoke-WebRequest -UseBasicParsing -Uri $ingestUri -Method Post -Headers $headers -ContentType "application/json" -Body $body
        if ($response.StatusCode -ne 202) {
            throw "Vector rejected $($sampleFile.Name) with HTTP $($response.StatusCode)."
        }
    }
    $linuxIngestUri = "http://$ingestHost`:$ingestPortNumber/linux"
    $epochSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($sampleFile in $linuxSampleFiles) {
        $body = Get-Content -LiteralPath $sampleFile.FullName -Raw
        $body = [regex]::Replace($body, '"timestamp"\s*:\s*"[^"]+"', ('"timestamp":"{0}"' -f ([DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))))
        $body = [regex]::Replace($body, 'audit\([0-9]+(?:\.[0-9]+)?:', "audit($epochSeconds.125:")
        $response = Invoke-WebRequest -UseBasicParsing -Uri $linuxIngestUri -Method Post -Headers $headers -ContentType "application/json" -Body $body
        if ($response.StatusCode -ne 202) {
            throw "Vector rejected $($sampleFile.Name) with HTTP $($response.StatusCode)."
        }
    }

    $securityIngestUri = "http://$ingestHost`:$ingestPortNumber/security"
    foreach ($sampleFile in $securitySampleFiles) {
        $payload = Get-Content -LiteralPath $sampleFile.FullName -Raw | ConvertFrom-Json
        $payload.event.timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $body = $payload | ConvertTo-Json -Depth 30 -Compress
        $response = Invoke-WebRequest -UseBasicParsing -Uri $securityIngestUri -Method Post -Headers $headers -ContentType "application/json" -Body $body
        if ($response.StatusCode -ne 202) {
            throw "Vector rejected $($sampleFile.Name) with HTTP $($response.StatusCode)."
        }
    }

    $syslogHost = if ($settings.ContainsKey("FUSION_SYSLOG_BIND_ADDRESS") -and $settings.FUSION_SYSLOG_BIND_ADDRESS) { $settings.FUSION_SYSLOG_BIND_ADDRESS } else { "127.0.0.1" }
    $rfc3164 = (Get-Content -LiteralPath (Join-Path $script:FusionRoot "samples\security-tools\rfc3164.log") -Raw).TrimEnd() + " validation_id=$runId"
    $tcpClient = [Net.Sockets.TcpClient]::new()
    try {
        $tcpClient.Connect($syslogHost, $syslogTcpPortNumber)
        $tcpBytes = [Text.UTF8Encoding]::new($false).GetBytes($rfc3164 + "`n")
        $tcpClient.GetStream().Write($tcpBytes, 0, $tcpBytes.Length)
    } finally {
        $tcpClient.Dispose()
    }

    $udpClient = [Net.Sockets.UdpClient]::new()
    try {
        foreach ($syslogFile in @("rfc5424.log", "unknown-valid-syslog.log")) {
            $syslogMessage = (Get-Content -LiteralPath (Join-Path $script:FusionRoot "samples\security-tools\$syslogFile") -Raw).TrimEnd() + " validation_id=$runId"
            $udpBytes = [Text.UTF8Encoding]::new($false).GetBytes($syslogMessage)
            [void]$udpClient.Send($udpBytes, $udpBytes.Length, $syslogHost, $syslogUdpPortNumber)
        }
    } finally {
        $udpClient.Dispose()
    }
} else {
    Write-Host "[8/12] Sample ingestion skipped."
}

Write-Host "[9/12] Verifying v0.1-v0.4 compatibility and normalized telemetry..."
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

    $securityQuery = "SELECT count(), countIf(event_action = 'network_alert'), countIf(event_action = 'dns_query' AND domain = 'fusion-test.example'), countIf(event_action = 'http_request' AND url = 'http://web.fusion-test.example/health'), countIf(event_action = 'tls_session' AND domain = 'tls.fusion-test.example'), countIf(event_action = 'network_flow'), countIf(vendor = 'OISF' AND product = 'Suricata' AND source_type = 'suricata_eve'), countIf(source_address != ''), countIf(position(raw_json, 'flow_id') > 0) FROM fusion.sysmon_events WHERE validation_id = '$runId' AND ingestion_path = '/security' FORMAT TSV"
    $syslogQuery = "SELECT count(), countIf(ingestion_protocol = 'syslog_tcp'), countIf(ingestion_protocol = 'syslog_udp'), countIf(original_format = 'rfc3164'), countIf(original_format = 'rfc5424'), countIf(product = 'mystery-app' AND position(raw_json, 'opaque vendor payload') > 0), countIf(source_address != ''), countIf(source_ip = '') FROM fusion.sysmon_events WHERE position(raw_json, '$runId') > 0 AND source_type = 'generic_syslog' FORMAT TSV"
    $securityResult = ""
    $syslogResult = ""
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $securityResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $securityQuery
        if ($LASTEXITCODE -ne 0) { throw "ClickHouse security JSON validation query failed." }
        $syslogResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $syslogQuery
        if ($LASTEXITCODE -ne 0) { throw "ClickHouse syslog validation query failed." }
        $securityValues = $securityResult.Trim() -split "`t"
        $syslogValues = $syslogResult.Trim() -split "`t"
        if ($securityValues.Count -eq 9 -and [int]$securityValues[0] -ge $securitySampleFiles.Count -and $syslogValues.Count -eq 8 -and [int]$syslogValues[0] -ge 3) { break }
        Start-Sleep -Seconds 1
    }
    $securityValues = $securityResult.Trim() -split "`t"
    if ($securityValues.Count -ne 9 -or [int]$securityValues[0] -ne 5 -or [int]$securityValues[1] -ne 1 -or [int]$securityValues[2] -ne 1 -or [int]$securityValues[3] -ne 1 -or [int]$securityValues[4] -ne 1 -or [int]$securityValues[5] -ne 1 -or [int]$securityValues[6] -ne 5 -or [int]$securityValues[7] -ne 5 -or [int]$securityValues[8] -ne 5) {
        throw "Unexpected normalized security-tool telemetry: $securityResult"
    }
    $syslogValues = $syslogResult.Trim() -split "`t"
    if ($syslogValues.Count -ne 8 -or [int]$syslogValues[0] -ne 3 -or [int]$syslogValues[1] -ne 1 -or [int]$syslogValues[2] -ne 2 -or [int]$syslogValues[3] -ne 1 -or [int]$syslogValues[4] -ne 2 -or [int]$syslogValues[5] -ne 1 -or [int]$syslogValues[6] -ne 3 -or [int]$syslogValues[7] -ne 3) {
        throw "Unexpected normalized TCP/UDP syslog telemetry: $syslogResult"
    }
    Write-Host "  SuricataRows=$($securityValues[0]), SyslogRows=$($syslogValues[0]), TCP=$($syslogValues[1]), UDP=$($syslogValues[2])"
}

Write-Host "[10/12] Validating endpoint and security-source dashboard queries..."
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

$securityDashboardPath = Join-Path $script:FusionRoot "grafana\dashboards\fusion-security-sources.json"
$securityDashboard = Get-Content -LiteralPath $securityDashboardPath -Raw | ConvertFrom-Json
$securityPanelTitles = @($securityDashboard.panels | ForEach-Object { $_.title })
$requiredSecurityPanels = @("Security tool events", "Suricata alerts", "Syslog events", "Network activity", "Security source activity over time", "Events by vendor", "Events by product", "Events by source type", "Events by ingestion protocol", "Top Suricata signatures", "Top source IPs", "Top destination IPs", "DNS activity", "HTTP activity", "Recent security alerts")
foreach ($requiredTitle in $requiredSecurityPanels) {
    if ($securityPanelTitles -notcontains $requiredTitle) { throw "Fusion Security Sources is missing the '$requiredTitle' panel." }
}
$requiredSecurityVariables = @("computer", "platform", "vendor", "product", "source", "ingestion")
foreach ($requiredVariable in $requiredSecurityVariables) {
    if (@($securityDashboard.templating.list.name) -notcontains $requiredVariable) { throw "Fusion Security Sources is missing the '$requiredVariable' filter." }
}
if (-not $SkipSamples) {
    foreach ($panel in $securityDashboard.panels) {
        $panelQuery = $panel.targets[0].rawSql.Replace('$__timeFilter(event_time)', "event_time >= now() - INTERVAL 1 DAY")
        $panelQuery = $panelQuery.Replace('$__timeInterval(event_time)', 'toStartOfMinute(event_time)')
        foreach ($filterField in @("host_name", "platform", "vendor", "product", "source_type", "ingestion_protocol")) {
            $variableName = switch ($filterField) { "host_name" { "computer" } "source_type" { "source" } "ingestion_protocol" { "ingestion" } default { $filterField } }
            $filterExpression = "match({0}, '`${{{1}:regex}}')" -f $filterField, $variableName
            $panelQuery = $panelQuery.Replace($filterExpression, "1")
        }
        $panelResult = & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --query $panelQuery
        if ($LASTEXITCODE -ne 0 -or -not ($panelResult | Out-String).Trim()) { throw "The '$($panel.title)' security dashboard query failed or returned no telemetry." }
    }
}

Write-Host "[11/12] Running detection engine acceptance tests..."
& (Join-Path $PSScriptRoot "validate-detections.ps1")
if ($LASTEXITCODE -ne 0) { throw "Detection engine validation failed." }

Write-Host "[12/12] Checking Grafana, its data source, and all provisioned dashboards..."
$grafanaBase = "http://127.0.0.1:$grafanaPortNumber"
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

$securityDashboards = Invoke-RestMethod -Uri "$grafanaBase/api/search?query=Fusion%20Security%20Sources" -Headers $authHeaders
if (-not ($securityDashboards | Where-Object { $_.uid -eq "fusion-security-sources" })) {
    throw "Fusion Security Sources dashboard was not provisioned."
}
$provisionedSecurityDashboard = (Invoke-RestMethod -Uri "$grafanaBase/api/dashboards/uid/fusion-security-sources" -Headers $authHeaders).dashboard
foreach ($requiredTitle in @("Suricata alerts", "Syslog events", "Events by vendor", "Events by ingestion protocol", "DNS activity", "HTTP activity", "Recent security alerts")) {
    if (@($provisionedSecurityDashboard.panels.title) -notcontains $requiredTitle) { throw "The provisioned Fusion Security Sources dashboard is missing '$requiredTitle'." }
}
foreach ($requiredVariable in $requiredSecurityVariables) {
    if (@($provisionedSecurityDashboard.templating.list.name) -notcontains $requiredVariable) { throw "The provisioned Fusion Security Sources dashboard is missing '$requiredVariable'." }
}

$detectionDashboards = Invoke-RestMethod -Uri "$grafanaBase/api/search?query=Fusion%20Detections" -Headers $authHeaders
if (-not ($detectionDashboards | Where-Object { $_.uid -eq "fusion-detections" })) {
    throw "Fusion Detections dashboard was not provisioned."
}
$provisionedDetectionDashboard = (Invoke-RestMethod -Uri "$grafanaBase/api/dashboards/uid/fusion-detections" -Headers $authHeaders).dashboard
foreach ($requiredTitle in @("Total detections", "New detections", "High/Critical detections", "Detections over time", "Detections by severity", "Detections by rule", "Detections by platform", "Detections by source type", "Detections by host", "Top affected users", "Top source IPs", "Top destination IPs", "MITRE tactics", "MITRE techniques", "Recent detections")) {
    if (@($provisionedDetectionDashboard.panels.title) -notcontains $requiredTitle) { throw "The provisioned Fusion Detections dashboard is missing '$requiredTitle'." }
}
foreach ($requiredVariable in @("severity", "status", "platform", "host", "rule", "tactic", "technique")) {
    if (@($provisionedDetectionDashboard.templating.list.name) -notcontains $requiredVariable) { throw "The provisioned Fusion Detections dashboard is missing '$requiredVariable'." }
}

Write-Host "Validation passed: v0.1-v0.4 ingestion, v0.5 detections, migrations, restart safety, storage, and all dashboards are healthy."
