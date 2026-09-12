#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

fusion_assert_engine
fusion_load_env

query_clickhouse() {
  fusion_compose exec -T clickhouse clickhouse-client \
    --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$1"
}

insert_clickhouse_admin() {
  fusion_compose exec -T clickhouse clickhouse-client \
    --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --async_insert=0 --query "$1"
}

run_id="fusion-v05-$(date -u '+%Y%m%d%H%M%S')-$$"
second_run_id="${run_id}-restart"
engine_id="fusion-validation-${run_id}"
ledger_run_id="${run_id}-ledger-1001"
ledger_engine_id="fusion-validation-ledger-${run_id}"

echo "[detections 1/8] Validating curated Sigma rules and positive/negative fixtures..."
fusion_compose run --rm --no-deps fusion-detection-engine validate-rules
fusion_compose run --rm --no-deps fusion-detection-engine validate-fixtures

echo "[detections 2/8] Seeding controlled normalized Windows, Linux, and Suricata fixtures..."
fusion_compose run --rm --no-deps fusion-detection-engine seed-fixtures --run-id "$run_id"
insert_clickhouse_admin "INSERT INTO fusion.detection_checkpoints (engine_id, checkpoint_time, checkpoint_uid, updated_at) VALUES ('$engine_id', now64(3), '', now64(3))" >/dev/null

echo "[detections 3/8] Evaluating fixtures and verifying platform coverage..."
fusion_compose run --rm --no-deps \
  -e "FUSION_DETECTION_ENGINE_ID=$engine_id" \
  -e FUSION_DETECTION_BATCH_SIZE=10000 \
  -e FUSION_DETECTION_LOOKBACK_SECONDS=0 \
  fusion-detection-engine run --once
result=$(query_clickhouse "SELECT count(), uniqExact(rule_id), uniqExact(platform), countIf(source_event_uid IN (SELECT event_uid FROM fusion.sysmon_events WHERE validation_id = '$run_id' AND JSONExtractString(raw_json, 'fixture_polarity') = 'negative')) FROM fusion.detections FINAL WHERE validation_id = '$run_id' FORMAT TSV")
expected=$(printf '9\t9\t3\t0')
if [ "$result" != "$expected" ]; then
  echo "Unexpected synthetic detection result: $result" >&2
  exit 1
fi
telemetry=$(query_clickhouse "SELECT count(), countIf(length(ruleset_fingerprint) = 64 AND length(checkpoint_uid) = 64 AND isNotNull(evaluation_floor_time) AND isNotNull(newest_eligible_event_time) AND events_evaluated > 0 AND new_events_processed > 0 AND processing_duration_seconds > 0 AND evaluated_events_per_second > 0 AND checkpoint_lag_seconds >= 0 AND unevaluated_event_count >= 0 AND oldest_unevaluated_age_seconds >= 0) FROM fusion.detection_checkpoints FINAL WHERE engine_id = '$engine_id' FORMAT TSV")
expected_telemetry=$(printf '1\t1')
if [ "$telemetry" != "$expected_telemetry" ]; then
  echo "Detection checkpoint telemetry is incomplete: $telemetry" >&2
  exit 1
fi
scope_telemetry=$(query_clickhouse "SELECT countIf(isNotNull(candidate_cursor_time) AND length(candidate_cursor_uid) = 64) FROM fusion.detection_evaluation_scopes FINAL WHERE engine_id = '$engine_id'")
if [ "$scope_telemetry" != "1" ]; then
  echo "Detection candidate scheduling cursor is incomplete: $scope_telemetry" >&2
  exit 1
fi
ledger_coverage=$(query_clickhouse "SELECT count(), uniqExact(ledger.event_uid) FROM fusion.detection_evaluated_events AS ledger INNER JOIN fusion.sysmon_events AS source ON ledger.event_uid = source.event_uid WHERE ledger.engine_id = '$engine_id' AND source.validation_id = '$run_id' FORMAT TSV")
expected_ledger_coverage=$(printf '18\t18')
if [ "$ledger_coverage" != "$expected_ledger_coverage" ]; then
  echo "Detection evaluation ledger did not cover every fixture: $ledger_coverage" >&2
  exit 1
fi

echo "[detections 4/8] Replaying the lookback window without creating duplicates..."
fusion_compose run --rm --no-deps \
  -e "FUSION_DETECTION_ENGINE_ID=$engine_id" \
  -e FUSION_DETECTION_BATCH_SIZE=10000 \
  -e FUSION_DETECTION_LOOKBACK_SECONDS=0 \
  fusion-detection-engine run --once
physical_count=$(query_clickhouse "SELECT count() FROM fusion.detections WHERE validation_id = '$run_id'")
if [ "$physical_count" -ne 9 ]; then
  echo "Detection replay created duplicates: $physical_count rows" >&2
  exit 1
fi
replay_ledger_count=$(query_clickhouse "SELECT count() FROM fusion.detection_evaluated_events WHERE engine_id = '$engine_id' AND validation_id = '$run_id'")
if [ "$replay_ledger_count" -ne 18 ]; then
  echo "Detection replay amplified evaluation-ledger rows: $replay_ledger_count" >&2
  exit 1
fi

echo "[detections 5/8] Restarting the engine and checking checkpoint continuity..."
fusion_compose restart fusion-detection-engine
fusion_compose up --detach --wait --wait-timeout 180 fusion-detection-engine
post_restart_count=$(query_clickhouse "SELECT count() FROM fusion.detections WHERE validation_id = '$run_id'")
if [ "$post_restart_count" -ne 9 ]; then
  echo "Detection restart changed existing detections: $post_restart_count rows" >&2
  exit 1
fi
fusion_compose run --rm --no-deps fusion-detection-engine seed-fixtures --run-id "$second_run_id"
fusion_compose run --rm --no-deps \
  -e "FUSION_DETECTION_ENGINE_ID=$engine_id" \
  -e FUSION_DETECTION_BATCH_SIZE=10000 \
  -e FUSION_DETECTION_LOOKBACK_SECONDS=0 \
  fusion-detection-engine run --once
new_count=$(query_clickhouse "SELECT count(), uniqExact(rule_id), uniqExact(platform) FROM fusion.detections FINAL WHERE validation_id = '$second_run_id' FORMAT TSV")
new_expected=$(printf '9\t9\t3')
if [ "$new_count" != "$new_expected" ]; then
  echo "New events after restart did not produce expected detections: $new_count" >&2
  exit 1
fi
new_ledger_coverage=$(query_clickhouse "SELECT count(), uniqExact(event_uid) FROM fusion.detection_evaluated_events WHERE engine_id = '$engine_id' AND validation_id = '$second_run_id' FORMAT TSV")
expected_new_ledger_coverage=$(printf '18\t18')
if [ "$new_ledger_coverage" != "$expected_new_ledger_coverage" ]; then
  echo "Events after restart were not completely ledgered: $new_ledger_coverage" >&2
  exit 1
fi

echo "[detections 6/8] Proving 1,001 same-timestamp events cannot hide behind the watermark..."
ledger_event_time=$(date -u -d '+5 seconds' '+%Y-%m-%d %H:%M:%S.000')
insert_clickhouse_admin "INSERT INTO fusion.sysmon_events (event_time, event_id, event_type, computer, record_id, process_guid, platform, source_type, host_name, source_event_id, event_code, event_category, event_action, event_kind, vendor, product, validation_id, raw_json) SELECT toDateTime64('$ledger_event_time', 3, 'UTC'), 0, 'ledger_validation', 'fusion-validation', number, '', 'network', 'fusion_validation', 'fusion-validation', toString(number), 'ledger-v052', 'validation', 'evaluate', 'event', 'Fusion', 'LedgerValidation', '$ledger_run_id', concat('{\"ledger_index\":', toString(number), '}') FROM (SELECT number FROM numbers(1001) UNION ALL SELECT toUInt64(0) AS number)" >/dev/null
ledger_source_rows=$(query_clickhouse "SELECT count(), uniqExact(event_uid) FROM fusion.sysmon_events WHERE validation_id = '$ledger_run_id' FORMAT TSV")
expected_ledger_source=$(printf '1002\t1001')
if [ "$ledger_source_rows" != "$expected_ledger_source" ]; then
  echo "The duplicate-source ledger fixture is incomplete: $ledger_source_rows" >&2
  exit 1
fi
insert_clickhouse_admin "INSERT INTO fusion.detection_checkpoints (engine_id, checkpoint_time, checkpoint_uid, updated_at) VALUES ('$ledger_engine_id', toDateTime64('$ledger_event_time', 3, 'UTC'), repeat('f', 64), now64(3))" >/dev/null
run_ledger_cycle() {
  fusion_compose run --rm --no-deps \
    -e "FUSION_DETECTION_ENGINE_ID=$ledger_engine_id" \
    -e FUSION_DETECTION_BATCH_SIZE=1000 \
    -e FUSION_DETECTION_LOOKBACK_SECONDS=0 \
    fusion-detection-engine run --once
}
run_ledger_cycle
first_ledger_page=$(query_clickhouse "SELECT count(), uniqExact(event_uid) FROM fusion.detection_evaluated_events WHERE engine_id = '$ledger_engine_id' AND validation_id = '$ledger_run_id' FORMAT TSV")
first_missing=$(query_clickhouse "SELECT uniqExact(source.event_uid) FROM fusion.sysmon_events AS source LEFT ANTI JOIN (SELECT event_uid FROM fusion.detection_evaluated_events WHERE engine_id = '$ledger_engine_id') AS evaluated ON source.event_uid = evaluated.event_uid WHERE source.validation_id = '$ledger_run_id'")
expected_first_ledger=$(printf '1000\t1000')
if [ "$first_ledger_page" != "$expected_first_ledger" ] || [ "$first_missing" -ne 1 ]; then
  echo "The first bounded ledger page was not exactly 1,000/1 pending: ledger=$first_ledger_page missing=$first_missing" >&2
  exit 1
fi
run_ledger_cycle
complete_ledger=$(query_clickhouse "SELECT count(), uniqExact(event_uid) FROM fusion.detection_evaluated_events WHERE engine_id = '$ledger_engine_id' AND validation_id = '$ledger_run_id' FORMAT TSV")
complete_missing=$(query_clickhouse "SELECT uniqExact(source.event_uid) FROM fusion.sysmon_events AS source LEFT ANTI JOIN (SELECT event_uid FROM fusion.detection_evaluated_events WHERE engine_id = '$ledger_engine_id') AS evaluated ON source.event_uid = evaluated.event_uid WHERE source.validation_id = '$ledger_run_id'")
ledger_detections=$(query_clickhouse "SELECT count() FROM fusion.detections WHERE validation_id = '$ledger_run_id'")
ledger_checkpoint=$(query_clickhouse "SELECT countIf(length(ruleset_fingerprint) = 64 AND isNotNull(evaluation_floor_time) AND checkpoint_uid = repeat('f', 64) AND unevaluated_event_count = 0) FROM fusion.detection_checkpoints FINAL WHERE engine_id = '$ledger_engine_id'")
expected_complete_ledger=$(printf '1001\t1001')
if [ "$complete_ledger" != "$expected_complete_ledger" ] || [ "$complete_missing" -ne 0 ] || [ "$ledger_detections" -ne 0 ] || [ "$ledger_checkpoint" -ne 1 ]; then
  echo "Same-timestamp ledger recovery failed: ledger=$complete_ledger missing=$complete_missing detections=$ledger_detections checkpoint=$ledger_checkpoint" >&2
  exit 1
fi
run_ledger_cycle
replay_ledger=$(query_clickhouse "SELECT count(), uniqExact(event_uid) FROM fusion.detection_evaluated_events WHERE engine_id = '$ledger_engine_id' AND validation_id = '$ledger_run_id' FORMAT TSV")
if [ "$replay_ledger" != "$expected_complete_ledger" ]; then
  echo "Same-timestamp replay amplified ledger rows: $replay_ledger" >&2
  exit 1
fi

echo "[detections 7/8] Proving telemetry ingestion continues while detection is stopped..."
ingestion_run_id="${run_id}-engine-stopped"
fusion_compose stop fusion-detection-engine
trap 'fusion_compose start fusion-detection-engine >/dev/null 2>&1 || true' EXIT HUP INT TERM
payload=$(sed -E -e "s/\"timestamp\": \"[^\"]+\"/\"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')\"/g" "$FUSION_ROOT/samples/security-tools/suricata-flow.json")
status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -H "X-Fusion-Validation-Id: $ingestion_run_id" \
  --data-binary "$payload" \
  "http://${FUSION_BIND_ADDRESS:-127.0.0.1}:${FUSION_INGEST_PORT:-8686}/security")
if [ "$status" != "202" ]; then
  echo "Vector rejected telemetry while detection was stopped with HTTP $status." >&2
  exit 1
fi
attempt=1
ingested=0
while [ "$attempt" -le 20 ]; do
  ingested=$(query_clickhouse "SELECT count() FROM fusion.sysmon_events WHERE validation_id = '$ingestion_run_id'")
  if [ "$ingested" -ge 1 ]; then break; fi
  sleep 1
  attempt=$((attempt + 1))
done
if [ "$ingested" -lt 1 ]; then
  echo "Telemetry did not reach ClickHouse while detection was stopped." >&2
  exit 1
fi
fusion_compose start fusion-detection-engine
fusion_compose up --detach --wait --wait-timeout 180 fusion-detection-engine
trap - EXIT HUP INT TERM

echo "[detections 8/8] Validating the bounded dry-run plan and detection dashboard SQL..."
fusion_compose run --rm --no-deps fusion-detection-engine \
  test-rule /rules/windows/encoded-powershell.yml --hours 1 --limit 100 >/dev/null
detection_dashboard="$FUSION_ROOT/grafana/dashboards/fusion-detections.json"
for title in "Total detections" "New detections" "High/Critical detections" "Detections over time" "Detections by severity" "Detections by rule" "Detections by platform" "Detections by source type" "Detections by host" "Top affected users" "Top source IPs" "Top destination IPs" "MITRE tactics" "MITRE techniques" "Recent detections"; do
  grep -q "\"title\": \"$title\"" "$detection_dashboard"
done
for variable in severity status platform host rule tactic technique; do
  grep -q "\"name\": \"$variable\"" "$detection_dashboard"
done
for query in \
  "SELECT count() FROM fusion.detections FINAL" \
  "SELECT severity, count() FROM fusion.detections FINAL GROUP BY severity" \
  "SELECT rule_name, count() FROM fusion.detections FINAL GROUP BY rule_name" \
  "SELECT platform, count() FROM fusion.detections FINAL GROUP BY platform" \
  "SELECT source_type, count() FROM fusion.detections FINAL GROUP BY source_type" \
  "SELECT host_name, count() FROM fusion.detections FINAL WHERE host_name != '' GROUP BY host_name" \
  "SELECT user_name, count() FROM fusion.detections FINAL WHERE user_name != '' GROUP BY user_name" \
  "SELECT source_ip, count() FROM fusion.detections FINAL WHERE source_ip != '' GROUP BY source_ip" \
  "SELECT destination_ip, count() FROM fusion.detections FINAL WHERE destination_ip != '' GROUP BY destination_ip" \
  "SELECT arrayJoin(mitre_tactics), count() FROM fusion.detections FINAL GROUP BY arrayJoin(mitre_tactics)" \
  "SELECT arrayJoin(mitre_techniques), count() FROM fusion.detections FINAL GROUP BY arrayJoin(mitre_techniques)"; do
  query_clickhouse "$query" >/dev/null
done

echo "Cleaning synthetic detection validation rows..."
fusion_compose stop fusion-detection-engine
trap 'fusion_compose start fusion-detection-engine >/dev/null 2>&1 || true' EXIT HUP INT TERM
query_clickhouse "ALTER TABLE fusion.detection_evaluated_events DELETE WHERE validation_id IN ('$run_id', '$second_run_id', '$ingestion_run_id', '$ledger_run_id') SETTINGS mutations_sync = 2" >/dev/null
query_clickhouse "ALTER TABLE fusion.sysmon_events DELETE WHERE validation_id IN ('$run_id', '$second_run_id', '$ingestion_run_id', '$ledger_run_id') SETTINGS mutations_sync = 2" >/dev/null
  query_clickhouse "ALTER TABLE fusion.detections DELETE WHERE validation_id IN ('$run_id', '$second_run_id') SETTINGS mutations_sync = 2" >/dev/null
  query_clickhouse "ALTER TABLE fusion.detection_checkpoints DELETE WHERE engine_id = '$engine_id' SETTINGS mutations_sync = 2" >/dev/null
  query_clickhouse "ALTER TABLE fusion.detection_checkpoints DELETE WHERE engine_id = '$ledger_engine_id' SETTINGS mutations_sync = 2" >/dev/null
  query_clickhouse "ALTER TABLE fusion.detection_evaluation_scopes DELETE WHERE engine_id IN ('$engine_id', '$ledger_engine_id') SETTINGS mutations_sync = 2" >/dev/null
fusion_compose start fusion-detection-engine
fusion_compose up --detach --wait --wait-timeout 180 fusion-detection-engine
trap - EXIT HUP INT TERM

echo "Detection validation passed: rules, fixtures, 1,001-row ledger completeness, checkpoint telemetry, deduplication, restart, ingestion isolation, dry-run, and dashboard queries are healthy."
