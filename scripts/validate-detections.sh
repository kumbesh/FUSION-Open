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

run_id="fusion-v05-$(date -u '+%Y%m%d%H%M%S')-$$"
second_run_id="${run_id}-restart"
engine_id="fusion-validation-${run_id}"

echo "[detections 1/7] Validating curated Sigma rules and positive/negative fixtures..."
fusion_compose run --rm --no-deps fusion-detection-engine validate-rules
fusion_compose run --rm --no-deps fusion-detection-engine validate-fixtures

echo "[detections 2/7] Seeding controlled normalized Windows, Linux, and Suricata fixtures..."
fusion_compose run --rm --no-deps fusion-detection-engine seed-fixtures --run-id "$run_id"
query_clickhouse "INSERT INTO fusion.detection_checkpoints (engine_id, checkpoint_time, checkpoint_uid, updated_at) VALUES ('$engine_id', now64(3), '', now64(3))" >/dev/null

echo "[detections 3/7] Evaluating fixtures and verifying platform coverage..."
fusion_compose run --rm --no-deps \
  -e "FUSION_DETECTION_ENGINE_ID=$engine_id" \
  -e FUSION_DETECTION_BATCH_SIZE=10000 \
  -e FUSION_DETECTION_LOOKBACK_SECONDS=300 \
  fusion-detection-engine run --once
result=$(query_clickhouse "SELECT count(), uniqExact(rule_id), uniqExact(platform), countIf(source_event_uid IN (SELECT event_uid FROM fusion.sysmon_events WHERE validation_id = '$run_id' AND JSONExtractString(raw_json, 'fixture_polarity') = 'negative')) FROM fusion.detections FINAL WHERE validation_id = '$run_id' FORMAT TSV")
expected=$(printf '9\t9\t3\t0')
if [ "$result" != "$expected" ]; then
  echo "Unexpected synthetic detection result: $result" >&2
  exit 1
fi

echo "[detections 4/7] Replaying the lookback window without creating duplicates..."
fusion_compose run --rm --no-deps \
  -e "FUSION_DETECTION_ENGINE_ID=$engine_id" \
  -e FUSION_DETECTION_BATCH_SIZE=10000 \
  -e FUSION_DETECTION_LOOKBACK_SECONDS=300 \
  fusion-detection-engine run --once
physical_count=$(query_clickhouse "SELECT count() FROM fusion.detections WHERE validation_id = '$run_id'")
if [ "$physical_count" -ne 9 ]; then
  echo "Detection replay created duplicates: $physical_count rows" >&2
  exit 1
fi

echo "[detections 5/7] Restarting the engine and checking checkpoint continuity..."
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
  -e FUSION_DETECTION_LOOKBACK_SECONDS=300 \
  fusion-detection-engine run --once
new_count=$(query_clickhouse "SELECT count(), uniqExact(rule_id), uniqExact(platform) FROM fusion.detections FINAL WHERE validation_id = '$second_run_id' FORMAT TSV")
new_expected=$(printf '9\t9\t3')
if [ "$new_count" != "$new_expected" ]; then
  echo "New events after restart did not produce expected detections: $new_count" >&2
  exit 1
fi

echo "[detections 6/7] Proving telemetry ingestion continues while detection is stopped..."
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

echo "[detections 7/7] Validating the bounded dry-run plan and detection dashboard SQL..."
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

echo "Detection validation passed: rules, fixtures, deduplication, restart, ingestion isolation, dry-run, and dashboard queries are healthy."
