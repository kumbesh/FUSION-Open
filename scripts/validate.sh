#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

skip_samples=false
if [ "${1:-}" = "--skip-samples" ]; then
  skip_samples=true
elif [ "$#" -gt 0 ]; then
  echo "Usage: $0 [--skip-samples]" >&2
  exit 2
fi

fusion_assert_engine
fusion_load_env

echo "[1/8] Validating Docker Compose and both ingestion bind modes..."
fusion_compose config --quiet
default_model=$(FUSION_BIND_ADDRESS=127.0.0.1 fusion_compose config --format json)
lab_model=$(FUSION_BIND_ADDRESS=192.0.2.10 fusion_compose config --format json)
printf '%s' "$default_model" | grep -q '"host_ip": "127.0.0.1"'
printf '%s' "$lab_model" | grep -q '"host_ip": "192.0.2.10"'

echo "[2/8] Running collector Vector configuration and VRL unit tests..."
fusion_compose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml
fusion_compose run --rm --no-deps vector test /etc/vector/vector.yaml

echo "[3/8] Checking the backward-compatible ClickHouse migration..."
schema_count=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT count() FROM system.columns WHERE database = 'fusion' AND table = 'sysmon_events' AND name IN ('provider_name','record_id','image_loaded','query_name','query_status','query_results','target_filename','target_object','registry_details','message')")
if [ "$schema_count" -ne 10 ]; then
  echo "ClickHouse v0.2 columns are missing. Run scripts/deploy.sh to apply migrations." >&2
  exit 1
fi

echo "[4/8] Checking container health..."
for service in clickhouse vector grafana; do
  container_id=$(fusion_compose ps -q "$service")
  if [ -z "$container_id" ]; then
    echo "Service '$service' is not running. Run scripts/deploy.sh first." >&2
    exit 1
  fi
  state=$(fusion_docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_id")
  if [ "$state" != "running healthy" ]; then
    echo "Service '$service' is not healthy (state: $state)." >&2
    exit 1
  fi
done

run_id="fusion-$(date +%s)-$$"
sample_count=0
if [ "$skip_samples" = false ]; then
  echo "[5/8] Sending v0.1 and Windows-agent-shaped Sysmon events..."
  event_time=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
  for sample in "$FUSION_ROOT"/samples/sysmon/*.json; do
    payload=$(sed -E \
      -e "s/\"UtcTime\": \"[^\"]+\"/\"UtcTime\": \"$event_time\"/g" \
      -e "s/\"timestamp\": \"[^\"]+\"/\"timestamp\": \"$event_time\"/g" \
      "$sample")
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
      -H 'Content-Type: application/json' \
      -H "X-Fusion-Validation-Id: $run_id" \
      --data-binary "$payload" \
      "http://${FUSION_BIND_ADDRESS:-127.0.0.1}:${FUSION_INGEST_PORT:-8686}/sysmon")
    if [ "$status" != "202" ]; then
      echo "Vector rejected $(basename "$sample") with HTTP $status." >&2
      exit 1
    fi
    sample_count=$((sample_count + 1))
  done

  batch_file=$(mktemp)
  trap 'rm -f "$batch_file"' EXIT HUP INT TERM
  for sample in "$FUSION_ROOT"/samples/windows-agent/*.json; do
    sed -E \
      -e "s/\"UtcTime\": \"[^\"]+\"/\"UtcTime\": \"$event_time\"/g" \
      -e "s/\"timestamp\": \"[^\"]+\"/\"timestamp\": \"$event_time\"/g" \
      "$sample" | tr -d '\r\n' >> "$batch_file"
    printf '\n' >> "$batch_file"
    sample_count=$((sample_count + 1))
  done
  status=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/x-ndjson' \
    -H "X-Fusion-Validation-Id: $run_id" \
    --data-binary "@$batch_file" \
    "http://${FUSION_BIND_ADDRESS:-127.0.0.1}:${FUSION_INGEST_PORT:-8686}/sysmon")
  rm -f "$batch_file"
  trap - EXIT HUP INT TERM
  if [ "$status" != "202" ]; then
    echo "Vector rejected the Windows-agent NDJSON batch with HTTP $status." >&2
    exit 1
  fi
else
  echo "[5/8] Sample ingestion skipped."
fi

echo "[6/8] Verifying v0.1 compatibility and Event IDs 1, 3, and 22..."
if [ "$skip_samples" = false ]; then
  query="SELECT count(), countIf(event_id = 1), countIf(event_id = 1 AND (positionCaseInsensitiveUTF8(image, 'powershell.exe') > 0 OR positionCaseInsensitiveUTF8(image, 'pwsh.exe') > 0)), countIf(event_id = 3), countIf(event_id = 22), countIf(event_id = 22 AND query_name = 'example.com'), countIf(position(raw_json, 'windows_event_log') > 0), countIf(position(raw_json, '<Event') > 0) FROM fusion.sysmon_events WHERE validation_id = '$run_id' FORMAT TSV"
  result="0\t0\t0\t0\t0\t0\t0\t0"
  attempt=1
  while [ "$attempt" -le 20 ]; do
    result=$(fusion_compose exec -T clickhouse clickhouse-client \
      --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$query")
    total=$(printf '%s' "$result" | cut -f1)
    if [ "$total" -ge "$sample_count" ]; then
      break
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  process=$(printf '%s' "$result" | cut -f2)
  powershell=$(printf '%s' "$result" | cut -f3)
  network=$(printf '%s' "$result" | cut -f4)
  dns=$(printf '%s' "$result" | cut -f5)
  dns_normalized=$(printf '%s' "$result" | cut -f6)
  raw_windows=$(printf '%s' "$result" | cut -f7)
  raw_xml=$(printf '%s' "$result" | cut -f8)
  if [ "$total" -lt "$sample_count" ] || [ "$process" -lt 3 ] || [ "$powershell" -lt 1 ] || [ "$network" -lt 2 ] || [ "$dns" -lt 1 ] || [ "$dns_normalized" -lt 1 ] || [ "$raw_windows" -lt 3 ] || [ "$raw_xml" -lt 3 ]; then
    echo "Unexpected ClickHouse counts: $result" >&2
    exit 1
  fi
  echo "  Rows=$total, Process=$process, PowerShell=$powershell, Network=$network, DNS=$dns, RawWindows=$raw_windows, RawXML=$raw_xml"
fi

echo "[7/8] Validating v0.2 dashboard panels and their stored-telemetry queries..."
dashboard="$FUSION_ROOT/grafana/dashboards/fusion-security-overview.json"
for title in "Top DNS queries" "Top executed processes" "External network destinations" "Sysmon events by Event ID"; do
  grep -q "\"title\": \"$title\"" "$dashboard"
done
if [ "$skip_samples" = false ]; then
  fusion_compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "SELECT query_name, count() AS queries FROM fusion.sysmon_events WHERE event_time >= now() - INTERVAL 1 DAY AND event_id = 22 AND query_name != '' GROUP BY query_name ORDER BY queries DESC LIMIT 10" >/dev/null
  fusion_compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "SELECT image, count() AS executions FROM fusion.sysmon_events WHERE event_time >= now() - INTERVAL 1 DAY AND event_id = 1 AND image != '' GROUP BY image ORDER BY executions DESC LIMIT 10" >/dev/null
  fusion_compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "SELECT if(destination_hostname = '', destination_ip, destination_hostname) AS destination, count() AS connections FROM fusion.sysmon_events WHERE event_time >= now() - INTERVAL 1 DAY AND event_id = 3 AND destination_ip != '' AND destination_ip NOT IN ('0.0.0.0', '127.0.0.1', '::1') AND NOT startsWith(destination_ip, '10.') AND NOT startsWith(destination_ip, '192.168.') AND NOT match(destination_ip, '^172\\.(1[6-9]|2[0-9]|3[01])\\.') AND NOT startsWith(destination_ip, '169.254.') AND NOT startsWith(lower(destination_ip), 'fe80:') AND NOT startsWith(lower(destination_ip), 'fc') AND NOT startsWith(lower(destination_ip), 'fd') GROUP BY destination ORDER BY connections DESC LIMIT 10" >/dev/null
  fusion_compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "SELECT toString(event_id) AS event_id, count() AS events FROM fusion.sysmon_events WHERE event_time >= now() - INTERVAL 1 DAY GROUP BY event_id ORDER BY events DESC" >/dev/null
  panel_result=$(fusion_compose exec -T clickhouse clickhouse-client \
    --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "SELECT countIf(event_id = 22 AND query_name != ''), countIf(event_id = 1 AND image != ''), countIf(event_id = 3 AND destination_ip != ''), uniqExact(event_id) FROM fusion.sysmon_events WHERE validation_id = '$run_id' FORMAT TSV")
  panel_dns=$(printf '%s' "$panel_result" | cut -f1)
  panel_process=$(printf '%s' "$panel_result" | cut -f2)
  panel_network=$(printf '%s' "$panel_result" | cut -f3)
  panel_ids=$(printf '%s' "$panel_result" | cut -f4)
  if [ "$panel_dns" -lt 1 ] || [ "$panel_process" -lt 1 ] || [ "$panel_network" -lt 1 ] || [ "$panel_ids" -lt 3 ]; then
    echo "Dashboard queries did not return the expected stored telemetry: $panel_result" >&2
    exit 1
  fi
fi

echo "[8/8] Checking Grafana and the provisioned ClickHouse data source..."
grafana_base="http://127.0.0.1:${FUSION_GRAFANA_PORT:-3000}"
curl -fsS "$grafana_base/api/health" >/dev/null
datasource_health=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/datasources/uid/fusion-clickhouse/health")
printf '%s' "$datasource_health" | grep -q '"status":"OK"'
dashboards=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/search?query=Fusion%20Security%20Overview")
printf '%s' "$dashboards" | grep -q 'fusion-security-overview'

echo "Validation passed: bindings, v0.1 compatibility, v0.2 normalization, storage, data source, and dashboard are healthy."
