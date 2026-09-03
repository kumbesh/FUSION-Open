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

echo "[1/9] Validating Docker Compose and both ingestion bind modes..."
fusion_compose config --quiet
default_model=$(FUSION_BIND_ADDRESS=127.0.0.1 fusion_compose config --format json)
lab_model=$(FUSION_BIND_ADDRESS=192.0.2.10 fusion_compose config --format json)
printf '%s' "$default_model" | grep -q '"host_ip": "127.0.0.1"'
printf '%s' "$lab_model" | grep -q '"host_ip": "192.0.2.10"'

echo "[2/9] Running collector Vector configuration and VRL unit tests..."
fusion_compose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml
fusion_compose run --rm --no-deps vector test /etc/vector/vector.yaml

echo "[3/9] Checking the live common ClickHouse schema..."
schema_count=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT count() FROM system.columns WHERE database = 'fusion' AND table = 'sysmon_events' AND name IN ('provider_name','record_id','image_loaded','query_name','query_status','query_results','target_filename','target_object','registry_details','message','host_name','platform','source_type','event_category','event_action','event_code','source_event_id','user_name','user_id','process_name','process_path','parent_process_name','parent_process_id','service_name','outcome','severity')")
if [ "$schema_count" -ne 26 ]; then
  echo "ClickHouse common event columns are missing. Run scripts/deploy.sh to apply migrations." >&2
  exit 1
fi

echo "[4/9] Proving the v0.2-to-v0.3 migration preserves Windows rows..."
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery < "$FUSION_ROOT/clickhouse/tests/002_v02_schema.sql"
migration_sql=$(mktemp)
cleanup_migration_test() {
  rm -f "$migration_sql"
  fusion_compose exec -T clickhouse clickhouse-client \
    --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "DROP DATABASE IF EXISTS fusion_v03_migration_test" >/dev/null 2>&1 || true
}
trap cleanup_migration_test EXIT HUP INT TERM
sed 's/fusion\.sysmon_events/fusion_v03_migration_test.sysmon_events/g' \
  "$FUSION_ROOT/clickhouse/migrations/003_common_security_events_v03.sql" > "$migration_sql"
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery < "$migration_sql"
migration_result=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT count(), countIf(platform = 'windows' AND host_name = 'V02-HOST' AND endsWith(process_path, 'cmd.exe') AND raw_json = '{\"v\":\"0.2\"}') FROM fusion_v03_migration_test.sysmon_events FORMAT TSV")
expected_migration=$(printf '1\t1')
if [ "$migration_result" != "$expected_migration" ]; then
  echo "Existing v0.2 data was not preserved with compatible defaults: $migration_result" >&2
  exit 1
fi
cleanup_migration_test
trap - EXIT HUP INT TERM

echo "[5/9] Checking container health..."
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
  echo "[6/9] Sending Windows Sysmon and Linux auditd/journald fixtures..."
  event_time=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
  for sample in "$FUSION_ROOT"/samples/sysmon/*.json "$FUSION_ROOT"/samples/windows-agent/*.json; do
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

  linux_sample_count=0
  audit_epoch=$(date -u '+%s')
  for sample in "$FUSION_ROOT"/samples/linux-agent/*.json; do
    payload=$(sed -E \
      -e "s/\"timestamp\": \"[^\"]+\"/\"timestamp\": \"$event_time\"/g" \
      -e "s/audit\([0-9]+(\.[0-9]+)?:/audit($audit_epoch.125:/g" \
      "$sample")
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
      -H 'Content-Type: application/json' \
      -H "X-Fusion-Validation-Id: $run_id" \
      --data-binary "$payload" \
      "http://${FUSION_BIND_ADDRESS:-127.0.0.1}:${FUSION_INGEST_PORT:-8686}/linux")
    if [ "$status" != "202" ]; then
      echo "Vector rejected $(basename "$sample") with HTTP $status." >&2
      exit 1
    fi
    linux_sample_count=$((linux_sample_count + 1))
  done
else
  echo "[6/9] Sample ingestion skipped."
fi

echo "[7/9] Verifying Windows compatibility and normalized Linux telemetry..."
if [ "$skip_samples" = false ]; then
  query="SELECT count(), countIf(event_id = 1), countIf(event_id = 1 AND (positionCaseInsensitiveUTF8(image, 'powershell.exe') > 0 OR positionCaseInsensitiveUTF8(image, 'pwsh.exe') > 0)), countIf(event_id = 3), countIf(event_id = 22), countIf(event_id = 22 AND query_name = 'example.com'), countIf(position(raw_json, 'windows_event_log') > 0), countIf(position(raw_json, '<Event') > 0) FROM fusion.sysmon_events WHERE validation_id = '$run_id' AND platform = 'windows' FORMAT TSV"
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

  linux_query="SELECT count(), countIf(source_type = 'linux_auditd'), countIf(source_type = 'linux_journald'), countIf(event_action = 'process_execute' AND process_path = '/usr/bin/curl' AND command_line = '/usr/bin/curl https://example.com' AND user_id = '1000'), countIf(event_action = 'sudo_command'), countIf(event_category = 'authentication'), countIf(outcome = 'failure'), countIf(service_name = 'fusion-lab.service'), countIf(position(raw_json, 'type=SYSCALL') > 0 AND position(raw_json, 'type=EOE') > 0), countIf(position(raw_json, 'Accepted publickey') > 0) FROM fusion.sysmon_events WHERE validation_id = '$run_id' AND platform = 'linux' FORMAT TSV"
  linux_result="0\t0\t0\t0\t0\t0\t0\t0\t0\t0"
  attempt=1
  while [ "$attempt" -le 20 ]; do
    linux_result=$(fusion_compose exec -T clickhouse clickhouse-client \
      --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$linux_query")
    linux_total=$(printf '%s' "$linux_result" | cut -f1)
    if [ "$linux_total" -ge "$linux_sample_count" ]; then
      break
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  linux_auditd=$(printf '%s' "$linux_result" | cut -f2)
  linux_journald=$(printf '%s' "$linux_result" | cut -f3)
  linux_process=$(printf '%s' "$linux_result" | cut -f4)
  linux_sudo=$(printf '%s' "$linux_result" | cut -f5)
  linux_auth=$(printf '%s' "$linux_result" | cut -f6)
  linux_failures=$(printf '%s' "$linux_result" | cut -f7)
  linux_service=$(printf '%s' "$linux_result" | cut -f8)
  linux_raw_audit=$(printf '%s' "$linux_result" | cut -f9)
  linux_raw_journal=$(printf '%s' "$linux_result" | cut -f10)
  if [ "$linux_total" -ne "$linux_sample_count" ] || [ "$linux_auditd" -ne 2 ] || [ "$linux_journald" -ne 3 ] || [ "$linux_process" -lt 1 ] || [ "$linux_sudo" -lt 1 ] || [ "$linux_auth" -lt 2 ] || [ "$linux_failures" -lt 1 ] || [ "$linux_service" -lt 1 ] || [ "$linux_raw_audit" -lt 1 ] || [ "$linux_raw_journal" -lt 1 ]; then
    echo "Unexpected normalized Linux telemetry: $linux_result" >&2
    exit 1
  fi
  echo "  LinuxRows=$linux_total, Auditd=$linux_auditd, Journald=$linux_journald, Auth=$linux_auth, Failures=$linux_failures"
fi

echo "[8/9] Validating multi-platform dashboard panels and stored-telemetry queries..."
dashboard="$FUSION_ROOT/grafana/dashboards/fusion-security-overview.json"
for title in "Top DNS queries" "Top executed processes" "External network destinations" "Sysmon events by Event ID" "Events by platform" "Top Linux executed processes" "Events by source type" "Failed authentication attempts" "Authentication activity" "sudo activity" "Linux process executions"; do
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
  linux_panel_result=$(fusion_compose exec -T clickhouse clickhouse-client \
    --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "SELECT countIf(event_action = 'process_execute'), countIf(event_category = 'authentication'), countIf(event_action = 'sudo_command'), uniqExact(source_type) FROM fusion.sysmon_events WHERE validation_id = '$run_id' AND platform = 'linux' FORMAT TSV")
  linux_panel_process=$(printf '%s' "$linux_panel_result" | cut -f1)
  linux_panel_auth=$(printf '%s' "$linux_panel_result" | cut -f2)
  linux_panel_sudo=$(printf '%s' "$linux_panel_result" | cut -f3)
  linux_panel_sources=$(printf '%s' "$linux_panel_result" | cut -f4)
  if [ "$linux_panel_process" -lt 1 ] || [ "$linux_panel_auth" -lt 2 ] || [ "$linux_panel_sudo" -lt 1 ] || [ "$linux_panel_sources" -lt 2 ]; then
    echo "Linux dashboard queries did not return the expected stored telemetry: $linux_panel_result" >&2
    exit 1
  fi
fi

echo "[9/9] Checking Grafana and the provisioned ClickHouse data source..."
grafana_base="http://127.0.0.1:${FUSION_GRAFANA_PORT:-3000}"
curl -fsS "$grafana_base/api/health" >/dev/null
datasource_health=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/datasources/uid/fusion-clickhouse/health")
printf '%s' "$datasource_health" | grep -q '"status":"OK"'
dashboards=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/search?query=Fusion%20Security%20Overview")
printf '%s' "$dashboards" | grep -q 'fusion-security-overview'
provisioned_dashboard=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/dashboards/uid/fusion-security-overview")
for title in "Events by platform" "Top Linux executed processes" "Events by source type" "Failed authentication attempts" "Authentication activity" "sudo activity" "Linux process executions"; do
  printf '%s' "$provisioned_dashboard" | grep -Fq "\"title\":\"$title\""
done
printf '%s' "$provisioned_dashboard" | grep -Fq '"name":"platform"'

echo "Validation passed: bindings, v0.1/v0.2 compatibility, v0.3 Windows/Linux normalization, storage, data source, and dashboard are healthy."
