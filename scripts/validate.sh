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

echo "[1/12] Validating Docker Compose and secure HTTP/syslog bind modes..."
fusion_compose config --quiet
default_model=$(FUSION_BIND_ADDRESS=127.0.0.1 FUSION_SYSLOG_BIND_ADDRESS=127.0.0.1 fusion_compose config --format json)
lab_model=$(FUSION_BIND_ADDRESS=192.0.2.10 FUSION_SYSLOG_BIND_ADDRESS=192.0.2.10 fusion_compose config --format json)
printf '%s' "$default_model" | grep -q '"host_ip": "127.0.0.1"'
printf '%s' "$lab_model" | grep -q '"host_ip": "192.0.2.10"'
if [ "$(printf '%s' "$default_model" | grep -c '"host_ip": "127.0.0.1"')" -lt 4 ]; then
  echo "Expected default localhost bindings for HTTP, syslog TCP/UDP, and Vector API." >&2
  exit 1
fi
if [ "$(printf '%s' "$lab_model" | grep -c '"host_ip": "192.0.2.10"')" -lt 3 ]; then
  echo "Expected explicit lab bindings for HTTP and syslog TCP/UDP." >&2
  exit 1
fi

echo "[2/12] Running collector Vector configuration and VRL unit tests..."
fusion_compose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml
fusion_compose run --rm --no-deps vector test /etc/vector/vector.yaml

echo "[3/12] Validating the Suricata EVE Vector integration configuration..."
fusion_docker run --rm --entrypoint /bin/sh -v "$FUSION_ROOT:/work:ro" timberio/vector:0.58.0-alpine \
  /work/integrations/suricata/test-config.sh /usr/local/bin/vector

echo "[4/12] Checking the live common ClickHouse and detection schemas..."
schema_count=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT count() FROM system.columns WHERE database = 'fusion' AND table = 'sysmon_events' AND name IN ('provider_name','record_id','image_loaded','query_name','query_status','query_results','target_filename','target_object','registry_details','message','host_name','platform','source_type','event_category','event_action','event_code','source_event_id','user_name','user_id','process_name','process_path','parent_process_name','parent_process_id','service_name','outcome','severity','device_name','vendor','product','event_kind','ingestion_protocol','ingestion_path','source_address','original_format','network_direction','rule_id','signature','signature_id','url','domain','syslog_facility','syslog_application')")
if [ "$schema_count" -ne 42 ]; then
  echo "ClickHouse common event columns are missing. Run scripts/deploy.sh to apply migrations." >&2
  exit 1
fi
detection_schema=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT countIf(table = 'sysmon_events' AND name = 'event_uid'), countIf(table = 'detections'), countIf(table = 'detection_checkpoints') FROM system.columns WHERE database = 'fusion' FORMAT TSV")
expected_detection_schema=$(printf '1\t35\t4')
if [ "$detection_schema" != "$expected_detection_schema" ]; then
  echo "ClickHouse v0.5 detection schema is incomplete: $detection_schema" >&2
  exit 1
fi

echo "[5/12] Proving v0.2-to-v0.3 and v0.3-to-v0.4 migrations preserve rows..."
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
  --query "SELECT count(), countIf(platform = 'windows' AND host_name = 'V02-HOST' AND endsWith(process_path, 'cmd.exe') AND JSONExtractString(raw_json, 'v') = '0.2') FROM fusion_v03_migration_test.sysmon_events FORMAT TSV")
expected_migration=$(printf '1\t1')
if [ "$migration_result" != "$expected_migration" ]; then
  echo "Existing v0.2 data was not preserved with compatible defaults: $migration_result" >&2
  exit 1
fi
cleanup_migration_test
trap - EXIT HUP INT TERM

fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery < "$FUSION_ROOT/clickhouse/tests/003_v03_schema.sql"
v04_migration_sql=$(mktemp)
cleanup_v04_migration_test() {
  rm -f "$v04_migration_sql"
  fusion_compose exec -T clickhouse clickhouse-client \
    --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "DROP DATABASE IF EXISTS fusion_v04_migration_test" >/dev/null 2>&1 || true
}
trap cleanup_v04_migration_test EXIT HUP INT TERM
sed 's/fusion\.sysmon_events/fusion_v04_migration_test.sysmon_events/g' \
  "$FUSION_ROOT/clickhouse/migrations/004_security_tool_ingestion_v04.sql" > "$v04_migration_sql"
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery < "$v04_migration_sql"
v04_migration_result=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT count(), countIf(platform = 'windows' AND vendor = 'Microsoft' AND product = 'Sysmon' AND ingestion_path = '/sysmon' AND JSONExtractString(raw_json, 'version') = '0.3' AND JSONExtractString(raw_json, 'platform') = 'windows'), countIf(platform = 'linux' AND vendor = 'Fusion' AND product = 'Linux' AND ingestion_path = '/linux' AND JSONExtractString(raw_json, 'version') = '0.3' AND JSONExtractString(raw_json, 'platform') = 'linux') FROM fusion_v04_migration_test.sysmon_events FORMAT TSV")
expected_v04_migration=$(printf '2\t1\t1')
if [ "$v04_migration_result" != "$expected_v04_migration" ]; then
  echo "Existing v0.3 data was not preserved with v0.4 defaults: $v04_migration_result" >&2
  exit 1
fi
cleanup_v04_migration_test
trap - EXIT HUP INT TERM

echo "[6/12] Proving the v0.4-to-v0.5 migration is preserving and idempotent..."
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery < "$FUSION_ROOT/clickhouse/tests/004_v04_schema.sql"
v05_migration_sql=$(mktemp)
cleanup_v05_migration_test() {
  rm -f "$v05_migration_sql"
  fusion_compose exec -T clickhouse clickhouse-client \
    --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "DROP DATABASE IF EXISTS fusion_v05_migration_test" >/dev/null 2>&1 || true
}
trap cleanup_v05_migration_test EXIT HUP INT TERM
sed \
  -e 's/fusion\.sysmon_events/fusion_v05_migration_test.sysmon_events/g' \
  -e 's/fusion\.detections/fusion_v05_migration_test.detections/g' \
  -e 's/fusion\.detection_checkpoints/fusion_v05_migration_test.detection_checkpoints/g' \
  "$FUSION_ROOT/clickhouse/migrations/005_detection_engine_v05.sql" > "$v05_migration_sql"
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery < "$v05_migration_sql"
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery < "$v05_migration_sql"
v05_migration_result=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT count(), countIf(platform = 'windows'), countIf(platform = 'linux'), countIf(source_type = 'suricata_eve'), countIf(source_type = 'generic_syslog'), uniqExact(event_uid), countIf(length(event_uid) = 64) FROM fusion_v05_migration_test.sysmon_events FORMAT TSV")
expected_v05_migration=$(printf '4\t1\t1\t1\t1\t4\t4')
if [ "$v05_migration_result" != "$expected_v05_migration" ]; then
  echo "Existing v0.4 data was not preserved with deterministic event identities: $v05_migration_result" >&2
  exit 1
fi
cleanup_v05_migration_test
trap - EXIT HUP INT TERM

echo "[7/12] Checking container health..."
for service in clickhouse vector grafana fusion-detection-engine; do
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
  echo "[8/12] Sending Windows, Linux, security JSON, and TCP/UDP syslog fixtures..."
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

  security_sample_count=0
  for sample in "$FUSION_ROOT"/samples/security-tools/suricata-*.json; do
    payload=$(sed -E -e "s/\"timestamp\": \"[^\"]+\"/\"timestamp\": \"$event_time\"/g" "$sample")
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
      -H 'Content-Type: application/json' \
      -H "X-Fusion-Validation-Id: $run_id" \
      --data-binary "$payload" \
      "http://${FUSION_BIND_ADDRESS:-127.0.0.1}:${FUSION_INGEST_PORT:-8686}/security")
    if [ "$status" != "202" ]; then
      echo "Vector rejected $(basename "$sample") with HTTP $status." >&2
      exit 1
    fi
    security_sample_count=$((security_sample_count + 1))
  done

  if ! command -v nc >/dev/null 2>&1; then
    echo "The nc command is required to validate TCP/UDP syslog ingestion." >&2
    exit 1
  fi
  printf '%s validation_id=%s\n' "$(cat "$FUSION_ROOT/samples/security-tools/rfc3164.log")" "$run_id" | \
    nc -w 2 "${FUSION_SYSLOG_BIND_ADDRESS:-127.0.0.1}" "${FUSION_SYSLOG_TCP_PORT:-5514}"
  for syslog_sample in rfc5424.log unknown-valid-syslog.log; do
    printf '%s validation_id=%s\n' "$(cat "$FUSION_ROOT/samples/security-tools/$syslog_sample")" "$run_id" | \
      nc -u -w 1 "${FUSION_SYSLOG_BIND_ADDRESS:-127.0.0.1}" "${FUSION_SYSLOG_UDP_PORT:-5514}"
  done
else
  echo "[8/12] Sample ingestion skipped."
fi

echo "[9/12] Verifying v0.1-v0.4 compatibility and normalized telemetry..."
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

  security_query="SELECT count(), countIf(event_action = 'network_alert'), countIf(event_action = 'dns_query' AND domain = 'fusion-test.example'), countIf(event_action = 'http_request' AND url = 'http://web.fusion-test.example/health'), countIf(event_action = 'tls_session' AND domain = 'tls.fusion-test.example'), countIf(event_action = 'network_flow'), countIf(vendor = 'OISF' AND product = 'Suricata' AND source_type = 'suricata_eve'), countIf(source_address != ''), countIf(position(raw_json, 'flow_id') > 0) FROM fusion.sysmon_events WHERE validation_id = '$run_id' AND ingestion_path = '/security' FORMAT TSV"
  syslog_query="SELECT count(), countIf(ingestion_protocol = 'syslog_tcp'), countIf(ingestion_protocol = 'syslog_udp'), countIf(original_format = 'rfc3164'), countIf(original_format = 'rfc5424'), countIf(product = 'mystery-app' AND position(raw_json, 'opaque vendor payload') > 0), countIf(source_address != ''), countIf(source_ip = '') FROM fusion.sysmon_events WHERE position(raw_json, '$run_id') > 0 AND source_type = 'generic_syslog' FORMAT TSV"
  attempt=1
  security_result=''
  syslog_result=''
  while [ "$attempt" -le 20 ]; do
    security_result=$(fusion_compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$security_query")
    syslog_result=$(fusion_compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$syslog_query")
    security_total=$(printf '%s' "$security_result" | cut -f1)
    syslog_total=$(printf '%s' "$syslog_result" | cut -f1)
    if [ "$security_total" -ge "$security_sample_count" ] && [ "$syslog_total" -ge 3 ]; then break; fi
    sleep 1
    attempt=$((attempt + 1))
  done
  expected_security=$(printf '5\t1\t1\t1\t1\t1\t5\t5\t5')
  expected_syslog=$(printf '3\t1\t2\t1\t2\t1\t3\t3')
  if [ "$security_result" != "$expected_security" ]; then
    echo "Unexpected normalized security-tool telemetry: $security_result" >&2
    exit 1
  fi
  if [ "$syslog_result" != "$expected_syslog" ]; then
    echo "Unexpected normalized TCP/UDP syslog telemetry: $syslog_result" >&2
    exit 1
  fi
  echo "  SuricataRows=$security_total, SyslogRows=$syslog_total"
fi

echo "[10/12] Validating endpoint and security-source dashboard queries..."
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

security_dashboard="$FUSION_ROOT/grafana/dashboards/fusion-security-sources.json"
for title in "Security tool events" "Suricata alerts" "Syslog events" "Network activity" "Security source activity over time" "Events by vendor" "Events by product" "Events by source type" "Events by ingestion protocol" "Top Suricata signatures" "Top source IPs" "Top destination IPs" "DNS activity" "HTTP activity" "Recent security alerts"; do
  grep -q "\"title\": \"$title\"" "$security_dashboard"
done
for variable in computer platform vendor product source ingestion; do
  grep -q "\"name\": \"$variable\"" "$security_dashboard"
done
if [ "$skip_samples" = false ]; then
  security_panel_result=$(fusion_compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --query "SELECT countIf(event_kind = 'alert'), countIf(event_category = 'dns' AND domain != ''), countIf(event_category = 'web' AND url != ''), uniqExact(vendor), uniqExact(product), uniqExact(source_type), uniqExact(ingestion_protocol) FROM fusion.sysmon_events WHERE (validation_id = '$run_id' OR position(raw_json, '$run_id') > 0) FORMAT TSV")
  security_panel_alerts=$(printf '%s' "$security_panel_result" | cut -f1)
  security_panel_dns=$(printf '%s' "$security_panel_result" | cut -f2)
  security_panel_http=$(printf '%s' "$security_panel_result" | cut -f3)
  security_panel_vendors=$(printf '%s' "$security_panel_result" | cut -f4)
  security_panel_products=$(printf '%s' "$security_panel_result" | cut -f5)
  security_panel_sources=$(printf '%s' "$security_panel_result" | cut -f6)
  security_panel_protocols=$(printf '%s' "$security_panel_result" | cut -f7)
  if [ "$security_panel_alerts" -lt 1 ] || [ "$security_panel_dns" -lt 1 ] || [ "$security_panel_http" -lt 1 ] || [ "$security_panel_vendors" -lt 2 ] || [ "$security_panel_products" -lt 2 ] || [ "$security_panel_sources" -lt 2 ] || [ "$security_panel_protocols" -lt 3 ]; then
    echo "Security Sources dashboard checks did not return expected telemetry: $security_panel_result" >&2
    exit 1
  fi
fi

echo "[11/12] Running detection engine acceptance tests..."
"$SCRIPT_DIR/validate-detections.sh"

echo "[12/12] Checking Grafana, its data source, and all provisioned dashboards..."
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

security_dashboards=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/search?query=Fusion%20Security%20Sources")
printf '%s' "$security_dashboards" | grep -q 'fusion-security-sources'
provisioned_security_dashboard=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/dashboards/uid/fusion-security-sources")
for title in "Suricata alerts" "Syslog events" "Events by vendor" "Events by ingestion protocol" "DNS activity" "HTTP activity" "Recent security alerts"; do
  printf '%s' "$provisioned_security_dashboard" | grep -Fq "\"title\":\"$title\""
done
for variable in computer platform vendor product source ingestion; do
  printf '%s' "$provisioned_security_dashboard" | grep -Fq "\"name\":\"$variable\""
done

detection_dashboards=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/search?query=Fusion%20Detections")
printf '%s' "$detection_dashboards" | grep -q 'fusion-detections'
provisioned_detection_dashboard=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/dashboards/uid/fusion-detections")
for title in "Total detections" "New detections" "High/Critical detections" "Detections over time" "Detections by severity" "Detections by rule" "Detections by platform" "Detections by source type" "Detections by host" "Top affected users" "Top source IPs" "Top destination IPs" "MITRE tactics" "MITRE techniques" "Recent detections"; do
  printf '%s' "$provisioned_detection_dashboard" | grep -Fq "\"title\":\"$title\""
done
for variable in severity status platform host rule tactic technique; do
  printf '%s' "$provisioned_detection_dashboard" | grep -Fq "\"name\":\"$variable\""
done

echo "Validation passed: v0.1-v0.4 ingestion, v0.5 detections, migrations, restart safety, storage, and all dashboards are healthy."
