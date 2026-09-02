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

echo "[1/6] Validating Docker Compose configuration..."
fusion_compose config --quiet

echo "[2/6] Running Vector configuration and VRL unit tests..."
fusion_compose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml
fusion_compose run --rm --no-deps vector test /etc/vector/vector.yaml

echo "[3/6] Checking container health..."
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
if [ "$skip_samples" = false ]; then
  echo "[4/6] Sending sample Sysmon events..."
  event_time=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
  for sample in "$FUSION_ROOT"/samples/sysmon/*.json; do
    payload=$(sed -E "s/\"UtcTime\": \"[^\"]+\"/\"UtcTime\": \"$event_time\"/" "$sample")
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
      -H 'Content-Type: application/json' \
      -H "X-Fusion-Validation-Id: $run_id" \
      --data-binary "$payload" \
      "http://127.0.0.1:${FUSION_INGEST_PORT:-8686}/sysmon")
    if [ "$status" != "202" ]; then
      echo "Vector rejected $(basename "$sample") with HTTP $status." >&2
      exit 1
    fi
  done
else
  echo "[4/6] Sample ingestion skipped."
fi

echo "[5/6] Verifying normalized rows in ClickHouse..."
if [ "$skip_samples" = false ]; then
  query="SELECT count(), countIf(event_id = 1), countIf(event_id = 1 AND (positionCaseInsensitiveUTF8(image, 'powershell.exe') > 0 OR positionCaseInsensitiveUTF8(image, 'pwsh.exe') > 0)), countIf(event_id = 3) FROM fusion.sysmon_events WHERE validation_id = '$run_id' FORMAT TSV"
  result="0\t0\t0\t0"
  attempt=1
  while [ "$attempt" -le 20 ]; do
    result=$(fusion_compose exec -T clickhouse clickhouse-client \
      --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$query")
    total=$(printf '%s' "$result" | cut -f1)
    if [ "$total" -ge 3 ]; then
      break
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  process=$(printf '%s' "$result" | cut -f2)
  powershell=$(printf '%s' "$result" | cut -f3)
  network=$(printf '%s' "$result" | cut -f4)
  if [ "$total" -lt 3 ] || [ "$process" -lt 2 ] || [ "$powershell" -lt 1 ] || [ "$network" -lt 1 ]; then
    echo "Unexpected ClickHouse counts: $result" >&2
    exit 1
  fi
  echo "  Rows=$total, Process=$process, PowerShell=$powershell, Network=$network"
fi

echo "[6/6] Checking Grafana and the provisioned ClickHouse data source..."
grafana_base="http://127.0.0.1:${FUSION_GRAFANA_PORT:-3000}"
curl -fsS "$grafana_base/api/health" >/dev/null
datasource_health=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/datasources/uid/fusion-clickhouse/health")
printf '%s' "$datasource_health" | grep -q '"status":"OK"'
dashboards=$(curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
  "$grafana_base/api/search?query=Fusion%20Security%20Overview")
printf '%s' "$dashboards" | grep -q 'fusion-security-overview'

echo "Validation passed: ingestion, normalization, storage, data source, and dashboard are healthy."

