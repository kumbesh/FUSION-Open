#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

skip_pull=false
skip_validate=false
for arg in "$@"; do
  case "$arg" in
    --skip-pull) skip_pull=true ;;
    --skip-validate) skip_validate=true ;;
    *) echo "Usage: $0 [--skip-pull] [--skip-validate]" >&2; exit 2 ;;
  esac
done

fusion_assert_engine
fusion_init_env
fusion_compose config --quiet

if [ "$skip_pull" = false ]; then
  echo "Pulling pinned Fusion images..."
  fusion_compose pull
fi

echo "Starting ClickHouse..."
fusion_compose up --detach --wait --wait-timeout 300 clickhouse
fusion_apply_migrations

echo "Starting Fusion..."
fusion_compose up --detach --force-recreate --no-deps vector grafana
fusion_compose up --detach --wait --wait-timeout 300 --remove-orphans

if [ "$skip_validate" = false ]; then
  "$SCRIPT_DIR/validate.sh"
fi

fusion_load_env
echo "Fusion is ready."
echo "Grafana: http://localhost:${FUSION_GRAFANA_PORT:-3000}"
echo "Ingest: http://${FUSION_BIND_ADDRESS:-127.0.0.1}:${FUSION_INGEST_PORT:-8686}/sysmon"
if [ "${FUSION_BIND_ADDRESS:-127.0.0.1}" != "127.0.0.1" ]; then
  echo "WARNING: Ingestion has no TLS or authentication. Restrict TCP ${FUSION_INGEST_PORT:-8686} to the isolated test VM or lab subnet." >&2
fi
