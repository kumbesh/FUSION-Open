#!/usr/bin/env sh
set -eu

FUSION_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FUSION_COMPOSE_FILE="$FUSION_ROOT/docker-compose.yml"

fusion_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker CLI was not found. Install and start Docker Desktop or Docker Engine." >&2
    exit 1
  fi
  docker "$@"
}

fusion_compose() {
  fusion_docker compose --project-directory "$FUSION_ROOT" -f "$FUSION_COMPOSE_FILE" "$@"
}

fusion_assert_engine() {
  if ! fusion_docker info >/dev/null 2>&1; then
    echo "Docker is installed but the engine is not running." >&2
    exit 1
  fi
}

fusion_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr '+/' '-_' | tr -d '=\n'
  else
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

fusion_init_env() {
  if [ -f "$FUSION_ROOT/.env" ]; then
    return
  fi
  clickhouse_secret=$(fusion_secret)
  grafana_secret=$(fusion_secret)
  sed \
    -e "s/CHANGE_ME_CLICKHOUSE/$clickhouse_secret/" \
    -e "s/CHANGE_ME_GRAFANA/$grafana_secret/" \
    "$FUSION_ROOT/.env.example" > "$FUSION_ROOT/.env"
  chmod 600 "$FUSION_ROOT/.env" 2>/dev/null || true
  echo "Created .env with generated local passwords."
}

fusion_load_env() {
  fusion_init_env
  set -a
  # shellcheck disable=SC1091
  . "$FUSION_ROOT/.env"
  set +a
}

fusion_apply_migrations() {
  fusion_load_env
  for migration in "$FUSION_ROOT"/clickhouse/migrations/*.sql; do
    if [ ! -f "$migration" ]; then
      continue
    fi
    echo "Applying ClickHouse migration $(basename "$migration")..."
    fusion_compose exec -T clickhouse clickhouse-client \
      --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery < "$migration"
  done
}
