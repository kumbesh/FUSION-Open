#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(
  CDPATH=
  cd -- "$(dirname -- "$0")"
  pwd
)
FUSION_ROOT=$(
  CDPATH=
  cd -- "$SCRIPT_DIR/.."
  pwd
)
TEST_DIR="$FUSION_ROOT/tests/vector-recovery"
COMPOSE_FILE="$TEST_DIR/docker-compose.yml"
HARDENED_CONFIG="$TEST_DIR/vector.yaml"
PROJECT_NAME=${FUSION_RECOVERY_PROJECT_NAME:-"fusion-vector-recovery-$(date +%s)-$$"}
KEEP_STATE=${FUSION_RECOVERY_KEEP_STATE:-0}
STATE_CREATED=false

case "$PROJECT_NAME" in
  fusion-vector-recovery-*) ;;
  *)
    echo "Refusing unsafe recovery-test project name: $PROJECT_NAME" >&2
    echo "The name must start with fusion-vector-recovery-." >&2
    exit 2
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI was not found." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed but the engine is not running." >&2
  exit 1
fi

case "$PROJECT_NAME" in
  *[!a-z0-9_-]*)
    echo "Refusing recovery-test project name with unsupported characters: $PROJECT_NAME" >&2
    exit 2
    ;;
esac
if [ -n "$(docker ps --all --quiet --filter "label=com.docker.compose.project=$PROJECT_NAME")" ] ||
   [ -n "$(docker volume ls --quiet --filter "label=com.docker.compose.project=$PROJECT_NAME")" ] ||
   docker network inspect "${PROJECT_NAME}_recovery" >/dev/null 2>&1; then
  echo "Refusing to reuse existing Docker resources for project $PROJECT_NAME." >&2
  exit 2
fi

if [ -n "${FUSION_RECOVERY_STATE_PATH:-}" ]; then
  STATE_DIR=$FUSION_RECOVERY_STATE_PATH
  case "$(basename -- "$STATE_DIR")" in
    fusion-vector-recovery-*) ;;
    *)
      echo "Refusing state directory without a fusion-vector-recovery- prefix: $STATE_DIR" >&2
      exit 2
      ;;
  esac
  if [ -e "$STATE_DIR" ] && [ "$(find "$STATE_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    echo "Refusing non-empty recovery-test state directory: $STATE_DIR" >&2
    exit 2
  fi
  mkdir -p "$STATE_DIR"
else
  STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fusion-vector-recovery-XXXXXX")
  STATE_CREATED=true
fi

mkdir -p "$STATE_DIR/fixtures"
chmod 0777 "$STATE_DIR/fixtures"
: > "$STATE_DIR/.fusion-vector-recovery-test"

to_docker_path() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) cygpath -m "$1" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

export FUSION_RECOVERY_STATE_DIR
FUSION_RECOVERY_STATE_DIR=$(to_docker_path "$STATE_DIR")
export FUSION_RECOVERY_VECTOR_CONFIG
FUSION_RECOVERY_VECTOR_CONFIG=$(to_docker_path "$HARDENED_CONFIG")
DOCKER_COMPOSE_FILE=$(to_docker_path "$COMPOSE_FILE")

compose() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
        docker compose --project-name "$PROJECT_NAME" --file "$DOCKER_COMPOSE_FILE" "$@"
      ;;
    *)
      docker compose --project-name "$PROJECT_NAME" --file "$DOCKER_COMPOSE_FILE" "$@"
      ;;
  esac
}

cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$result" -ne 0 ]; then
    echo "Recovery-test logs:" >&2
    compose logs --no-color --tail=200 >&2
  fi
  # Do not pass --volumes: the test intentionally preserves its disk buffer.
  compose down --remove-orphans >/dev/null 2>&1
  if [ "$KEEP_STATE" = "1" ]; then
    echo "Preserved isolated recovery-test state at $STATE_DIR"
  elif [ "$STATE_CREATED" = "true" ] && [ -f "$STATE_DIR/.fusion-vector-recovery-test" ]; then
    case "$(basename -- "$STATE_DIR")" in
      fusion-vector-recovery-*) rm -r -- "$STATE_DIR" ;;
      *) echo "Refusing to remove unexpected state path: $STATE_DIR" >&2 ;;
    esac
  fi
  exit "$result"
}
trap cleanup EXIT HUP INT TERM

wait_for_clickhouse() {
  attempts=0
  while [ "$attempts" -lt 60 ]; do
    # Expansion is intentionally performed by the shell in the container.
    # shellcheck disable=SC2016
    if compose exec -T clickhouse sh -c \
      'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT 1"' \
      >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "ClickHouse did not become ready." >&2
  return 1
}

wait_for_vector() {
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    if compose exec -T vector wget -q -O /dev/null http://127.0.0.1:8687/health \
      >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "Vector did not become ready." >&2
  return 1
}

query_clickhouse() {
  # Expansion is intentionally performed by the shell in the container.
  # shellcheck disable=SC2016
  compose exec -T clickhouse sh -c \
    'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$1"' \
    sh "$1" | tr -d '\r'
}

wait_for_query_value() {
  query=$1
  expected=$2
  attempts=0
  while [ "$attempts" -lt 60 ]; do
    actual=$(query_clickhouse "$query" 2>/dev/null || true)
    if [ "$actual" = "$expected" ]; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "Timed out waiting for ClickHouse query result '$expected'; last result was '$actual'." >&2
  return 1
}

post_fixture() {
  fixture=$1
  compose exec -T vector wget -q -O /dev/null \
    --header 'Content-Type: application/x-ndjson' \
    --post-file "/fixtures/$fixture" \
    http://127.0.0.1:8686/recovery
}

assert_production_guard() {
  sink_block=$(sed -n '/^  clickhouse:$/,/^  rejected_console:$/p' "$FUSION_ROOT/vector/vector.yaml")
  encoding_block=$(printf '%s\n' "$sink_block" | sed -n '/^    encoding:$/,/^    batch:$/p')
  printf '%s\n' "$sink_block" | grep -q '^    skip_unknown_fields: false$'
  printf '%s\n' "$sink_block" | grep -q '^    encoding:$'
  printf '%s\n' "$encoding_block" | grep -q '^        - X-Fusion-Validation-Id$'
  printf '%s\n' "$encoding_block" | grep -q '^        - x-fusion-validation-id$'
  [ "$(printf '%s\n' "$encoding_block" | grep -c '^        - ')" -eq 2 ]
}

LEGACY_CONFIG="$STATE_DIR/vector-legacy.yaml"
awk '
  /FUSION_RECOVERY_GUARD_BEGIN/ { skip = 1; next }
  /FUSION_RECOVERY_GUARD_END/ { skip = 0; next }
  !skip { print }
' "$HARDENED_CONFIG" > "$LEGACY_CONFIG"

printf '%s\n' '{"sequence":0}' > "$STATE_DIR/fixtures/baseline.ndjson"
: > "$STATE_DIR/fixtures/recovery.ndjson"
sequence=1
while [ "$sequence" -le 1000 ]; do
  if [ "$sequence" -eq 197 ]; then
    printf '{"sequence":%s,"X-Fusion-Validation-Id":"stale-transport-metadata"}\n' "$sequence"
  else
    printf '{"sequence":%s}\n' "$sequence"
  fi
  sequence=$((sequence + 1))
done > "$STATE_DIR/fixtures/recovery.ndjson"
printf '%s\n' '{"sequence":1001}' > "$STATE_DIR/fixtures/post-recovery.ndjson"

assert_production_guard
echo "PASS: production ClickHouse sink has the narrow transport-header guard"

FUSION_RECOVERY_VECTOR_CONFIG=$(to_docker_path "$LEGACY_CONFIG")
export FUSION_RECOVERY_VECTOR_CONFIG
compose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml >/dev/null

FUSION_RECOVERY_VECTOR_CONFIG=$(to_docker_path "$HARDENED_CONFIG")
export FUSION_RECOVERY_VECTOR_CONFIG
compose run --rm --no-deps vector validate --no-environment /etc/vector/vector.yaml >/dev/null
compose run --rm --no-deps vector test /etc/vector/vector.yaml >/dev/null
echo "PASS: legacy and hardened recovery-test Vector configurations validate"

compose up -d clickhouse
wait_for_clickhouse

FUSION_RECOVERY_VECTOR_CONFIG=$(to_docker_path "$LEGACY_CONFIG")
export FUSION_RECOVERY_VECTOR_CONFIG
compose up -d vector
wait_for_vector
post_fixture baseline.ndjson
wait_for_query_value \
  "SELECT count() FROM fusion.sysmon_events WHERE source_type = 'vector_recovery_test' AND record_id = 0 FORMAT TSVRaw" \
  "1"
echo "PASS: normal strict-schema ingestion works"

compose stop --timeout 20 clickhouse >/dev/null
post_fixture recovery.ndjson

attempts=0
while [ "$attempts" -lt 30 ]; do
  if compose logs --no-color vector 2>&1 | grep -Eqi 'connection refused|dns error|HTTP error|Retrying after error|error sending request|call request error'; then
    break
  fi
  attempts=$((attempts + 1))
  sleep 1
done
if [ "$attempts" -ge 30 ]; then
  echo "Vector did not report the intentional ClickHouse outage." >&2
  exit 1
fi
echo "PASS: temporary ClickHouse unavailability reached the retry path"

compose stop --timeout 5 vector >/dev/null
compose rm --force vector >/dev/null

FUSION_RECOVERY_VECTOR_CONFIG=$(to_docker_path "$HARDENED_CONFIG")
export FUSION_RECOVERY_VECTOR_CONFIG
compose up -d vector
wait_for_vector
sleep 1
compose start clickhouse >/dev/null
wait_for_clickhouse

wait_for_query_value \
  "SELECT count() FROM fusion.sysmon_events WHERE source_type = 'vector_recovery_test' AND record_id BETWEEN 1 AND 1000 FORMAT TSVRaw" \
  "1000"

recovery_result=$(query_clickhouse \
  "SELECT count(), uniqExact(source_event_id), sum(record_id), countIf(record_id = 197), countIf(position(raw_json, '\"X-Fusion-Validation-Id\":\"stale-transport-metadata\"') > 0) FROM fusion.sysmon_events WHERE source_type = 'vector_recovery_test' AND record_id BETWEEN 1 AND 1000 FORMAT TSVRaw")
expected_result=$(printf '1000\t1000\t500500\t1\t1')
if [ "$recovery_result" != "$expected_result" ]; then
  echo "Unexpected replay result: $recovery_result" >&2
  exit 1
fi

hardened_logs=$(compose logs --no-color vector 2>&1)
if printf '%s\n' "$hardened_logs" | grep -Eq 'Code: 117|Bad Request|Events dropped'; then
  echo "The hardened replay logged a terminal rejection or dropped event." >&2
  exit 1
fi
echo "PASS: 1,000 buffered events resumed once after restart and recovery"
echo "PASS: stale row 197 did not poison valid peers or weaken strict schema checks"

post_fixture post-recovery.ndjson
wait_for_query_value \
  "SELECT count() FROM fusion.sysmon_events WHERE source_type = 'vector_recovery_test' AND record_id = 1001 FORMAT TSVRaw" \
  "1"
echo "PASS: ingestion remains live after recovery"
echo "Preserved project-scoped test volumes for $PROJECT_NAME (no volume cleanup was performed)."
echo "Vector sink recovery regression passed."
