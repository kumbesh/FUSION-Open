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
    --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
    --async_insert=0 --query "$1"
}

run_id="fusion-v06-$(date -u '+%Y%m%d%H%M%S')-$$"
engine_id="fusion-correlation-validation-${run_id}"
host_name="${run_id}.invalid"
first_detection="${run_id}-detection-1"
second_detection="${run_id}-detection-2"
schema_database="fusion_v06_validation_$(date -u '+%Y%m%d%H%M%S')_$$"
source_fixture_sql=$(mktemp)
migration_sql=$(mktemp)
migration_integrity_sql=$(mktemp)
schema_test_sql=$(mktemp)
schema_integrity_test_sql=$(mktemp)
service_stopped=false
smoke_seeded=false
schema_database_created=false

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  rm -f "$source_fixture_sql" "$migration_sql" "$migration_integrity_sql" \
    "$schema_test_sql" "$schema_integrity_test_sql"
  if [ "$schema_database_created" = true ]; then
    query_clickhouse "DROP DATABASE IF EXISTS $schema_database" >/dev/null 2>&1
  fi
  if [ "$smoke_seeded" = true ]; then
    query_clickhouse "ALTER TABLE fusion.incident_detection_links DELETE WHERE validation_id = '$run_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.incident_event_links DELETE WHERE validation_id = '$run_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.incidents DELETE WHERE validation_id = '$run_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.correlation_evaluated_inputs DELETE WHERE engine_id = '$engine_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.correlation_episode_state DELETE WHERE engine_id = '$engine_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.correlation_rule_state DELETE WHERE engine_id = '$engine_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.correlation_scope_bootstrap_confirmations DELETE WHERE engine_id = '$engine_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.correlation_schedule_state DELETE WHERE engine_id = '$engine_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.correlation_detection_input_witness DELETE WHERE detection_id IN ('$first_detection', '$second_detection') SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.correlation_detection_input_history DELETE WHERE validation_id = '$run_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
    query_clickhouse "ALTER TABLE fusion.detections DELETE WHERE validation_id = '$run_id' SETTINGS mutations_sync = 2" >/dev/null 2>&1
  fi
  if [ "$service_stopped" = true ]; then
    fusion_compose start fusion-correlation-engine >/dev/null 2>&1
    fusion_compose up --detach --wait --wait-timeout 180 fusion-correlation-engine >/dev/null 2>&1
  fi
  if [ "$status" -eq 0 ]; then
    echo "Correlation validation passed: four rules, Python regressions, v0.6 schema/replay contracts, exact ledger coverage, one synthetic host incident, two evidence links, status telemetry, and idempotent replay are healthy. This is synthetic validation, not real v0.6 acceptance evidence."
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

echo "[correlations 1/5] Validating exactly four frozen correlation rules offline..."
fusion_compose run --rm --no-deps fusion-correlation-engine \
  validate-rules --expected-count 4

echo "[correlations 2/5] Running Python correlation tests in an ephemeral built-image container..."
fusion_compose run --rm --no-deps --user 0 --entrypoint /bin/sh \
  --workdir /work/correlation/engine -v "$FUSION_ROOT:/work:ro" \
  fusion-correlation-engine -c \
  'python -m pip install --quiet --target /tmp/fusion-pytest pytest==9.1.1 && PYTHONPATH=/tmp/fusion-pytest:/work/correlation/engine python -m pytest -p no:cacheprovider /work/correlation/tests /work/tests/grafana'

echo "[correlations 3/5] Verifying live and isolated v0.6 schema/view contracts..."
live_schema=$(query_clickhouse "SELECT countIf(engine NOT IN ('View','MaterializedView')), countIf(engine = 'View'), countIf(engine = 'MaterializedView') FROM system.tables WHERE database = 'fusion' AND name IN ('correlation_detection_input_history','correlation_detection_input_history_mv','correlation_detection_input_witness','correlation_detection_input_witness_mv','correlation_integrity_events','correlation_integrity_scope_state_current','incidents','incident_detection_links','incident_event_links','correlation_evaluated_inputs','correlation_rule_state','correlation_episode_state','correlation_scope_bootstrap_confirmations','correlation_schedule_state','incident_status_transitions','correlation_evaluated_inputs_current','incident_status_transitions_current','correlation_scope_bootstrap_confirmations_current','correlation_rule_state_current','correlation_episode_state_current','correlation_schedule_state_current','incident_detection_links_current','incident_event_links_current','incident_revisions_committed','incidents_current','incident_timeline') FORMAT TSV")
expected_live_schema=$(printf '12\t12\t2')
if [ "$live_schema" != "$expected_live_schema" ]; then
  echo "ClickHouse v0.6 correlation schema is incomplete: $live_schema" >&2
  exit 1
fi

insert_clickhouse_admin "CREATE DATABASE $schema_database" >/dev/null
schema_database_created=true
sed "s/fusion\./$schema_database./g" \
  "$FUSION_ROOT/clickhouse/tests/010_v06_source_fixture.sql" > "$source_fixture_sql"
sed "s/fusion\./$schema_database./g" \
  "$FUSION_ROOT/clickhouse/migrations/010_correlation_incidents_v06.sql" > "$migration_sql"
sed "s/fusion\./$schema_database./g" \
  "$FUSION_ROOT/clickhouse/migrations/011_correlation_integrity_v06.sql" > "$migration_integrity_sql"
sed "s/fusion\./$schema_database./g" \
  "$FUSION_ROOT/clickhouse/tests/010_v06_correlation_schema.sql" > "$schema_test_sql"
sed "s/fusion\./$schema_database./g" \
  "$FUSION_ROOT/clickhouse/tests/011_v06_correlation_integrity_schema.sql" > "$schema_integrity_test_sql"
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --database "$schema_database" --multiquery < "$source_fixture_sql" >/dev/null
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --database "$schema_database" --multiquery < "$migration_sql" >/dev/null
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --database "$schema_database" --multiquery < "$migration_sql" >/dev/null
schema_result=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --async_insert=0 --database "$schema_database" --multiquery < "$schema_test_sql")
if [ "$(printf '%s\n' "$schema_result" | tail -n 1)" != "v0.6 correlation schema regression passed" ]; then
  echo "The isolated v0.6 schema regression did not report success." >&2
  exit 1
fi
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --database "$schema_database" --multiquery < "$migration_integrity_sql" >/dev/null
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --database "$schema_database" --multiquery < "$migration_integrity_sql" >/dev/null
schema_integrity_result=$(fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --async_insert=0 --database "$schema_database" --multiquery < "$schema_integrity_test_sql")
if [ "$(printf '%s\n' "$schema_integrity_result" | tail -n 1)" != "v0.6 correlation integrity schema regression passed" ]; then
  echo "The isolated v0.6 correlation-integrity schema regression did not report success." >&2
  exit 1
fi
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --database "$schema_database" --multiquery < "$migration_integrity_sql" >/dev/null
fusion_compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --database "$schema_database" --multiquery < "$migration_integrity_sql" >/dev/null
post_population_reapply=$(query_clickhouse "SELECT (SELECT count() FROM (SELECT DISTINCT detection_id, detected_at, semantic_fingerprint FROM $schema_database.correlation_detection_input_history EXCEPT DISTINCT SELECT DISTINCT detection_id, detected_at, semantic_fingerprint FROM $schema_database.correlation_detection_input_witness)), (SELECT count() FROM (SELECT DISTINCT detection_id, detected_at, semantic_fingerprint FROM $schema_database.correlation_detection_input_witness EXCEPT DISTINCT SELECT DISTINCT detection_id, detected_at, semantic_fingerprint FROM $schema_database.correlation_detection_input_history)), (SELECT count() FROM $schema_database.correlation_integrity_events), (SELECT uniqExact(integrity_event_id) FROM $schema_database.correlation_integrity_events), (SELECT count() FROM $schema_database.correlation_integrity_scope_state_current) FORMAT TSV")
expected_post_population_reapply=$(printf '0\t0\t6\t5\t1')
if [ "$post_population_reapply" != "$expected_post_population_reapply" ]; then
  echo "Populated v0.6 integrity migration reapplication changed logical history or integrity state: $post_population_reapply" >&2
  exit 1
fi
query_clickhouse "DROP DATABASE $schema_database" >/dev/null
schema_database_created=false

echo "[correlations 4/5] Running a tagged synthetic host-correlation smoke..."
fusion_compose stop fusion-correlation-engine
service_stopped=true
insert_clickhouse_admin "INSERT INTO fusion.detections (detection_id, detected_at, updated_at, rule_id, rule_name, rule_version, severity, status, platform, vendor, product, source_type, host_name, source_event_uid, source_event_id, source_event_time, validation_id, evidence_json, rule_metadata_json) VALUES ('$first_detection', now64(3), now64(3), 'fusion-validation-rule-one', 'Fusion synthetic correlation validation one', '1', 'high', 'new', 'windows', 'Fusion', 'Validation', 'fusion_validation', '$host_name', '${run_id}-event-1', '${run_id}-source-1', now64(3) - INTERVAL 2 SECOND, '$run_id', '{}', '{}'), ('$second_detection', now64(3), now64(3), 'fusion-validation-rule-two', 'Fusion synthetic correlation validation two', '1', 'medium', 'new', 'windows', 'Fusion', 'Validation', 'fusion_validation', '$host_name', '${run_id}-event-2', '${run_id}-source-2', now64(3) - INTERVAL 1 SECOND, '$run_id', '{}', '{}')" >/dev/null
smoke_seeded=true

run_smoke_cycle() {
  fusion_compose run --rm --no-deps \
    -e "FUSION_CORRELATION_ENGINE_ID=$engine_id" \
    -e FUSION_CORRELATION_LOOKBACK_SECONDS=60 \
    -e FUSION_CORRELATION_BATCH_SIZE=10000 \
    fusion-correlation-engine run --once
}

run_smoke_cycle
smoke_result=$(query_clickhouse "SELECT (SELECT count() FROM fusion.incidents_current WHERE validation_id = '$run_id' AND correlation_rule_id = 'fusion-correlation-host-suspicious-activity' AND input_count = 2 AND detection_count = 2 AND event_count = 0), (SELECT count() FROM fusion.incident_detection_links_current WHERE validation_id = '$run_id'), (SELECT count() FROM fusion.incident_event_links_current WHERE validation_id = '$run_id'), (SELECT count() FROM fusion.correlation_evaluated_inputs_current WHERE engine_id = '$engine_id' AND validation_id = '$run_id'), (SELECT uniqExact(tuple(correlation_rule_id, input_kind, input_id)) FROM fusion.correlation_evaluated_inputs_current WHERE engine_id = '$engine_id' AND validation_id = '$run_id'), (SELECT countIf(evaluation_action = 'created') FROM fusion.correlation_evaluated_inputs_current WHERE engine_id = '$engine_id' AND validation_id = '$run_id' AND correlation_rule_id = 'fusion-correlation-host-suspicious-activity'), (SELECT count() FROM fusion.incident_timeline WHERE validation_id = '$run_id') FORMAT TSV")
expected_smoke=$(printf '1\t2\t0\t8\t8\t1\t2')
if [ "$smoke_result" != "$expected_smoke" ]; then
  echo "Unexpected synthetic correlation result: $smoke_result" >&2
  exit 1
fi

echo "[correlations 5/5] Replaying the smoke and proving logical idempotence..."
before_replay=$(query_clickhouse "SELECT (SELECT count() FROM fusion.incidents WHERE validation_id = '$run_id'), (SELECT count() FROM fusion.incident_detection_links WHERE validation_id = '$run_id'), (SELECT count() FROM fusion.correlation_evaluated_inputs WHERE engine_id = '$engine_id' AND validation_id = '$run_id') FORMAT TSV")
run_smoke_cycle
after_replay=$(query_clickhouse "SELECT (SELECT count() FROM fusion.incidents WHERE validation_id = '$run_id'), (SELECT count() FROM fusion.incident_detection_links WHERE validation_id = '$run_id'), (SELECT count() FROM fusion.correlation_evaluated_inputs WHERE engine_id = '$engine_id' AND validation_id = '$run_id') FORMAT TSV")
if [ "$after_replay" != "$before_replay" ] || [ "$after_replay" != "$(printf '1\t2\t8')" ]; then
  echo "Correlation replay amplified physical effects: before=$before_replay after=$after_replay" >&2
  exit 1
fi
status_output=$(fusion_compose run --rm --no-deps \
  -e "FUSION_CORRELATION_ENGINE_ID=$engine_id" \
  fusion-correlation-engine status)
printf '%s' "$status_output" | grep -q '"schema": "fusion-correlation-status/v1"'
printf '%s' "$status_output" | grep -q '"scope_count": 4'
