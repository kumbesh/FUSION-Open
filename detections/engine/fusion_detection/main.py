"""Command-line entry point for the Fusion Detection Engine."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import signal
import sys
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .checkpoint import DetectionEngine
from .clickhouse import ClickHouseStore
from .compiler import SigmaCompiler, load_rules_strict, validate_rule_directory
from .config import Settings
from .evaluator import DetectionEvaluator
from .fixtures import prepare_fixture_events, validate_fixtures
from .models import Checkpoint, RuleValidationError


MAX_CONSECUTIVE_DRAIN_CYCLES = 10
DRAIN_YIELD_SECONDS = 0.1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fusion-detection")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="run the incremental detection loop")
    run.add_argument("--once", action="store_true", help="run one polling cycle and exit")
    validate = subparsers.add_parser("validate-rules", help="validate all repository Sigma rules")
    validate.add_argument("--rules-dir", type=Path)
    validate.add_argument("--mapping", type=Path)
    fixture_validate = subparsers.add_parser("validate-fixtures", help="validate positive and negative rule fixtures")
    fixture_validate.add_argument("--fixtures-dir", type=Path, default=Path("/samples/detections"))
    seed = subparsers.add_parser("seed-fixtures", help="explicitly insert synthetic detection fixtures")
    seed.add_argument("--fixtures-dir", type=Path, default=Path("/samples/detections"))
    seed.add_argument("--run-id", required=True)
    dry_run = subparsers.add_parser("test-rule", help="evaluate one rule without writing detections")
    dry_run.add_argument("rule", type=Path)
    dry_run.add_argument("--mapping", type=Path)
    dry_run.add_argument("--mitre-mapping", type=Path)
    dry_run.add_argument("--hours", type=int, default=24)
    dry_run.add_argument("--limit", type=int, default=1000)
    subparsers.add_parser("status", help="print checkpoint and source-backlog telemetry as JSON")
    subparsers.add_parser("healthcheck", help="validate ClickHouse connectivity and rule loading")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = Settings.from_env()
        _configure_logging(settings.log_level)
        if args.command == "validate-rules":
            return _validate_rules(args.rules_dir or settings.rules_dir, args.mapping or settings.mapping_path)
        if args.command == "validate-fixtures":
            rules = load_rules_strict(settings.rules_dir, settings.mapping_path)
            positives, negatives = validate_fixtures(args.fixtures_dir, rules)
            print(f"Detection fixtures: positive={positives} negative={negatives}")
            return 0
        if args.command == "seed-fixtures":
            rules = load_rules_strict(settings.rules_dir, settings.mapping_path)
            positives, negatives = validate_fixtures(args.fixtures_dir, rules)
            events = prepare_fixture_events(args.fixtures_dir, args.run_id)
            inserted = ClickHouseStore(settings).insert_fixture_events(events)
            print(json.dumps({"run_id": args.run_id, "inserted": inserted, "positive": positives, "negative": negatives}, sort_keys=True))
            return 0
        if args.command == "test-rule":
            return _dry_run(args, settings)
        if args.command == "status":
            return _status(settings)
        if args.command == "healthcheck":
            rules = load_rules_strict(settings.rules_dir, settings.mapping_path)
            ClickHouseStore(
                settings,
                ruleset_fingerprint=_ruleset_fingerprint(rules, settings),
            ).healthcheck()
            return 0
        return _run(settings, once=args.once)
    except (RuleValidationError, ValueError, OSError) as exc:
        logging.getLogger("fusion_detection").error("startup_failed error=%s", exc)
        return 2
    except Exception as exc:
        logging.getLogger("fusion_detection").error("operation_failed error=%s", exc)
        return 1


def _validate_rules(rules_dir: Path, mapping_path: Path) -> int:
    result = validate_rule_directory(rules_dir, SigmaCompiler(mapping_path))
    for error in result.errors:
        print(error, file=sys.stderr)
    print(
        f"Detection rules: total={result.total} valid={result.valid} "
        f"invalid={result.invalid} unsupported={result.unsupported}"
    )
    return 1 if result.errors or result.total == 0 else 0


def _dry_run(args: argparse.Namespace, settings: Settings) -> int:
    if not 1 <= args.hours <= 720:
        raise ValueError("--hours must be between 1 and 720")
    if not 1 <= args.limit <= 10000:
        raise ValueError("--limit must be between 1 and 10000")
    compiler = SigmaCompiler(args.mapping or settings.mapping_path)
    rule = compiler.load_rule(args.rule)
    evaluator = DetectionEvaluator((rule,), args.mitre_mapping or settings.mitre_mapping_path)
    store = ClickHouseStore(settings)
    events = store.fetch_recent_events(datetime.now(timezone.utc) - timedelta(hours=args.hours), args.limit)
    matches = []
    for event in events:
        if evaluator.evaluate(event):
            matches.append(event["event_uid"])
    output = {
        "rule": str(args.rule),
        "rule_id": rule.rule.rule_id,
        "field_mapping_and_plan": rule.plan(),
        "bounded_event_query": {"lookback_hours": args.hours, "limit": args.limit},
        "events_evaluated": len(events),
        "matching_events": len(matches),
        "sample_event_ids": matches[:20],
        "detections_written": 0,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def _status(settings: Settings) -> int:
    rules = load_rules_strict(settings.rules_dir, settings.mapping_path)
    fingerprint = _ruleset_fingerprint(rules, settings)
    store = ClickHouseStore(settings, ruleset_fingerprint=fingerprint)
    checkpoint = store.load_checkpoint()
    checkpoint_persisted = checkpoint is not None
    if checkpoint is None:
        checkpoint = Checkpoint(
            datetime.now(timezone.utc) - timedelta(seconds=settings.lookback_seconds),
            "",
        )
    scope = store.load_evaluation_scope()
    evaluation_floor_time = (
        scope.evaluation_floor_time if scope is not None else None
    )
    candidate_cursor = scope.candidate_cursor if scope is not None else None
    evaluation_floor_persisted = scope is not None
    if evaluation_floor_time is None:
        evaluation_floor_time = store.load_legacy_evaluation_floor()
        evaluation_floor_persisted = evaluation_floor_time is not None
    if evaluation_floor_time is None:
        evaluation_floor_time = checkpoint.event_time - timedelta(
            seconds=settings.lookback_seconds
        )
    backlog = store.fetch_backlog_status(checkpoint, evaluation_floor_time)
    print(json.dumps({
        "engine_id": settings.engine_id,
        "ruleset_fingerprint": fingerprint,
        "checkpoint_persisted": checkpoint_persisted,
        "checkpoint_time": checkpoint.event_time.isoformat(),
        "checkpoint_uid": checkpoint.event_uid,
        "evaluation_floor_persisted": evaluation_floor_persisted,
        "evaluation_floor_time": evaluation_floor_time.isoformat(),
        "candidate_cursor_time": (
            candidate_cursor.event_time.isoformat()
            if candidate_cursor is not None
            else None
        ),
        "candidate_cursor_uid": (
            candidate_cursor.event_uid if candidate_cursor is not None else ""
        ),
        "newest_eligible_event_time": (
            backlog.newest_event_time.isoformat()
            if backlog.newest_event_time is not None
            else None
        ),
        "newest_eligible_event_uid": backlog.newest_event_uid,
        "checkpoint_lag_events": backlog.lag_events,
        "checkpoint_lag_seconds": backlog.lag_seconds,
        "unevaluated_event_count": backlog.unevaluated_events,
        "oldest_unevaluated_event_time": (
            backlog.oldest_unevaluated_event_time.isoformat()
            if backlog.oldest_unevaluated_event_time is not None
            else None
        ),
        "oldest_unevaluated_age_seconds": backlog.oldest_unevaluated_age_seconds,
    }, sort_keys=True))
    return 0


def _run(settings: Settings, once: bool) -> int:
    logger = logging.getLogger("fusion_detection")
    rules = load_rules_strict(settings.rules_dir, settings.mapping_path)
    fingerprint = _ruleset_fingerprint(rules, settings)
    evaluator = DetectionEvaluator(rules, settings.mitre_mapping_path)
    store = ClickHouseStore(settings, ruleset_fingerprint=fingerprint)
    engine = DetectionEngine(store, evaluator, logger)
    stop = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    logger.info(
        "engine_started rules_loaded=%d poll_seconds=%d lookback_seconds=%d batch_size=%d "
        "max_consecutive_drain_cycles=%d ruleset_fingerprint=%s",
        len(rules), settings.poll_seconds, settings.lookback_seconds, settings.batch_size,
        MAX_CONSECUTIVE_DRAIN_CYCLES,
        fingerprint,
    )
    result = _run_loop(settings, engine, once, lambda: stop, logger=logger)
    logger.info("engine_stopped")
    return result


def _run_loop(
    settings: Settings,
    engine: DetectionEngine,
    once: bool,
    stopped: Callable[[], bool],
    *,
    sleeper: Callable[[float, Callable[[], bool]], None] | None = None,
    logger: logging.Logger | None = None,
) -> int:
    sleep = sleeper or _interruptible_sleep
    active_logger = logger or logging.getLogger("fusion_detection")
    backoff = 1
    consecutive_drain_cycles = 0
    while not stopped():
        try:
            stats = engine.run_cycle()
            backoff = 1
            if once:
                return 0
            full_candidate_page = (
                stats.events_evaluated + stats.evaluation_failures
                == settings.batch_size
            )
            has_immediate_work = (
                full_candidate_page
                and stats.events_evaluated > 0
                and stats.backlog.unevaluated_events > 0
            )
            if has_immediate_work:
                consecutive_drain_cycles += 1
                if consecutive_drain_cycles >= MAX_CONSECUTIVE_DRAIN_CYCLES:
                    active_logger.info(
                        "backlog_drain_yield completed_cycles=%d checkpoint_lag_events=%d "
                        "unevaluated_event_count=%d yield_seconds=%.3f",
                        consecutive_drain_cycles,
                        stats.backlog.lag_events,
                        stats.backlog.unevaluated_events,
                        DRAIN_YIELD_SECONDS,
                    )
                    sleep(DRAIN_YIELD_SECONDS, stopped)
                    consecutive_drain_cycles = 0
                continue
            consecutive_drain_cycles = 0
            sleep(settings.poll_seconds, stopped)
        except Exception:
            consecutive_drain_cycles = 0
            active_logger.exception("poll_failed retry_seconds=%d", backoff)
            if once:
                return 1
            sleep(backoff, stopped)
            backoff = min(backoff * 2, 60)
    return 0


def _interruptible_sleep(seconds: float, stopped: Callable[[], bool]) -> None:
    deadline = time.monotonic() + seconds
    while not stopped() and time.monotonic() < deadline:
        time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))


def _ruleset_fingerprint(rules: tuple, settings: Settings) -> str:
    """Hash every input that can change matching or emitted detection metadata."""
    digest = hashlib.sha256()
    # A code-version change can alter compiler/evaluator semantics without
    # changing rule or mapping bytes. Include it so an upgraded engine receives
    # a fresh bounded evaluation ledger instead of trusting an older result.
    digest.update(b"fusion-detection-engine\0")
    digest.update(__version__.encode("utf-8"))
    digest.update(b"\0")
    for rule in sorted(rules, key=lambda compiled: compiled.rule.rule_id):
        digest.update(rule.rule.rule_id.encode("utf-8"))
        digest.update(b"\0")
        try:
            rule_path = rule.rule.path.resolve().relative_to(
                settings.rules_dir.resolve()
            ).as_posix()
        except ValueError:
            rule_path = str(rule.rule.path.resolve())
        digest.update(rule_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(rule.rule.path.read_bytes())
        digest.update(b"\0")
    for path in (settings.mapping_path, settings.mitre_mapping_path):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
