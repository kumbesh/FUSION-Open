"""Command-line entry point for the Fusion Detection Engine."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .checkpoint import DetectionEngine
from .clickhouse import ClickHouseStore
from .compiler import SigmaCompiler, load_rules_strict, validate_rule_directory
from .config import Settings
from .evaluator import DetectionEvaluator
from .fixtures import prepare_fixture_events, validate_fixtures
from .models import RuleValidationError


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
        if args.command == "healthcheck":
            load_rules_strict(settings.rules_dir, settings.mapping_path)
            ClickHouseStore(settings).healthcheck()
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


def _run(settings: Settings, once: bool) -> int:
    logger = logging.getLogger("fusion_detection")
    rules = load_rules_strict(settings.rules_dir, settings.mapping_path)
    evaluator = DetectionEvaluator(rules, settings.mitre_mapping_path)
    store = ClickHouseStore(settings)
    engine = DetectionEngine(store, evaluator, logger)
    stop = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    logger.info(
        "engine_started rules_loaded=%d poll_seconds=%d lookback_seconds=%d batch_size=%d",
        len(rules), settings.poll_seconds, settings.lookback_seconds, settings.batch_size,
    )
    backoff = 1
    while not stop:
        try:
            engine.run_cycle()
            backoff = 1
            if once:
                return 0
            _interruptible_sleep(settings.poll_seconds, lambda: stop)
        except Exception:
            logger.exception("poll_failed retry_seconds=%d", backoff)
            if once:
                return 1
            _interruptible_sleep(backoff, lambda: stop)
            backoff = min(backoff * 2, 60)
    logger.info("engine_stopped")
    return 0


def _interruptible_sleep(seconds: int, stopped: Callable[[], bool]) -> None:
    deadline = time.monotonic() + seconds
    while not stopped() and time.monotonic() < deadline:
        time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
