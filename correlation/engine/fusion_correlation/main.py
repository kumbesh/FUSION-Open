"""Command-line entry point for the Fusion correlation engine."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from . import __version__
from .clickhouse import ClickHouseCorrelationStore
from .compiler import CorrelationCompiler, load_rules_strict, validate_rule_directory
from .config import Settings
from .control import LifecycleControlServer, request_transition
from .engine import CorrelationEngine
from .evaluator import CorrelationEvaluator
from .models import CompiledRule, RuleValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fusion-correlation")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="run the bounded correlation loop")
    run.add_argument("--once", action="store_true", help="run one rule cycle and exit")
    validate = subparsers.add_parser(
        "validate-rules", help="validate repository correlation rules offline"
    )
    validate.add_argument("--rules-dir", type=Path)
    validate.add_argument("--mitre-mapping", type=Path)
    validate.add_argument("--expected-count", type=int, default=4)
    subparsers.add_parser(
        "status", help="print persisted correlation schedule telemetry as JSON"
    )
    subparsers.add_parser(
        "healthcheck", help="validate rule loading and ClickHouse connectivity"
    )
    transition = subparsers.add_parser(
        "transition", help="request a serialized local incident status transition"
    )
    transition.add_argument("incident_id")
    transition.add_argument("target_status", choices=("acknowledged", "closed"))
    transition.add_argument("--transition-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = Settings.from_env()
        _configure_logging(settings.log_level)
        if args.command == "validate-rules":
            return _validate_rules(
                args.rules_dir or settings.rules_dir,
                args.mitre_mapping or settings.mitre_mapping_path,
                args.expected_count,
            )
        if args.command == "transition":
            response = request_transition(
                settings.control_socket,
                args.incident_id,
                args.target_status,
                args.transition_id,
            )
            print(json.dumps(response, sort_keys=True))
            return 0 if response.get("ok") is True else 1

        compiler, rules = _load_rules(settings)
        store = ClickHouseCorrelationStore(settings)
        if args.command == "healthcheck":
            store.healthcheck()
            return 0
        if args.command == "status":
            # Status must remain observable while a projection-integrity fault
            # is keeping correlation scopes persistently blocked.
            store.healthcheck(check_projection_integrity=False)
            print(json.dumps(store.status(), sort_keys=True, default=_json_default))
            return 0
        return _run(settings, compiler, rules, store, once=args.once)
    except (RuleValidationError, ValueError, OSError) as exc:
        logging.getLogger("fusion_correlation").error("startup_failed error=%s", exc)
        return 2
    except Exception as exc:
        logging.getLogger("fusion_correlation").error("operation_failed error=%s", exc)
        return 1


def _load_rules(settings: Settings) -> tuple[CorrelationCompiler, tuple[CompiledRule, ...]]:
    compiler = CorrelationCompiler(settings.mitre_mapping_path)
    rules = load_rules_strict(settings.rules_dir, compiler)
    return compiler, rules


def _validate_rules(rules_dir: Path, mapping: Path, expected_count: int) -> int:
    if expected_count < 1:
        raise ValueError("--expected-count must be positive")
    result = validate_rule_directory(rules_dir, CorrelationCompiler(mapping))
    for error in result.errors:
        print(error, file=sys.stderr)
    print(
        f"Correlation rules: total={result.total} valid={result.valid} "
        f"invalid={result.invalid} expected={expected_count}"
    )
    return int(bool(result.errors or result.total != expected_count))


def _run(
    settings: Settings,
    compiler: CorrelationCompiler,
    rules: Sequence[CompiledRule],
    store: ClickHouseCorrelationStore,
    *,
    once: bool,
) -> int:
    logger = logging.getLogger("fusion_correlation")
    # Per-scope runtime preflight owns projection verification so it can first
    # persist a durable integrity event and block the affected scope.  Keep the
    # startup check limited to connectivity and the schema required to do so.
    store.healthcheck(check_projection_integrity=False)
    evaluator = CorrelationEvaluator(
        technique_to_tactics=compiler.technique_to_tactics
    )
    engine = CorrelationEngine(
        store=store,
        evaluator=evaluator,
        compiled_rules=rules,
        engine_id=settings.engine_id,
        lookback_seconds=settings.lookback_seconds,
        batch_size=settings.batch_size,
        context_limit=settings.context_limit,
        logger=logger,
    )
    stop_event = threading.Event()
    mutation_lock = threading.RLock()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    control = LifecycleControlServer(
        settings.control_socket,
        store,
        mutation_lock,
        on_error=lambda kind: logger.warning("control_request_failed kind=%s", kind),
    )
    control.start()
    logger.info(
        "engine_started rules_loaded=%d poll_seconds=%d lookback_seconds=%d "
        "batch_size=%d max_consecutive_drain_cycles=%d drain_yield_ms=%d",
        len(rules),
        settings.poll_seconds,
        settings.lookback_seconds,
        settings.batch_size,
        settings.max_consecutive_drain_cycles,
        settings.drain_yield_milliseconds,
    )
    try:
        return _run_loop(
            settings,
            engine,
            once,
            stop_event.is_set,
            mutation_lock=mutation_lock,
            logger=logger,
        )
    finally:
        control.stop()
        logger.info("engine_stopped")


def _run_loop(
    settings: Settings,
    engine: CorrelationEngine,
    once: bool,
    stopped: Callable[[], bool],
    *,
    mutation_lock: threading.RLock | None = None,
    sleeper: Callable[[float, Callable[[], bool]], None] | None = None,
    logger: logging.Logger | None = None,
) -> int:
    lock = mutation_lock or threading.RLock()
    sleep = sleeper or _interruptible_sleep
    active_logger = logger or logging.getLogger("fusion_correlation")
    backoff = 1
    consecutive_drain_cycles = 0
    while not stopped():
        try:
            with lock:
                results = engine.run_cycle()
            backoff = 1
            if once:
                return int(any(result.integrity.blocked for result in results))
            immediate_work = any(
                result.failed_inputs == 0
                and result.evaluated_inputs == settings.batch_size
                and result.backlog is not None
                and result.backlog.unevaluated_input_count > 0
                for result in results
            )
            if immediate_work:
                consecutive_drain_cycles += 1
                if consecutive_drain_cycles >= settings.max_consecutive_drain_cycles:
                    active_logger.info(
                        "backlog_drain_yield completed_cycles=%d yield_milliseconds=%d",
                        consecutive_drain_cycles,
                        settings.drain_yield_milliseconds,
                    )
                    sleep(settings.drain_yield_milliseconds / 1000.0, stopped)
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
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


def _json_default(value: object) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()  # type: ignore[union-attr]
    return str(value)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
