"""Offline validation command for Fusion correlation rules."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

import yaml

from .compiler import CorrelationCompiler, validate_rule_directory
from .fixtures import validate_fixture_coverage
from .models import RuleValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate strict fusion-correlation/v1 YAML without network or database access."
    )
    parser.add_argument(
        "rules_dir",
        nargs="?",
        type=Path,
        default=Path("correlation/rules"),
        help="directory containing correlation YAML rules",
    )
    parser.add_argument(
        "--mitre-mapping",
        type=Path,
        default=None,
        help="versioned technique-to-tactic mapping (repository default when omitted)",
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="fail unless exactly this many rules are present",
    )
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=None,
        help="optional directory whose positive/negative fixture coverage must be exact",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="emit bounded machine-readable validation output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    errors: list[str] = []
    rules = ()
    total = 0
    try:
        compiler = CorrelationCompiler(args.mitre_mapping)
        result = validate_rule_directory(args.rules_dir, compiler)
        total = result.total
        rules = result.rules
        errors.extend(result.errors)
        if args.fixtures_dir is not None and not result.errors:
            errors.extend(validate_fixture_coverage(args.fixtures_dir, rules))
    except (RuleValidationError, yaml.YAMLError, UnicodeError, OSError) as exc:
        errors.append(str(exc))

    if args.expected_count is not None:
        if args.expected_count < 0:
            errors.append("--expected-count must not be negative")
        elif total != args.expected_count:
            errors.append(
                f"expected exactly {args.expected_count} rules but found {total}"
            )

    payload = {
        "schema": "fusion-correlation-validation/v1",
        "rules_dir": str(args.rules_dir),
        "total": total,
        "valid": len(rules),
        "invalid": len(errors),
        "rules": [
            {
                "id": rule.rule_id,
                "version": rule.version,
                "condition_type": rule.condition_kind,
                "scope_fingerprint": rule.scope_fingerprint,
            }
            for rule in rules
        ],
        "errors": errors,
    }
    if args.json_output:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    else:
        for rule in rules:
            print(
                "PASS "
                f"{rule.rule_id} v{rule.version} "
                f"{rule.condition_kind} {rule.scope_fingerprint}"
            )
        for error in errors:
            print(f"FAIL {error}")
        print(
            f"Correlation rules: total={total} valid={len(rules)} invalid={len(errors)}"
        )
    return 1 if errors else 0


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    entrypoint()
