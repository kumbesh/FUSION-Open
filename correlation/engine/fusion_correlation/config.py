"""Bounded environment configuration for the Fusion correlation engine."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum}, got {value}"
        )
    return value


@dataclass(frozen=True)
class Settings:
    """Correlation runtime settings with conservative lab defaults."""

    clickhouse_host: str
    clickhouse_port: int
    clickhouse_database: str
    clickhouse_user: str
    clickhouse_password: str
    rules_dir: Path
    mitre_mapping_path: Path
    poll_seconds: int
    lookback_seconds: int
    batch_size: int
    context_limit: int
    max_consecutive_drain_cycles: int
    drain_yield_milliseconds: int
    engine_id: str
    control_socket: Path
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        engine_id = os.getenv(
            "FUSION_CORRELATION_ENGINE_ID", "fusion-correlation-default"
        ).strip()
        if not engine_id or len(engine_id) > 128:
            raise ValueError(
                "FUSION_CORRELATION_ENGINE_ID must contain 1-128 characters"
            )
        return cls(
            clickhouse_host=os.getenv(
                "FUSION_CORRELATION_CLICKHOUSE_HOST", "clickhouse"
            ),
            clickhouse_port=_bounded_int(
                "FUSION_CORRELATION_CLICKHOUSE_PORT", 8123, 1, 65535
            ),
            clickhouse_database=os.getenv(
                "FUSION_CORRELATION_CLICKHOUSE_DATABASE", "fusion"
            ),
            clickhouse_user=os.getenv("CLICKHOUSE_USER", "fusion"),
            clickhouse_password=os.getenv(
                "CLICKHOUSE_PASSWORD", "fusion-local-only"
            ),
            rules_dir=Path(
                os.getenv("FUSION_CORRELATION_RULES_DIR", "/rules")
            ),
            mitre_mapping_path=Path(
                os.getenv(
                    "FUSION_CORRELATION_MITRE_MAPPING_PATH",
                    "/mappings/mitre-technique-tactics.yml",
                )
            ),
            poll_seconds=_bounded_int(
                "FUSION_CORRELATION_POLL_SECONDS", 10, 1, 3600
            ),
            lookback_seconds=_bounded_int(
                "FUSION_CORRELATION_LOOKBACK_SECONDS", 3600, 60, 604800
            ),
            batch_size=_bounded_int(
                "FUSION_CORRELATION_BATCH_SIZE", 1000, 1, 10000
            ),
            context_limit=_bounded_int(
                "FUSION_CORRELATION_CONTEXT_LIMIT", 10000, 10, 100000
            ),
            max_consecutive_drain_cycles=_bounded_int(
                "FUSION_CORRELATION_MAX_DRAIN_CYCLES", 10, 1, 1000
            ),
            drain_yield_milliseconds=_bounded_int(
                "FUSION_CORRELATION_DRAIN_YIELD_MS", 100, 1, 5000
            ),
            engine_id=engine_id,
            control_socket=Path(
                os.getenv(
                    "FUSION_CORRELATION_CONTROL_SOCKET",
                    "/run/fusion-correlation/control.sock",
                )
            ),
            log_level=os.getenv(
                "FUSION_CORRELATION_LOG_LEVEL", "INFO"
            ).upper(),
        )
