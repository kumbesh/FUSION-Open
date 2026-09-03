"""Environment-backed configuration with bounded defaults."""

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
        raise ValueError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


@dataclass(frozen=True)
class Settings:
    clickhouse_host: str
    clickhouse_port: int
    clickhouse_database: str
    clickhouse_user: str
    clickhouse_password: str
    rules_dir: Path
    mapping_path: Path
    mitre_mapping_path: Path
    poll_seconds: int
    lookback_seconds: int
    batch_size: int
    engine_id: str
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            clickhouse_host=os.getenv("FUSION_DETECTION_CLICKHOUSE_HOST", "clickhouse"),
            clickhouse_port=_bounded_int("FUSION_DETECTION_CLICKHOUSE_PORT", 8123, 1, 65535),
            clickhouse_database=os.getenv("FUSION_DETECTION_CLICKHOUSE_DATABASE", "fusion"),
            clickhouse_user=os.getenv("CLICKHOUSE_USER", "fusion"),
            clickhouse_password=os.getenv("CLICKHOUSE_PASSWORD", "fusion-local-only"),
            rules_dir=Path(os.getenv("FUSION_DETECTION_RULES_DIR", "/rules")),
            mapping_path=Path(os.getenv("FUSION_DETECTION_MAPPING_PATH", "/mappings/sigma_fields.yml")),
            mitre_mapping_path=Path(os.getenv("FUSION_DETECTION_MITRE_MAPPING_PATH", "/mappings/mitre.yml")),
            poll_seconds=_bounded_int("FUSION_DETECTION_POLL_SECONDS", 10, 1, 3600),
            lookback_seconds=_bounded_int("FUSION_DETECTION_LOOKBACK_SECONDS", 120, 0, 86400),
            batch_size=_bounded_int("FUSION_DETECTION_BATCH_SIZE", 1000, 1, 10000),
            engine_id=os.getenv("FUSION_DETECTION_ENGINE_ID", "fusion-default"),
            log_level=os.getenv("FUSION_DETECTION_LOG_LEVEL", "INFO").upper(),
        )
