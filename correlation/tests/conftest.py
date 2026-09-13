from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ENGINE_ROOT = REPOSITORY_ROOT / "correlation" / "engine"
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))

from fusion_correlation.compiler import CorrelationCompiler  # noqa: E402


@pytest.fixture
def repository_root() -> Path:
    return REPOSITORY_ROOT


@pytest.fixture
def rules_dir(repository_root: Path) -> Path:
    return repository_root / "correlation" / "rules"


@pytest.fixture
def correlation_fixtures_dir(repository_root: Path) -> Path:
    return repository_root / "correlation" / "fixtures"


@pytest.fixture
def mitre_mapping_path(repository_root: Path) -> Path:
    return repository_root / "correlation" / "mappings" / "mitre-technique-tactics.yml"


@pytest.fixture
def compiler(mitre_mapping_path: Path) -> CorrelationCompiler:
    return CorrelationCompiler(mitre_mapping_path)
