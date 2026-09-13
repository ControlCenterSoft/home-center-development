from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "6fc3c27577defb718df0d994aed55ebef9eb96da"
BASELINE_VERSION = "0.63.0"
CANDIDATE_VERSION = "0.64.0"


def _load_063_systemd_drill():
    path = ROOT / "tests/test_release_063_hosted_systemd_upgrade.py"
    spec = importlib.util.spec_from_file_location("hc_release_063_systemd_drill_for_064", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="real-systemd 0.63.0 -> 0.64.0 qualification runs once on Python 3.12",
)
def test_release_064_real_systemd_upgrade_health_and_rollback(tmp_path: Path) -> None:
    module = _load_063_systemd_drill()
    module._load_062_systemd_drill()._prepare_clean_systemd_sandbox()
    base = module._load_062_systemd_drill()._load_060_systemd_drill()
    base.BASE_SHA = BASE_SHA
    base.BASELINE_VERSION = BASELINE_VERSION
    base.CANDIDATE_VERSION = CANDIDATE_VERSION
    base.test_release_060_real_systemd_upgrade_health_and_rollback(tmp_path)
