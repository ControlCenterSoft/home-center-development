from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "94ceae8a3bac2c53beade4c258dc68767d1c04fb"
BASELINE_VERSION = "0.58.0"
CANDIDATE_VERSION = "0.59.0"


def _load_058_systemd_drill():
    path = ROOT / "tests/test_release_058_hosted_systemd_upgrade.py"
    spec = importlib.util.spec_from_file_location("hc_release_058_systemd_drill", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="real systemd 0.58 -> 0.59 qualification runs once on the hosted Python 3.12 leg",
)
def test_release_059_real_systemd_upgrade_health_and_rollback(tmp_path: Path) -> None:
    """Run the proven real-systemd drill against exact 0.58 and exact 0.59.

    The existing test owns service/readiness, credential/config/state preservation
    and rollback assertions; this release layer only binds its immutable source
    baseline and candidate identities.
    """

    module = _load_058_systemd_drill()
    module.BASE_SHA = BASE_SHA
    module.BASELINE_VERSION = BASELINE_VERSION
    module.CANDIDATE_VERSION = CANDIDATE_VERSION
    module.test_release_058_real_systemd_upgrade_health_and_rollback(tmp_path)
