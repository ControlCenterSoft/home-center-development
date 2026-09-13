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


def _load_058_drill():
    path = ROOT / "tests/test_release_058_hosted_upgrade_drill.py"
    spec = importlib.util.spec_from_file_location("hc_release_058_hosted_upgrade", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H058 = _load_058_drill()


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="0.58 -> 0.59 hosted upgrade/rollback drill runs once on the Python 3.12 leg",
)
def test_release_059_hosted_upgrade_from_058_and_rollback(tmp_path: Path) -> None:
    """Reuse the proven node-upgrade harness with exact 0.58/0.59 identities.

    Only the version/revision inputs are rebound.  The harness still builds the
    baseline and candidate from detached exact source trees and exercises the
    real install-node/rollback-node scripts without rewriting candidate source.
    """

    old = (H058.BASE_SHA, H058.BASELINE_VERSION, H058.CANDIDATE_VERSION)
    H058.BASE_SHA = BASE_SHA
    H058.BASELINE_VERSION = BASELINE_VERSION
    H058.CANDIDATE_VERSION = CANDIDATE_VERSION
    try:
        H058.test_release_058_hosted_upgrade_from_057_and_rollback(tmp_path)
    finally:
        H058.BASE_SHA, H058.BASELINE_VERSION, H058.CANDIDATE_VERSION = old
        # The historical harness cleanup names the old candidate version.
        # Remove only release directories created by this exact 0.59 rehearsal.
        H058._sudo("find /opt/home-center/releases -maxdepth 1 -type d -name '0.59.0-*' -exec rm -rf {} + 2>/dev/null || true")
