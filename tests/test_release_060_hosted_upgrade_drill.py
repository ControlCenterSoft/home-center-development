from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "1b54a0e72ca8fead4527946f95498dde41ee553f"
BASELINE_VERSION = "0.59.0"
CANDIDATE_VERSION = "0.60.0"


def _load_059_drill():
    path = ROOT / "tests/test_release_059_hosted_upgrade_drill.py"
    spec = importlib.util.spec_from_file_location("hc_release_059_upgrade_drill", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="0.59 -> 0.60 hosted upgrade/rollback drill runs once on the Python 3.12 leg",
)
def test_release_060_hosted_upgrade_from_059_and_rollback(tmp_path: Path) -> None:
    """Reuse the proven node drill with exact 0.59 Stable and exact 0.60 HEAD."""

    module = _load_059_drill()
    module.BASE_SHA = BASE_SHA
    module.BASELINE_VERSION = BASELINE_VERSION
    module.CANDIDATE_VERSION = CANDIDATE_VERSION
    try:
        module.test_release_059_hosted_upgrade_from_058_and_rollback(tmp_path)
    finally:
        subprocess.run(
            [
                "sudo",
                "bash",
                "-ceu",
                "find /opt/home-center/releases -maxdepth 1 -type d -name '0.60.0-*' -exec rm -rf {} + 2>/dev/null || true",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
