from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "ff5ef0c7fb878ee28ff314cd5809c8cb0df2f726"
BASELINE_VERSION = "0.61.2"
CANDIDATE_VERSION = "0.62.0"


def _load_060_drill():
    path = ROOT / "tests/test_release_060_hosted_upgrade_drill.py"
    spec = importlib.util.spec_from_file_location("hc_release_060_upgrade_drill_for_062", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="0.61.2 -> 0.62.0 hosted upgrade/rollback drill runs once on Python 3.12",
)
def test_release_062_hosted_upgrade_from_0612_and_rollback(tmp_path: Path) -> None:
    module = _load_060_drill()
    module.BASE_SHA = BASE_SHA
    module.BASELINE_VERSION = BASELINE_VERSION
    module.CANDIDATE_VERSION = CANDIDATE_VERSION
    try:
        module.test_release_060_hosted_upgrade_from_059_and_rollback(tmp_path)
    finally:
        subprocess.run(
            [
                "sudo",
                "bash",
                "-ceu",
                "find /opt/home-center/releases -maxdepth 1 -type d -name '0.62.0-*' -exec rm -rf {} + 2>/dev/null || true",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
