from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "8adc370a947c520d4bbb9f0e020cb03741e2e46c"
BASELINE_VERSION = "0.62.1"
CANDIDATE_VERSION = "0.63.0"
PUBLISHED_REF = "v0.63.0"


def _load_060_drill():
    path = ROOT / "tests/test_release_060_hosted_upgrade_drill.py"
    spec = importlib.util.spec_from_file_location("hc_release_060_upgrade_drill_for_063", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_published_063_drill(tmp_path: Path) -> None:
    """Re-run the immutable 0.63 drill from its published source tag on newer lines."""

    published_root = tmp_path / "published-063-source"
    run_root = tmp_path / "published-063-run"
    run_root.mkdir()
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(published_root), PUBLISHED_REF],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    try:
        path = published_root / "tests/test_release_063_hosted_upgrade_drill.py"
        spec = importlib.util.spec_from_file_location("hc_published_063_hosted_upgrade_drill", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.test_release_063_hosted_upgrade_from_0621_and_rollback(run_root)
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(published_root)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "worktree", "prune"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="0.62.1 -> 0.63.0 hosted upgrade/rollback drill runs once on Python 3.12",
)
def test_release_063_hosted_upgrade_from_0621_and_rollback(tmp_path: Path) -> None:
    current_version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    if current_version != CANDIDATE_VERSION:
        _run_published_063_drill(tmp_path)
        return

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
                "find /opt/home-center/releases -maxdepth 1 -type d -name '0.63.0-*' -exec rm -rf {} + 2>/dev/null || true",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
