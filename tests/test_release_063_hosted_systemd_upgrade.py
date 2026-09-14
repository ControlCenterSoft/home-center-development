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


def _load_062_systemd_drill():
    path = ROOT / "tests/test_release_062_hosted_systemd_upgrade.py"
    spec = importlib.util.spec_from_file_location("hc_release_062_systemd_drill_for_063", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_published_063_systemd_drill(tmp_path: Path) -> None:
    """Re-run the immutable 0.63 systemd drill from its published source tag."""

    published_root = tmp_path / "published-063-systemd-source"
    run_root = tmp_path / "published-063-systemd-run"
    run_root.mkdir()
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(published_root), PUBLISHED_REF],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    try:
        path = published_root / "tests/test_release_063_hosted_systemd_upgrade.py"
        spec = importlib.util.spec_from_file_location("hc_published_063_systemd_upgrade_drill", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.test_release_063_real_systemd_upgrade_health_and_rollback(run_root)
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
    reason="real-systemd 0.62.1 -> 0.63.0 qualification runs once on Python 3.12",
)
def test_release_063_real_systemd_upgrade_health_and_rollback(tmp_path: Path) -> None:
    current_version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    if current_version != CANDIDATE_VERSION:
        _run_published_063_systemd_drill(tmp_path)
        return

    module = _load_062_systemd_drill()
    module._prepare_clean_systemd_sandbox()
    base = module._load_060_systemd_drill()
    base.BASE_SHA = BASE_SHA
    base.BASELINE_VERSION = BASELINE_VERSION
    base.CANDIDATE_VERSION = CANDIDATE_VERSION
    base.test_release_060_real_systemd_upgrade_health_and_rollback(tmp_path)
