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
CANDIDATE_VERSION = "0.62.1"


def _load_060_systemd_drill():
    path = ROOT / "tests/test_release_060_hosted_systemd_upgrade.py"
    spec = importlib.util.spec_from_file_location("hc_release_060_systemd_drill_for_062", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prepare_clean_systemd_sandbox() -> None:
    """Remove only Home Center state left by earlier tests on the ephemeral GHA VM."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("systemd sandbox cleanup is restricted to GitHub Actions")
    subprocess.run(
        ["sudo", "bash", "-ceu", """
systemctl disable --now home-center-backup.timer >/dev/null 2>&1 || true
systemctl disable --now home-center.service >/dev/null 2>&1 || true
systemctl stop home-center-backup.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/home-center.service /etc/systemd/system/home-center-backup.service /etc/systemd/system/home-center-backup.timer
systemctl daemon-reload || true
rm -rf /opt/home-center /etc/home-center /var/lib/home-center /var/lib/home-center-deploy
rm -rf /var/backups/home-center /var/backups/home-center-deploy /run/home-center-locks
"""],
        text=True,
        capture_output=True,
        check=True,
    )


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="real-systemd 0.61.2 -> 0.62.1 qualification runs once on Python 3.12",
)
def test_release_062_real_systemd_upgrade_health_and_rollback(tmp_path: Path) -> None:
    _prepare_clean_systemd_sandbox()
    module = _load_060_systemd_drill()
    module.BASE_SHA = BASE_SHA
    module.BASELINE_VERSION = BASELINE_VERSION
    module.CANDIDATE_VERSION = CANDIDATE_VERSION
    module.test_release_060_real_systemd_upgrade_health_and_rollback(tmp_path)
