from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_release_058_real_systemd_test(request: pytest.FixtureRequest):
    """Remove only empty directories left by the preceding 0.58 shim drill.

    The hosted 0.57 -> 0.58 shim qualification intentionally leaves the parent
    configuration/state directories in place after deleting its files.  The
    real-systemd qualification requires a clean node boundary and must not
    accept or delete non-empty state, so normalize only those known-empty
    parents immediately before that one test.
    """

    if request.node.name != "test_release_058_real_systemd_upgrade_health_and_rollback":
        yield
        return

    for raw in ("/etc/home-center", "/var/lib/home-center"):
        path = Path(raw)
        if not path.exists():
            continue
        if not path.is_dir():
            pytest.fail(f"unexpected non-directory Home Center path: {path}")
        probe = subprocess.run(
            ["sudo", "find", raw, "-mindepth", "1", "-maxdepth", "1", "-print", "-quit"],
            text=True,
            capture_output=True,
            check=True,
        )
        if probe.stdout.strip():
            pytest.fail(f"refusing to remove non-empty Home Center path: {path}: {probe.stdout.strip()}")
        subprocess.run(["sudo", "rmdir", raw], check=True)

    yield
