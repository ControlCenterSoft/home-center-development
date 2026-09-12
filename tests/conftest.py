from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Keep completed release-specific deployment drills historical.

    The 0.57 hosted upgrade drills qualify the exact 0.56 -> 0.57 candidate and
    intentionally assert that the checked-out source itself is 0.57.0.  Once a
    newer exact release identity is under qualification, rerunning those old
    candidate drills against the new source would be a false release check.
    Their historical contracts remain covered by their source/tests; the active
    release train owns the current Stable -> candidate deployment drills.
    """

    current_version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    if current_version == "0.57.0":
        return
    historical_057 = {
        "test_release_057_hosted_upgrade_drill.py",
        "test_release_057_hosted_systemd_upgrade.py",
    }
    marker = pytest.mark.skip(reason="historical 0.57 candidate deployment drill; current release train owns upgrade qualification")
    for item in items:
        if item.path.name in historical_057:
            item.add_marker(marker)


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
