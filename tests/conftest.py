from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Keep completed release-specific deployment drills historical.

    Exact Stable -> candidate deployment drills are release-identity specific.
    Once a newer release train owns the checkout, old candidate drills remain
    historical evidence and must not be rerun against a different source
    identity.  The active release train provides its own exact-bound drills.
    """

    current_version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    historical: set[str] = set()
    if current_version != "0.57.0":
        historical.update(
            {
                "test_release_057_hosted_upgrade_drill.py",
                "test_release_057_hosted_systemd_upgrade.py",
            }
        )
    if current_version != "0.58.0":
        historical.update(
            {
                "test_release_058_hosted_upgrade_drill.py",
                "test_release_058_hosted_systemd_upgrade.py",
            }
        )
    marker = pytest.mark.skip(
        reason="historical release-candidate deployment drill; current release train owns exact upgrade qualification"
    )
    for item in items:
        if item.path.name in historical:
            item.add_marker(marker)


@pytest.fixture(autouse=True)
def isolate_real_systemd_release_test(request: pytest.FixtureRequest):
    """Remove only empty state/config parents before the active systemd drill."""

    if request.node.name not in {
        "test_release_058_real_systemd_upgrade_health_and_rollback",
        "test_release_059_real_systemd_upgrade_health_and_rollback",
    }:
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
