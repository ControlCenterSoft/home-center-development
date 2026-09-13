from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Keep completed candidate-only deployment drills historical.

    A release-specific hosted upgrade drill intentionally asserts the checked-out
    candidate identity. Once a newer release train owns Stable -> candidate
    qualification, the completed older drill must not be rerun against the new
    source identity. Its source/contract coverage remains in the suite while the
    current release owns the live deployment rehearsal.
    """

    current_version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    historical: dict[str, set[str]] = {
        "0.57.0": {
            "test_release_057_hosted_upgrade_drill.py",
            "test_release_057_hosted_systemd_upgrade.py",
        },
        "0.58.0": {
            "test_release_058_hosted_upgrade_drill.py",
            "test_release_058_hosted_systemd_upgrade.py",
        },
        "0.59.0": {
            "test_release_059_hosted_upgrade_drill.py",
            "test_release_059_hosted_systemd_upgrade.py",
        },
    }
    for release, files in historical.items():
        if current_version == release:
            continue
        marker = pytest.mark.skip(
            reason=f"historical {release} candidate deployment drill; current release train owns upgrade qualification"
        )
        for item in items:
            if item.path.name in files:
                item.add_marker(marker)


@pytest.fixture(autouse=True)
def isolate_real_systemd_release_test(request: pytest.FixtureRequest):
    """Remove only empty parents left by the preceding shim deployment drill.

    Real-systemd qualification requires a clean node boundary. Never remove
    non-empty Home Center state: any unexpected content is a hard test failure.
    """

    if request.node.name not in {
        "test_release_058_real_systemd_upgrade_health_and_rollback",
        "test_release_059_real_systemd_upgrade_health_and_rollback",
        "test_release_060_real_systemd_upgrade_health_and_rollback",
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
