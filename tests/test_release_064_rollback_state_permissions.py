from __future__ import annotations

import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
STATE_RESTORE = re.compile(
    r"\\binstall\\s+-m\\s+(?P<mode>[0-7]{4})\\s+-o\\s+home-center\\s+-g\\s+home-center\\b"
)


@pytest.mark.parametrize(
    "relative",
    (
        "deploy/scripts/install-node.sh",
        "deploy/scripts/rollback-node.sh",
    ),
)
def test_release_064_recovery_restores_state_owner_only(relative: str) -> None:
    source = (ROOT / relative).read_text(encoding="utf-8")
    restore_lines = [
        line.strip()
        for line in source.splitlines()
        if "install -m" in line and "state.sqlite3" in line
    ]
    assert len(restore_lines) == 1, "recovery must have one auditable SQLite restore operation"
    match = STATE_RESTORE.search(restore_lines[0])
    assert match is not None
    assert match.group("mode") == "0600"
