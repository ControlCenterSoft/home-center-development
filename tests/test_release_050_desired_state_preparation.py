from __future__ import annotations

from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_artifact_requires_household_desired_state_runtime() -> None:
    assert "home_center/household_desired_state_0500.py" in REQUIRED_MEMBERS


def test_release_notes_keep_050_non_authorizing() -> None:
    notes = (ROOT / "docs" / "releases" / "0.50.0.md").read_text(encoding="utf-8")

    assert "planning-only" in notes
    assert "mutation_authorized" in notes
    assert "provider_execution_enabled" in notes
    assert "production_mutation_enabled" in notes
    assert "не" in notes.lower()


def test_desired_state_runtime_has_no_provider_or_process_imports() -> None:
    source = (
        ROOT
        / "product"
        / "control-plane"
        / "src"
        / "home_center"
        / "household_desired_state_0500.py"
    ).read_text(encoding="utf-8")

    forbidden = (
        "import os",
        "import socket",
        "import subprocess",
        "import urllib",
        "import requests",
        "import httpx",
        "from pathlib",
        "from socket",
        "from subprocess",
    )
    for marker in forbidden:
        assert marker not in source

    assert "provider_execution_enabled" in source
    assert "production_mutation_enabled" in source
