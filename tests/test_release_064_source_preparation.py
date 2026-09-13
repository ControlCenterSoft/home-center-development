from __future__ import annotations

import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.64.0"

RUNTIME_FILES = (
    "safe_auto_repair.py",
    "safe_auto_repair_history.py",
    "safe_auto_repair_migration.py",
    "safe_auto_repair_admission.py",
    "safe_auto_repair_job.py",
    "safe_auto_repair_job_store.py",
    "safe_auto_repair_adapter.py",
    "safe_auto_repair_verification.py",
    "safe_auto_repair_worker.py",
    "safe_auto_repair_ui.py",
)

CONTRACT_FILES = (
    "safe-auto-repair-recommendation.v1.schema.json",
    "safe-auto-repair-admission.v1.schema.json",
    "safe-auto-repair-job.v1.schema.json",
    "safe-auto-repair-adapter-request.v1.schema.json",
    "safe-auto-repair-adapter-result.v1.schema.json",
    "safe-auto-repair-post-condition.v1.schema.json",
    "safe-auto-repair-verification-decision.v1.schema.json",
    "safe-auto-repair-ui.v1.schema.json",
)


def test_release_064_source_identity_is_exact_everywhere() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == VERSION
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == VERSION

    runtime_init = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(
        encoding="utf-8"
    )
    assert f'__version__ = "{VERSION}"' in runtime_init

    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert f'<small id="version">{VERSION}</small>' in html
    assert '<small id="version">0.63.0</small>' not in html


def test_release_064_source_contains_the_bounded_repair_chain() -> None:
    runtime = ROOT / "product/control-plane/src/home_center"
    for name in RUNTIME_FILES:
        assert (runtime / name).is_file(), name


def test_release_064_contracts_remain_closed() -> None:
    contracts = ROOT / "contracts/automation"
    for name in CONTRACT_FILES:
        payload = json.loads((contracts / name).read_text(encoding="utf-8"))
        assert payload["additionalProperties"] is False, name


def test_release_064_notes_preserve_candidate_and_authority_boundaries() -> None:
    notes = (ROOT / "docs/releases/0.64.0.md").read_text(encoding="utf-8")
    assert "Status: source preparation only; not Release Candidate and not Public Stable." in notes
    assert "Authoritative Public Stable baseline for this work is Home Center 0.63.0." in notes
    assert "0.63.0 → 0.64.0" in notes
    assert "the user-set administrator password" in notes
    assert "eligible_for_auto_repair=true` is evidence only" in notes
    assert "does not claim provider qualification, HA capability or commercial-launch/legal clearance" in notes
