from __future__ import annotations

import json
import tomllib
from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.59.0"


def test_release_059_exact_identity_is_consistent() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == VERSION
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == VERSION
    runtime_init = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{VERSION}"' in runtime_init
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert f'<small id="version">{VERSION}</small>' in html
    assert '<script src="/static/policy-effective-state.js"></script>' in html


def test_release_059_notes_are_official_bounded_and_truthful() -> None:
    notes = (ROOT / "docs/releases/0.59.0.md").read_text(encoding="utf-8")
    assert notes.startswith("# Home Center 0.59.0\n\nStatus: official release.")
    assert "`single-node-core`" in notes
    assert "multi-node HA / automatic failover" in notes
    assert "concrete production backend/provider execution" in notes
    assert "commercial launch clearance" in notes
    assert "backend acceptance не означает enforcement success" in notes
    assert "Automatic backend retry" in notes
    assert "0.58.0 → 0.59.0" in notes


def test_release_059_policy_runtime_is_required_in_reproducible_wheel() -> None:
    assert {
        "home_center/api_v6.py",
        "home_center/api_v7.py",
        "home_center/api_v8.py",
        "home_center/household_policy_api.py",
        "home_center/household_policy_composer.py",
        "home_center/household_policy_effective_state.py",
        "home_center/household_policy_enforcement_admission.py",
        "home_center/household_policy_enforcement_qualification_binding.py",
        "home_center/household_policy_enforcement_reconciliation_snapshot.py",
        "home_center/household_policy_enforcement_runtime.py",
        "home_center/household_policy_reconciliation.py",
        "home_center/household_policy_reconciliation_api_runtime.py",
        "home_center/household_policy_reconciliation_recovery.py",
        "home_center/household_policy_reconciliation_runtime.py",
        "home_center/household_policy_runtime.py",
        "home_center/household_policy_verification_state.py",
        "home_center/household_policy_verification_transition.py",
        "home_center/policy_backend_qualification.py",
        "home_center/release_promotion_gate.py",
        "home_center/target_node_qualification.py",
        "home_center/technical_stable_profile.py",
    } <= REQUIRED_MEMBERS


def test_release_059_enforcement_openapi_preserves_fail_closed_authority() -> None:
    document = json.loads(
        (ROOT / "contracts/openapi/home-center-household-policy-enforcement.v1.openapi.json").read_text(
            encoding="utf-8"
        )
    )
    assert document["openapi"] == "3.1.0"
    paths = document["paths"]
    assert {
        "/api/v1/household/policy/enforcement/plan",
        "/api/v1/household/policy/enforcement/confirm",
        "/api/v1/household/policy/enforcement/execute",
    } <= set(paths)
    serialized = json.dumps(document, sort_keys=True)
    assert "external_publication_authorized" in serialized
    assert "automatic_retry_authorized" in serialized


def test_release_059_upgrade_drills_are_exact_and_do_not_rewrite_identity() -> None:
    for name in (
        "test_release_059_hosted_upgrade_drill.py",
        "test_release_059_hosted_systemd_upgrade.py",
    ):
        source = (ROOT / "tests" / name).read_text(encoding="utf-8")
        assert "BASELINE_VERSION = \"0.58.0\"" in source
        assert "CANDIDATE_VERSION = \"0.59.0\"" in source
        assert "94ceae8a3bac2c53beade4c258dc68767d1c04fb" in source
        assert "SOURCE_VERSION" not in source
        assert "replace(source_marker" not in source
