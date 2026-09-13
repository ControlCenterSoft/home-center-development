from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QR_RUNTIME_MODULES = (
    "qr_onboarding.py",
    "qr_onboarding_validation.py",
    "qr_onboarding_runtime.py",
    "qr_onboarding_api.py",
    "qr_onboarding_audit.py",
    "qr_onboarding_effect_handoff.py",
    "qr_onboarding_effect_verification.py",
    "qr_onboarding_effect_admission.py",
    "qr_onboarding_effect_execution.py",
    "qr_onboarding_effect_source.py",
    "qr_onboarding_effect_worker.py",
    "qr_onboarding_effect_api.py",
)


def test_063_qr_train_adds_no_third_party_runtime_dependency() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert not project.get("dependencies")

    source_root = ROOT / "product/control-plane/src/home_center"
    external_imports: set[str] = set()
    for name in QR_RUNTIME_MODULES:
        tree = ast.parse((source_root / name).read_text(encoding="utf-8"), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".", 1)[0]
                    if top not in sys.stdlib_module_names:
                        external_imports.add(top)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                top = node.module.split(".", 1)[0]
                if top not in sys.stdlib_module_names:
                    external_imports.add(top)
    assert external_imports == set()


def test_063_candidate_does_not_claim_commercial_or_provider_clearance() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "Status: qualification candidate; not Public Stable." in notes
    assert "Concrete provider/HA/commercial-launch claims remain separate qualification boundaries" in notes
    assert "Technical Public Stable qualification must remain distinct" in notes
    assert "commercial launch clearance unclaimed" in notes


def test_063_qr_sources_do_not_embed_distribution_or_remote_service_clients() -> None:
    source_root = ROOT / "product/control-plane/src/home_center"
    combined = "\n".join((source_root / name).read_text(encoding="utf-8") for name in QR_RUNTIME_MODULES)
    for forbidden in (
        "import requests",
        "from requests",
        "import httpx",
        "from httpx",
        "import boto3",
        "from boto3",
        "import paramiko",
        "from paramiko",
    ):
        assert forbidden not in combined
