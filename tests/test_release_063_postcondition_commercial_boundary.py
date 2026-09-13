from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "product/control-plane/src/home_center/qr_onboarding_effect_post_condition.py"


def test_063_postcondition_adds_no_external_runtime_dependency() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"), filename=MODULE.name)
    external: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0]
                if top not in sys.stdlib_module_names:
                    external.add(top)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top = node.module.split(".", 1)[0]
            if top not in sys.stdlib_module_names:
                external.add(top)
    assert external == set()


def test_063_postcondition_keeps_commercial_provider_ha_claims_unqualified() -> None:
    notes = (ROOT / "docs/releases/0.63.0.md").read_text(encoding="utf-8")
    assert "not Release Candidate and not Public Stable" in notes
    assert "Concrete provider/HA/commercial-launch claims remain separate qualification boundaries" in notes
    assert "Technical Public Stable qualification must remain distinct" in notes


def test_063_postcondition_has_no_remote_service_client_import() -> None:
    source = MODULE.read_text(encoding="utf-8")
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
        assert forbidden not in source
