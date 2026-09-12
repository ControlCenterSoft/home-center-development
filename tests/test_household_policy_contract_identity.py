from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "household"
PREFIX = "https://control-center.pro/schemas/home-center/"


def test_policy_contracts_use_canonical_public_schema_identity() -> None:
    paths = sorted(CONTRACTS.glob("household-policy-*.schema.json"))
    assert paths
    for path in paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        schema_id = schema.get("$id")
        assert isinstance(schema_id, str) and schema_id.startswith(PREFIX), path.name
        assert ".example" not in schema_id, path.name
        assert schema_id.endswith(path.name), path.name
