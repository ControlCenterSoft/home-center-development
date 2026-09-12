from __future__ import annotations

import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/household"
SCHEMAS = (
    "household-policy-change-plan-request.v1.schema.json",
    "household-policy-change-plan.v1.schema.json",
    "household-policy-change-confirm-request.v1.schema.json",
    "household-policy-desired-state.v1.schema.json",
)


def test_release_059_policy_contracts_are_closed_draft_2020_12_schemas() -> None:
    identifiers: set[str] = set()
    for name in SCHEMAS:
        schema = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False
        assert isinstance(schema.get("required"), list) and schema["required"]
        assert schema["$id"].endswith(f"/contracts/household/{name}")
        assert schema["$id"] not in identifiers
        identifiers.add(schema["$id"])
        jsonschema.Draft202012Validator.check_schema(schema)
    assert len(identifiers) == len(SCHEMAS)
