from __future__ import annotations

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "contracts/devices"
SCHEMAS = (
    "device-management-failed-enrollment-cleanup-execute-request.v1.schema.json",
    "device-management-failed-enrollment-cleanup-execution-receipt.v1.schema.json",
)


def test_release_058_cleanup_execution_contracts_are_closed_draft_2020_12_schemas() -> None:
    identifiers: set[str] = set()
    for name in SCHEMAS:
        schema = json.loads((CONTRACT_DIR / name).read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False
        assert isinstance(schema.get("required"), list) and schema["required"]
        assert schema["$id"].endswith(f"/contracts/devices/{name}")
        assert schema["$id"] not in identifiers
        identifiers.add(schema["$id"])
        jsonschema.Draft202012Validator.check_schema(schema)
    assert len(identifiers) == len(SCHEMAS)
