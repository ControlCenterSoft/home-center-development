from __future__ import annotations

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "contracts/devices"
SCHEMAS = (
    "device-management-enrollment-post-condition-request.v1.schema.json",
    "device-management-enrollment-post-condition-result.v1.schema.json",
    "device-management-enrollment-post-condition-evidence.v1.schema.json",
    "device-management-enrollment-post-condition-verification-receipt.v1.schema.json",
    "device-management-enrollment-verifier-profile.v1.schema.json",
    "device-management-enrollment-verifier-contract-qualification-receipt.v1.schema.json",
)


def test_release_058_post_condition_contracts_are_valid_closed_draft_2020_12_schemas() -> None:
    identifiers: set[str] = set()

    for name in SCHEMAS:
        path = CONTRACT_DIR / name
        schema = json.loads(path.read_text(encoding="utf-8"))

        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False
        assert isinstance(schema.get("required"), list) and schema["required"]
        assert schema["$id"].endswith(f"/contracts/devices/{name}")
        assert schema["$id"] not in identifiers
        identifiers.add(schema["$id"])

        jsonschema.Draft202012Validator.check_schema(schema)

    assert len(identifiers) == len(SCHEMAS)
