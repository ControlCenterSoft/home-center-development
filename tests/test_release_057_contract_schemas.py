from __future__ import annotations

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "contracts/devices"
SCHEMAS = (
    "device-management-enrollment-adapter-cancel-result.v1.schema.json",
    "device-management-enrollment-adapter-start-request.v1.schema.json",
    "device-management-enrollment-adapter-start-result.v1.schema.json",
    "device-management-enrollment-cancel-receipt.v1.schema.json",
    "device-management-enrollment-execution-cancel-request.v1.schema.json",
    "device-management-enrollment-execution-plan-request.v1.schema.json",
    "device-management-enrollment-execution-plan.v1.schema.json",
    "device-management-enrollment-execution-receipt.v1.schema.json",
    "device-management-enrollment-execution-retry-request.v1.schema.json",
    "device-management-enrollment-execution-start-request.v1.schema.json",
)


def test_release_057_device_enrollment_contracts_are_valid_closed_draft_2020_12_schemas() -> None:
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
