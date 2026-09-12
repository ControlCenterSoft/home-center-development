from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    POLICY_RECOVERY_REQUEST_SCHEMA,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "household"


def _validator(name: str) -> jsonschema.Draft202012Validator:
    schema = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_policy_request_contracts_match_runtime_schema_identities() -> None:
    cases = (
        (
            "household-policy-plan-request.v1.schema.json",
            POLICY_PLAN_REQUEST_SCHEMA,
            {"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": "member-parent"},
        ),
        (
            "household-policy-confirm-request.v1.schema.json",
            POLICY_CONFIRM_REQUEST_SCHEMA,
            {"schema": POLICY_CONFIRM_REQUEST_SCHEMA, "proposal_id": "hpc-" + "1" * 24, "confirmed": True},
        ),
        (
            "household-policy-recovery-request.v1.schema.json",
            POLICY_RECOVERY_REQUEST_SCHEMA,
            {"schema": POLICY_RECOVERY_REQUEST_SCHEMA, "proposal_id": "hpc-" + "2" * 24},
        ),
    )
    for name, schema_identity, payload in cases:
        validator = _validator(name)
        assert validator.schema["properties"]["schema"]["const"] == schema_identity
        validator.validate(payload)


def test_policy_request_contracts_are_closed() -> None:
    cases = (
        (
            "household-policy-plan-request.v1.schema.json",
            {"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": "member-parent", "unexpected": True},
        ),
        (
            "household-policy-confirm-request.v1.schema.json",
            {"schema": POLICY_CONFIRM_REQUEST_SCHEMA, "proposal_id": "hpc-" + "1" * 24, "confirmed": True, "unexpected": True},
        ),
        (
            "household-policy-recovery-request.v1.schema.json",
            {"schema": POLICY_RECOVERY_REQUEST_SCHEMA, "proposal_id": "hpc-" + "2" * 24, "unexpected": True},
        ),
    )
    for name, payload in cases:
        with pytest.raises(jsonschema.ValidationError):
            _validator(name).validate(payload)


def test_policy_confirmation_contract_requires_explicit_true() -> None:
    validator = _validator("household-policy-confirm-request.v1.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(
            {
                "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
                "proposal_id": "hpc-" + "3" * 24,
                "confirmed": False,
            }
        )
