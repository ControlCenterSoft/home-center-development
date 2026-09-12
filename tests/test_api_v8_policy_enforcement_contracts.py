from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest


CONTRACTS = Path(__file__).parents[1] / "contracts"


@pytest.mark.parametrize(
    ("filename", "sample"),
    [
        (
            "household/household-policy-enforcement-plan-request.v1.schema.json",
            {
                "schema": "home-center.household-policy-enforcement-plan-request.v1",
                "member_id": "member-a",
                "backend_id": "provider-a",
            },
        ),
        (
            "household/household-policy-enforcement-confirm-request.v1.schema.json",
            {
                "schema": "home-center.household-policy-enforcement-confirm-request.v1",
                "plan_id": "hpep-0123456789abcdef01234567",
                "confirmed": True,
            },
        ),
        (
            "household/household-policy-enforcement-execute-request.v1.schema.json",
            {
                "schema": "home-center.household-policy-enforcement-execute-request.v1",
                "plan_id": "hpep-0123456789abcdef01234567",
            },
        ),
    ],
)
def test_enforcement_http_request_contracts_are_closed_and_accept_exact_samples(
    filename: str,
    sample: dict[str, object],
) -> None:
    schema = json.loads((CONTRACTS / filename).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(sample)
    assert schema["additionalProperties"] is False

    tampered = dict(sample)
    tampered["unexpected"] = "rejected"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(tampered)


def test_enforcement_openapi_is_bounded_to_three_explicit_operations() -> None:
    path = CONTRACTS / "openapi/home-center-household-policy-enforcement.v1.openapi.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["openapi"] == "3.1.0"
    assert document["info"]["version"] == "0.59.0-development"
    assert set(document["paths"]) == {
        "/api/v1/household/policy/enforcement/plan",
        "/api/v1/household/policy/enforcement/confirm",
        "/api/v1/household/policy/enforcement/execute",
    }

    confirm = document["paths"]["/api/v1/household/policy/enforcement/confirm"]["post"]
    execute = document["paths"]["/api/v1/household/policy/enforcement/execute"]["post"]
    assert confirm["parameters"][0]["name"] == "Idempotency-Key"
    assert confirm["parameters"][0]["required"] is True
    assert execute["parameters"][0]["name"] == "Idempotency-Key"
    assert execute["parameters"][0]["required"] is True
