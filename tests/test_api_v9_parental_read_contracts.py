from __future__ import annotations

import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def _json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_parental_read_openapi_exposes_only_read_and_preview_operations() -> None:
    document = _json("contracts/openapi/home-center-parental-internet-read.v1.openapi.json")
    assert document["openapi"] == "3.1.0"
    assert document["info"]["version"] == "0.60.0-development"
    assert set(document["paths"]) == {
        "/api/v1/household/parental-internet/desired",
        "/api/v1/household/parental-internet/decision-preview",
    }
    assert set(document["paths"]["/api/v1/household/parental-internet/desired"]) == {"get"}
    assert set(document["paths"]["/api/v1/household/parental-internet/decision-preview"]) == {"post"}
    serialized = json.dumps(document, sort_keys=True)
    assert "preview_only" not in serialized or "preview" in serialized
    assert "/plan" not in serialized
    assert "/confirm" not in serialized
    assert "/execute" not in serialized


def test_preview_request_contract_cannot_carry_policy_or_authority_material() -> None:
    schema = _json("contracts/household/parental-internet-decision-preview-request.v1.schema.json")
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    for forbidden in (
        "policy_id",
        "policy_sha256",
        "rule_source_id",
        "rule_source_version",
        "rule_source_sha256",
        "backend_id",
        "provider_id",
        "enforcement_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert forbidden not in properties


def test_preview_and_saved_policy_results_hard_close_mutation_authority() -> None:
    preview = _json("contracts/household/parental-internet-decision-preview-result.v1.schema.json")
    assert preview["properties"]["preview_only"] == {"const": True}
    assert preview["properties"]["enforcement_verified"] == {"const": False}
    assert preview["properties"]["provider_execution_authorized"] == {"const": False}
    assert preview["properties"]["infrastructure_mutation_authorized"] == {"const": False}
    assert preview["properties"]["external_publication_authorized"] == {"const": False}

    desired = _json("contracts/household/parental-internet-policy-desired-read.v1.schema.json")
    assert desired["properties"]["provider_execution_authorized"] == {"const": False}
    assert desired["properties"]["infrastructure_mutation_authorized"] == {"const": False}
    assert desired["properties"]["external_publication_authorized"] == {"const": False}


def test_contract_examples_validate_with_closed_schemas() -> None:
    request_schema = _json("contracts/household/parental-internet-decision-preview-request.v1.schema.json")
    jsonschema.Draft202012Validator(request_schema).validate(
        {
            "schema": "home-center.parental-internet-decision-preview-request.v1",
            "member_id": "member-child",
            "domain": "school.example",
            "category": "education",
            "weekday": 1,
            "minute_of_day": 600,
            "daily_used_minutes": 20,
            "weekly_used_minutes": 100,
            "continuous_used_minutes": 10,
            "view": "cozy",
        }
    )

    desired_schema = _json("contracts/household/parental-internet-policy-desired-read.v1.schema.json")
    jsonschema.Draft202012Validator(desired_schema).validate(
        {
            "schema": "home-center.parental-internet-policy-desired-read.v1",
            "member_id": "member-child",
            "view": "cozy",
            "state": "absent",
            "value": None,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
    )
