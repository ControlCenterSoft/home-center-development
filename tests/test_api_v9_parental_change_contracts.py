from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from home_center.api_v9 import (
    CONFIRM_PATH,
    PLAN_PATH,
    REAUTH_PATH,
    REAUTH_REQUEST_SCHEMA,
    REAUTH_RESULT_SCHEMA,
    RuntimeRequestHandlerV9,
)
from home_center.api_v8 import RuntimeRequestHandlerV8

ROOT = Path(__file__).resolve().parents[1]


def _json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_parental_change_routes_are_separate_and_do_not_expose_provider_execution() -> None:
    assert PLAN_PATH == "/api/v1/household/parental-internet/plan"
    assert REAUTH_PATH == "/api/v1/household/parental-internet/reauth"
    assert CONFIRM_PATH == "/api/v1/household/parental-internet/confirm"
    assert issubclass(RuntimeRequestHandlerV9, RuntimeRequestHandlerV8)
    source = (ROOT / "product/control-plane/src/home_center/api_v9.py").read_text(encoding="utf-8")
    assert "max_bytes=262_144" in source
    assert 'self.headers.get("Idempotency-Key") != plan_id' in source
    assert 'self.headers.get("X-Home-Center-Step-Up")' in source
    assert "_same_origin_post_allowed" in source
    assert "provider_adapter" not in source
    assert "dns_policy_adapter" not in source
    assert "proxy_policy_adapter" not in source
    assert "/execute" not in source


def test_parental_reauth_contract_is_exact_plan_bound_and_closed() -> None:
    request = _json("contracts/household/parental-internet-reauth-request.v1.schema.json")
    result = _json("contracts/household/parental-internet-reauth-result.v1.schema.json")
    assert request["additionalProperties"] is False
    assert request["properties"]["schema"] == {"const": REAUTH_REQUEST_SCHEMA}
    assert request["properties"]["plan_id"]["pattern"] == "^hpip-[0-9a-f]{24}$"
    assert "scope" not in request["properties"]
    assert "step_up_token" not in request["properties"]
    assert result["additionalProperties"] is False
    assert result["properties"]["schema"] == {"const": REAUTH_RESULT_SCHEMA}
    assert result["properties"]["single_use"] == {"const": True}
    assert result["properties"]["scope"]["pattern"].startswith("^household")


def test_parental_change_openapi_requires_idempotency_and_step_up() -> None:
    document = _json("contracts/openapi/home-center-parental-internet-change.v1.openapi.json")
    assert document["openapi"] == "3.1.0"
    assert document["info"]["version"] == "0.60.0-development"
    assert set(document["paths"]) == {PLAN_PATH, REAUTH_PATH, CONFIRM_PATH}
    confirm = document["paths"][CONFIRM_PATH]["post"]
    headers = {item["name"]: item for item in confirm["parameters"]}
    assert headers["Idempotency-Key"]["required"] is True
    assert headers["X-Home-Center-Step-Up"]["required"] is True
    serialized = json.dumps(document, sort_keys=True)
    assert "/execute" not in serialized
    assert "DNS/proxy enforcement" in document["info"]["description"]


def test_reauth_example_contracts_validate() -> None:
    request_schema = _json("contracts/household/parental-internet-reauth-request.v1.schema.json")
    result_schema = _json("contracts/household/parental-internet-reauth-result.v1.schema.json")
    plan_id = "hpip-" + "a" * 24
    request = {
        "schema": REAUTH_REQUEST_SCHEMA,
        "provider": "local",
        "username": "admin",
        "password": "not-persisted-test-value",
        "plan_id": plan_id,
    }
    jsonschema.Draft202012Validator(request_schema).validate(request)
    jsonschema.Draft202012Validator(result_schema).validate(
        {
            "schema": REAUTH_RESULT_SCHEMA,
            "state": "verified",
            "plan_id": plan_id,
            "scope": "household.parental-internet.policy:" + plan_id,
            "step_up_token": "A" * 43,
            "expires_in_seconds": 300,
            "single_use": True,
        }
    )


def test_release_wheel_requires_safe_parental_runtime() -> None:
    qualifier = (ROOT / "scripts/qualify_release_artifact.py").read_text(encoding="utf-8")
    assert '"home_center/parental_internet_policy_runtime_safe.py"' in qualifier
