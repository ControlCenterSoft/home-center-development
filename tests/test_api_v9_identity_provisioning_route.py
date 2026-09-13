from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from home_center.api_v9 import RuntimeRequestHandlerV9
from home_center.api_v8 import RuntimeRequestHandlerV8

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/household"


def test_v9_identity_routes_extend_v8_without_overlapping_policy_routes() -> None:
    assert issubclass(RuntimeRequestHandlerV9, RuntimeRequestHandlerV8)
    assert RuntimeRequestHandlerV9.IDENTITY_PLAN_POSTS == {
        "/api/v1/household/identity/provisioning/plan"
    }
    assert RuntimeRequestHandlerV9.IDENTITY_EXECUTE_POSTS == {
        "/api/v1/household/identity/provisioning/execute"
    }
    assert RuntimeRequestHandlerV9.IDENTITY_BIND_POSTS == {
        "/api/v1/household/identity/provisioning/bind"
    }
    assert RuntimeRequestHandlerV9.IDENTITY_POSTS.isdisjoint(
        RuntimeRequestHandlerV8.POLICY_ENFORCEMENT_POSTS
    )


def test_production_server_uses_v9_and_safe_runtime() -> None:
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    runtime = (ROOT / "product/control-plane/src/home_center/runtime_safe.py").read_text(encoding="utf-8")
    api = (ROOT / "product/control-plane/src/home_center/api_v9.py").read_text(encoding="utf-8")

    assert "from .api_v9 import RuntimeRequestHandlerV9" in server
    assert "HomeCenterServer(config.web_bind, RuntimeRequestHandlerV9, runtime)" in server
    assert "RoleIdentityProvisioningApiService(" in runtime
    assert "SafeRoleIdentityProvisioningRuntimeService(self.store)" in runtime
    assert "_same_origin_post_allowed" in api
    assert "_require_actor" in api
    assert "_blocked_for_external" in api
    assert "max_bytes=8192" in api
    assert 'self.headers.get("Idempotency-Key")' in api


def test_identity_api_request_schemas_are_closed_and_secret_reference_only() -> None:
    plan = json.loads(
        (CONTRACTS / "role-identity-provisioning-api-plan-request.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    execute = json.loads(
        (CONTRACTS / "role-identity-provisioning-api-execute-request.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    bind = json.loads(
        (CONTRACTS / "role-identity-provisioning-api-bind-request.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    for schema in (plan, execute, bind):
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
    assert execute["properties"]["confirmed"] == {"const": True}
    assert bind["properties"]["confirmed"] == {"const": True}
    serialized = json.dumps(execute, sort_keys=True)
    assert "secret://" in serialized
    assert "password" not in serialized.lower()
    assert "token" not in serialized.lower()


def test_api_service_never_persists_credential_references_in_plan_state_contract() -> None:
    service = (
        ROOT / "product/control-plane/src/home_center/role_identity_provisioning_api_runtime.py"
    ).read_text(encoding="utf-8")
    assert '"credential_references"' not in service.split("envelope =", 1)[1].split("existing =", 1)[0]
    assert '"credential_material_included": False' in service
    assert "qualified_provider(" in service
    assert "qualification_evidence_sha256(" in service
    assert "identity_provisioning_api_plan_stale" in service
    assert "identity_provisioning_api_provider_stale" in service
