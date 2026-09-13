from __future__ import annotations

from pathlib import Path

from home_center.api_v9 import RuntimeRequestHandlerV9
from home_center.api_v10 import RuntimeRequestHandlerV10

ROOT = Path(__file__).resolve().parents[1]


def test_v10_adds_only_separate_identity_binding_route_over_v9() -> None:
    assert issubclass(RuntimeRequestHandlerV10, RuntimeRequestHandlerV9)
    assert RuntimeRequestHandlerV10.IDENTITY_BIND_POSTS == {
        "/api/v1/household/identity/provisioning/bind"
    }
    assert RuntimeRequestHandlerV10.IDENTITY_BIND_POSTS.isdisjoint(RuntimeRequestHandlerV9.IDENTITY_POSTS)


def test_production_server_uses_v10_identity_binding_boundary() -> None:
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    api = (ROOT / "product/control-plane/src/home_center/api_v10.py").read_text(encoding="utf-8")

    assert "from .api_v10 import RuntimeRequestHandlerV10" in server
    assert "HomeCenterServer(config.web_bind, RuntimeRequestHandlerV10, runtime)" in server
    assert "_blocked_for_external" in api
    assert "_same_origin_post_allowed" in api
    assert "_require_actor" in api
    assert "max_bytes=4096" in api
    assert 'self.headers.get("Idempotency-Key")' in api


def test_binding_route_never_accepts_execution_receipt_or_provider_evidence_from_client() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v10.py").read_text(encoding="utf-8")
    runtime = (
        ROOT / "product/control-plane/src/home_center/role_identity_binding_api_runtime.py"
    ).read_text(encoding="utf-8")

    assert 'fields={"plan_id", "execution_job_id", "confirmed"}' in api
    assert "execution_receipt" not in api
    assert "credential_references" not in api
    assert "provider_evidence" not in api
    assert "self.store.job(execution_job_id)" in runtime
    assert "receipt = evidence.get(\"receipt\")" in runtime
    assert "self.binding.transition(" in runtime
    assert ".start(" not in runtime
    assert ".observe(" not in runtime
