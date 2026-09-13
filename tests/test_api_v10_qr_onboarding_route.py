from __future__ import annotations

import inspect

from home_center.api_v9 import RuntimeRequestHandlerV9
from home_center.api_v10 import RuntimeRequestHandlerV10, _CorrelatedQrRuntime


def test_qr_routes_extend_current_handler_chain_without_shadowing_identity_routes() -> None:
    assert issubclass(RuntimeRequestHandlerV10, RuntimeRequestHandlerV9)
    assert RuntimeRequestHandlerV10.QR_ISSUE_POSTS == {
        "/api/v1/household/qr-onboarding/issue"
    }
    assert RuntimeRequestHandlerV10.QR_PLAN_POSTS == {
        "/api/v1/household/qr-onboarding/plan"
    }
    assert RuntimeRequestHandlerV10.QR_CONSUME_POSTS == {
        "/api/v1/household/qr-onboarding/consume"
    }
    assert RuntimeRequestHandlerV10.QR_REVOKE_POSTS == {
        "/api/v1/household/qr-onboarding/revoke"
    }
    assert RuntimeRequestHandlerV10.QR_POSTS.isdisjoint(RuntimeRequestHandlerV9.IDENTITY_POSTS)


def test_qr_http_boundary_reuses_auth_origin_external_and_bounded_body_fences() -> None:
    source = inspect.getsource(RuntimeRequestHandlerV10.do_POST)
    assert "self._classify_request(correlation_id)" in source
    assert "self._blocked_for_external(path, context)" in source
    assert "self._same_origin_post_allowed(context)" in source
    assert "self._require_actor(correlation_id)" in source
    assert "self._read_json(max_bytes=8192)" in source
    assert "int(time.time())" in source
    assert "self.runtime.household._actor_member(actor, bindings)" in source
    assert "raw_onboarding_code" not in source
    assert "external_publication_authorized" not in source


def test_correlated_runtime_injects_server_correlation_and_exposes_repository() -> None:
    class FakeRuntime:
        def __init__(self) -> None:
            self.repository = object()
            self.calls: list[tuple[str, dict[str, object]]] = []

        def issue(self, **kwargs):
            self.calls.append(("issue", kwargs))
            return "issued"

        def consume(self, **kwargs):
            self.calls.append(("consume", kwargs))
            return "consumed"

        def revoke(self, **kwargs):
            self.calls.append(("revoke", kwargs))
            return "revoked"

        def plan_redemption(self, **kwargs):
            self.calls.append(("plan", kwargs))
            return "planned"

    fake = FakeRuntime()
    adapter = _CorrelatedQrRuntime(fake, "qr.http.correlation-1")
    assert adapter.repository is fake.repository
    assert adapter.issue(value=1) == "issued"
    assert adapter.consume(value=2) == "consumed"
    assert adapter.revoke(value=3) == "revoked"
    assert adapter.plan_redemption(value=4) == "planned"
    assert fake.calls == [
        ("issue", {"correlation_id": "qr.http.correlation-1", "value": 1}),
        ("consume", {"correlation_id": "qr.http.correlation-1", "value": 2}),
        ("revoke", {"correlation_id": "qr.http.correlation-1", "value": 3}),
        ("plan", {"value": 4}),
    ]
