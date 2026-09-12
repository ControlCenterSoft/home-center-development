import pytest

from home_center.api_v7 import RuntimeRequestHandlerV7
from home_center.api_v8 import RuntimeRequestHandlerV8


def test_policy_enforcement_routes_are_explicit_and_separate_from_reconciliation() -> None:
    assert RuntimeRequestHandlerV8.POLICY_ENFORCEMENT_PLAN_POSTS == {
        "/api/v1/household/policy/enforcement/plan"
    }
    assert RuntimeRequestHandlerV8.POLICY_ENFORCEMENT_CONFIRM_POSTS == {
        "/api/v1/household/policy/enforcement/confirm"
    }
    assert RuntimeRequestHandlerV8.POLICY_ENFORCEMENT_EXECUTE_POSTS == {
        "/api/v1/household/policy/enforcement/execute"
    }
    assert issubclass(RuntimeRequestHandlerV8, RuntimeRequestHandlerV7)
    assert RuntimeRequestHandlerV8.POLICY_ENFORCEMENT_POSTS.isdisjoint(
        RuntimeRequestHandlerV7.POLICY_RECONCILIATION_POSTS
    )


def test_policy_enforcement_http_bodies_are_exact_contracts() -> None:
    plan = {"member_id": "member-a", "backend_id": "provider-a"}
    assert RuntimeRequestHandlerV8._exact_body(plan, {"member_id", "backend_id"}) is plan

    with pytest.raises(ValueError):
        RuntimeRequestHandlerV8._exact_body(
            {"member_id": "member-a", "backend_id": "provider-a", "confirmed": True},
            {"member_id", "backend_id"},
        )

    with pytest.raises(ValueError):
        RuntimeRequestHandlerV8._exact_body(["member-a", "provider-a"], {"member_id", "backend_id"})
