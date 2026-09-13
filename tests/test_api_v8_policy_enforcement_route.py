import pytest

from home_center.api_v7 import RuntimeRequestHandlerV7
from home_center.api_v8 import (
    CONFIRM_REQUEST_SCHEMA,
    EXECUTE_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    RuntimeRequestHandlerV8,
)


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


def test_policy_enforcement_http_bodies_are_explicit_schema_contracts() -> None:
    plan = {
        "schema": PLAN_REQUEST_SCHEMA,
        "member_id": "member-a",
        "backend_id": "provider-a",
    }
    assert RuntimeRequestHandlerV8._schema_body(
        plan,
        schema=PLAN_REQUEST_SCHEMA,
        fields={"member_id", "backend_id"},
    ) is plan

    confirm = {
        "schema": CONFIRM_REQUEST_SCHEMA,
        "plan_id": "hpep-0123456789abcdef01234567",
        "confirmed": True,
    }
    assert RuntimeRequestHandlerV8._schema_body(
        confirm,
        schema=CONFIRM_REQUEST_SCHEMA,
        fields={"plan_id", "confirmed"},
    ) is confirm

    execute = {
        "schema": EXECUTE_REQUEST_SCHEMA,
        "plan_id": "hpep-0123456789abcdef01234567",
    }
    assert RuntimeRequestHandlerV8._schema_body(
        execute,
        schema=EXECUTE_REQUEST_SCHEMA,
        fields={"plan_id"},
    ) is execute

    with pytest.raises(ValueError):
        RuntimeRequestHandlerV8._schema_body(
            {
                "schema": PLAN_REQUEST_SCHEMA,
                "member_id": "member-a",
                "backend_id": "provider-a",
                "confirmed": True,
            },
            schema=PLAN_REQUEST_SCHEMA,
            fields={"member_id", "backend_id"},
        )

    with pytest.raises(ValueError):
        RuntimeRequestHandlerV8._schema_body(
            {
                "schema": "home-center.household-policy-enforcement-plan-request.v2",
                "member_id": "member-a",
                "backend_id": "provider-a",
            },
            schema=PLAN_REQUEST_SCHEMA,
            fields={"member_id", "backend_id"},
        )


def test_policy_enforcement_http_fields_reject_implicit_coercion() -> None:
    request = {
        "member_id": "member-a",
        "backend_id": "provider-a",
        "confirmed": True,
    }
    assert RuntimeRequestHandlerV8._text_field(request, "member_id") == "member-a"
    assert RuntimeRequestHandlerV8._text_field(request, "backend_id") == "provider-a"
    assert RuntimeRequestHandlerV8._bool_field(request, "confirmed") is True

    with pytest.raises(ValueError):
        RuntimeRequestHandlerV8._text_field({"plan_id": 123}, "plan_id")

    with pytest.raises(ValueError):
        RuntimeRequestHandlerV8._bool_field({"confirmed": 1}, "confirmed")

    with pytest.raises(ValueError):
        RuntimeRequestHandlerV8._bool_field({"confirmed": "true"}, "confirmed")
