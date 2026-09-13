import pytest

from home_center.api_v8 import RuntimeRequestHandlerV8
from home_center.api_v9 import (
    BIND_REQUEST_SCHEMA,
    EXECUTE_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    PREFLIGHT_REQUEST_SCHEMA,
    RuntimeRequestHandlerV9,
)


def test_identity_routes_are_explicit_and_extend_current_handler_chain() -> None:
    assert issubclass(RuntimeRequestHandlerV9, RuntimeRequestHandlerV8)
    assert RuntimeRequestHandlerV9.IDENTITY_PLAN_POSTS == {
        "/api/v1/household/identity/provisioning/plan"
    }
    assert RuntimeRequestHandlerV9.IDENTITY_PREFLIGHT_POSTS == {
        "/api/v1/household/identity/provisioning/preflight"
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


def test_identity_http_bodies_are_closed_and_do_not_accept_provider_evidence() -> None:
    plan = {
        "schema": PLAN_REQUEST_SCHEMA,
        "member_id": "member-child",
        "provider_id": "local-account",
        "account_name": "artemiy",
        "home_directory_mode": "local",
        "profile_mode": "local",
    }
    assert RuntimeRequestHandlerV9._schema_body(
        plan,
        schema=PLAN_REQUEST_SCHEMA,
        fields={"member_id", "provider_id", "account_name", "home_directory_mode", "profile_mode"},
    ) is plan

    with pytest.raises(ValueError):
        RuntimeRequestHandlerV9._schema_body(
            {**plan, "provider_evidence_sha256": "a" * 64},
            schema=PLAN_REQUEST_SCHEMA,
            fields={"member_id", "provider_id", "account_name", "home_directory_mode", "profile_mode"},
        )

    preflight = {"schema": PREFLIGHT_REQUEST_SCHEMA, "plan_id": "hcidp-" + "e" * 24}
    assert RuntimeRequestHandlerV9._schema_body(
        preflight, schema=PREFLIGHT_REQUEST_SCHEMA, fields={"plan_id"}
    ) is preflight

    execute = {
        "schema": EXECUTE_REQUEST_SCHEMA,
        "plan_id": "hcidp-" + "e" * 24,
        "confirmed": True,
        "credential_references": [],
    }
    assert RuntimeRequestHandlerV9._schema_body(
        execute,
        schema=EXECUTE_REQUEST_SCHEMA,
        fields={"plan_id", "confirmed", "credential_references"},
    ) is execute

    bind = {
        "schema": BIND_REQUEST_SCHEMA,
        "plan_id": "hcidp-" + "e" * 24,
        "execution_job_id": "job-exact-1",
        "confirmed": True,
    }
    assert RuntimeRequestHandlerV9._schema_body(
        bind,
        schema=BIND_REQUEST_SCHEMA,
        fields={"plan_id", "execution_job_id", "confirmed"},
    ) is bind
    with pytest.raises(ValueError):
        RuntimeRequestHandlerV9._schema_body(
            {**bind, "execution_receipt": {"state": "verified"}},
            schema=BIND_REQUEST_SCHEMA,
            fields={"plan_id", "execution_job_id", "confirmed"},
        )


def test_identity_http_fields_reject_implicit_coercion() -> None:
    assert RuntimeRequestHandlerV9._text({"member_id": "member-child"}, "member_id") == "member-child"
    assert RuntimeRequestHandlerV9._boolean({"confirmed": True}, "confirmed") is True
    with pytest.raises(ValueError):
        RuntimeRequestHandlerV9._text({"plan_id": 123}, "plan_id")
    with pytest.raises(ValueError):
        RuntimeRequestHandlerV9._boolean({"confirmed": 1}, "confirmed")
