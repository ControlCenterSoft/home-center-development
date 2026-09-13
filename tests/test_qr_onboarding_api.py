from __future__ import annotations

import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope
from home_center.qr_onboarding_api import (
    CONSUME_REQUEST_SCHEMA,
    ISSUE_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    REVOKE_REQUEST_SCHEMA,
    QrOnboardingApiError,
    QrOnboardingApiService,
    parse_consume_request,
    parse_issue_request,
    parse_plan_request,
    parse_revoke_request,
)
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository


def _snapshot():
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
            FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
        ),
        devices=(),
    )
    store = HouseholdStore()
    store.create(household)
    return store.read("home-main")


def _api():
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    runtime = QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))
    return QrOnboardingApiService(runtime)


def test_issue_request_is_closed_and_actor_time_are_not_client_selected() -> None:
    body = {
        "schema": ISSUE_REQUEST_SCHEMA,
        "target_member_id": "guest-1",
        "subject": "guest",
        "device_id": None,
        "guest_scope": ["internet.guest"],
        "ttl_seconds": 600,
    }
    request = parse_issue_request(body)
    assert request.guest_scope == (GuestScope.INTERNET_GUEST,)

    with pytest.raises(QrOnboardingApiError, match="qr_api_issue_request_rejected"):
        parse_issue_request({**body, "actor_member_id": "parent-1"})
    with pytest.raises(QrOnboardingApiError, match="qr_api_issue_request_rejected"):
        parse_issue_request({**body, "created_at_epoch": 1_000})

    issued = _api().issue(
        snapshot=_snapshot(),
        actor_member_id="parent-1",
        body=body,
        now_epoch=1_000,
    )
    assert issued.record.invitation.issuer_member_id == "parent-1"
    assert issued.record.invitation.created_at_epoch == 1_000
    assert issued.record.invitation.expires_at_epoch == 1_600


def test_api_rejects_guest_scope_broadening_before_runtime() -> None:
    with pytest.raises(QrOnboardingApiError, match="qr_runtime_guest_scope_not_bounded"):
        _api().issue(
            snapshot=_snapshot(),
            actor_member_id="parent-1",
            body={
                "schema": ISSUE_REQUEST_SCHEMA,
                "target_member_id": "guest-1",
                "subject": "guest",
                "device_id": None,
                "guest_scope": ["home.status.read"],
                "ttl_seconds": 600,
            },
            now_epoch=1_000,
        )


def test_plan_and_consume_keep_code_ephemeral_and_require_confirmation() -> None:
    api = _api()
    snapshot = _snapshot()
    issued = api.issue(
        snapshot=snapshot,
        actor_member_id="parent-1",
        body={
            "schema": ISSUE_REQUEST_SCHEMA,
            "target_member_id": "guest-1",
            "subject": "guest",
            "device_id": None,
            "guest_scope": ["internet.guest"],
            "ttl_seconds": 600,
        },
        now_epoch=1_000,
    )
    code = issued.payload.onboarding_code
    plan = api.plan(
        snapshot=snapshot,
        body={
            "schema": PLAN_REQUEST_SCHEMA,
            "invitation_id": issued.record.invitation.invitation_id,
            "onboarding_code": code,
        },
        now_epoch=1_100,
    )

    with pytest.raises(QrOnboardingApiError, match="qr_api_confirmation_required"):
        parse_consume_request(
            {
                "schema": CONSUME_REQUEST_SCHEMA,
                "plan": plan.to_dict(),
                "onboarding_code": code,
                "expected_version": 1,
                "confirmed": False,
                "idempotency_key": "consume-api-0001",
            }
        )

    record, receipt = api.consume(
        snapshot=snapshot,
        actor="qr-redemption-session-1",
        body={
            "schema": CONSUME_REQUEST_SCHEMA,
            "plan": plan.to_dict(),
            "onboarding_code": code,
            "expected_version": 1,
            "confirmed": True,
            "idempotency_key": "consume-api-0001",
        },
        now_epoch=1_200,
    )
    assert record.state.value == "consumed"
    assert receipt.to_dict()["onboarding_effect_verified"] is False
    assert "onboarding_code" not in receipt.to_dict()


def test_consume_rejects_tampered_plan_and_extra_request_fields() -> None:
    api = _api()
    snapshot = _snapshot()
    issued = api.issue(
        snapshot=snapshot,
        actor_member_id="parent-1",
        body={
            "schema": ISSUE_REQUEST_SCHEMA,
            "target_member_id": "guest-1",
            "subject": "guest",
            "device_id": None,
            "guest_scope": ["internet.guest"],
            "ttl_seconds": 600,
        },
        now_epoch=1_000,
    )
    code = issued.payload.onboarding_code
    plan = api.plan(
        snapshot=snapshot,
        body={
            "schema": PLAN_REQUEST_SCHEMA,
            "invitation_id": issued.record.invitation.invitation_id,
            "onboarding_code": code,
        },
        now_epoch=1_100,
    ).to_dict()
    tampered = dict(plan)
    tampered["target_member_id"] = "parent-1"
    with pytest.raises(QrOnboardingApiError):
        api.consume(
            snapshot=snapshot,
            actor="qr-redemption-session-2",
            body={
                "schema": CONSUME_REQUEST_SCHEMA,
                "plan": tampered,
                "onboarding_code": code,
                "expected_version": 1,
                "confirmed": True,
                "idempotency_key": "consume-api-0002",
            },
            now_epoch=1_200,
        )
    with pytest.raises(QrOnboardingApiError, match="qr_api_consume_request_rejected"):
        parse_consume_request(
            {
                "schema": CONSUME_REQUEST_SCHEMA,
                "plan": plan,
                "onboarding_code": code,
                "expected_version": 1,
                "confirmed": True,
                "idempotency_key": "consume-api-0003",
                "actor": "parent-1",
            }
        )


def test_revoke_request_cannot_select_actor_and_uses_server_parent_context() -> None:
    api = _api()
    snapshot = _snapshot()
    issued = api.issue(
        snapshot=snapshot,
        actor_member_id="parent-1",
        body={
            "schema": ISSUE_REQUEST_SCHEMA,
            "target_member_id": "guest-1",
            "subject": "guest",
            "device_id": None,
            "guest_scope": ["internet.guest"],
            "ttl_seconds": 600,
        },
        now_epoch=1_000,
    )
    revoke = {
        "schema": REVOKE_REQUEST_SCHEMA,
        "invitation_id": issued.record.invitation.invitation_id,
        "expected_version": 1,
        "idempotency_key": "revoke-api-0001",
    }
    parsed = parse_revoke_request(revoke)
    assert parsed.invitation_id == issued.record.invitation.invitation_id
    with pytest.raises(QrOnboardingApiError, match="qr_api_revoke_request_rejected"):
        parse_revoke_request({**revoke, "actor_member_id": "parent-1"})
    record, _ = api.revoke(
        snapshot=snapshot,
        actor_member_id="parent-1",
        body=revoke,
        now_epoch=1_100,
    )
    assert record.state.value == "revoked"


def test_plan_request_and_versions_are_strictly_bounded() -> None:
    with pytest.raises(QrOnboardingApiError, match="qr_api_onboarding_code_invalid"):
        parse_plan_request(
            {
                "schema": PLAN_REQUEST_SCHEMA,
                "invitation_id": "hcqri-" + "a" * 24,
                "onboarding_code": "short",
            }
        )
    with pytest.raises(QrOnboardingApiError, match="qr_api_expected_version_invalid"):
        parse_revoke_request(
            {
                "schema": REVOKE_REQUEST_SCHEMA,
                "invitation_id": "hcqri-" + "a" * 24,
                "expected_version": True,
                "idempotency_key": "revoke-api-0002",
            }
        )
