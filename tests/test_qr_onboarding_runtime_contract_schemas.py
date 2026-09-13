from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import jsonschema

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository

ROOT = Path(__file__).resolve().parents[1]


def _schema(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def _issued():
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
    snapshot = store.read("home-main")
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    service = QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="K" * 32,
    )
    return snapshot, service, issued


def test_runtime_record_matches_closed_schema() -> None:
    _, _, issued = _issued()
    schema = _schema("qr-onboarding-runtime-record.v1.schema.json")
    jsonschema.Draft202012Validator(schema).validate(issued.record.to_dict())
    forged = dict(issued.record.to_dict())
    forged["raw_onboarding_code_persisted"] = True
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(forged))
    assert errors


def test_operation_receipts_match_closed_schema_before_and_after_consume() -> None:
    snapshot, service, issued = _issued()
    schema = _schema("qr-onboarding-operation-receipt.v1.schema.json")
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(issued.receipt.to_dict())

    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="K" * 32,
        now_epoch=1_100,
    )
    _, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="K" * 32,
        actor="redemption-session-1",
        idempotency_key="consume-key-0002",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    validator.validate(receipt.to_dict())
    assert receipt.to_dict()["invitation_state_post_condition_verified"] is True
    assert receipt.to_dict()["onboarding_effect_verified"] is False
    assert receipt.to_dict()["external_publication_authorized"] is False


def test_contracts_are_closed_and_contain_no_raw_secret_value_field() -> None:
    for name in (
        "qr-onboarding-runtime-record.v1.schema.json",
        "qr-onboarding-operation-receipt.v1.schema.json",
    ):
        schema = _schema(name)
        assert schema["additionalProperties"] is False
        text = json.dumps(schema, sort_keys=True)
        assert '"onboarding_code"' not in text
        assert '"credential_value"' not in text
