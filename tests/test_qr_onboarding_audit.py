from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import jsonschema

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_audit import qr_onboarding_audit_details
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository

ROOT = Path(__file__).resolve().parents[1]


def test_audit_projection_contains_only_bounded_receipt_evidence() -> None:
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
        onboarding_code="L" * 32,
    )

    details = qr_onboarding_audit_details(issued.receipt).to_dict()
    schema = json.loads(
        (ROOT / "contracts/household/qr-onboarding-audit-details.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(details)
    encoded = json.dumps(details, sort_keys=True)
    assert "L" * 32 not in encoded
    assert details["raw_onboarding_code_included"] is False
    assert details["qr_payload_included"] is False
    assert details["account_creation_authorized"] is False
    assert details["device_registration_authorized"] is False
    assert details["provider_execution_authorized"] is False
