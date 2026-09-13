from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import jsonschema
import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_handoff import build_qr_onboarding_effect_handoff
from home_center.qr_onboarding_effect_post_condition import (
    QrOnboardingEffectObservationState,
    QrOnboardingEffectPostConditionError,
    build_qr_onboarding_effect_observation,
    qr_onboarding_effect_observation_from_dict,
    qr_onboarding_effect_verification_receipt_from_dict,
    verify_qr_onboarding_effect_post_condition,
)
from home_center.qr_onboarding_effect_verification import (
    QrOnboardingPostCondition,
    build_qr_onboarding_effect_verification_request,
)
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository
from scripts.qualify_release_artifact import REQUIRED_MEMBERS

ROOT = Path(__file__).resolve().parents[1]


def _snapshot():
    store = HouseholdStore()
    store.create(
        Household(
            household_id="home-main",
            members=(
                FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
                FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
                FamilyMember("child-1", "Child", HouseholdRole.CHILD),
            ),
            devices=(ManagedDevice("tablet-1", "child-1", "Tablet", managed=False),),
        )
    )
    return store.read("home-main")


def _service() -> QrOnboardingRuntimeService:
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    return QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))


def _guest_request():
    snapshot = _snapshot()
    service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="A" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="A" * 32,
        now_epoch=1_100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="A" * 32,
        actor="redemption-session-1",
        idempotency_key="consume-postcondition-0001",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    request = build_qr_onboarding_effect_verification_request(
        handoff=handoff, effect_job_id="job-qr-effect-guest-0001"
    )
    return handoff, request


def _device_request():
    snapshot = _snapshot()
    service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="child-1",
        subject=OnboardingSubject.DEVICE,
        device_id="tablet-1",
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        onboarding_code="B" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="B" * 32,
        now_epoch=1_100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="B" * 32,
        actor="redemption-session-2",
        idempotency_key="consume-postcondition-0002",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    request = build_qr_onboarding_effect_verification_request(
        handoff=handoff, effect_job_id="job-qr-effect-device-0001"
    )
    return handoff, request


def _satisfied(handoff, request, *, now=2_000):
    return build_qr_onboarding_effect_observation(
        request=request,
        handoff=handoff,
        observed_post_condition=request.expected_post_condition,
        state=QrOnboardingEffectObservationState.SATISFIED,
        source_id="authoritative-household-reader-v1",
        observed_at_epoch=now,
        valid_until_epoch=now + 120,
    )


def test_guest_success_requires_fresh_exact_authoritative_readback() -> None:
    handoff, request = _guest_request()
    observation = _satisfied(handoff, request)
    assert observation.guest_scope == (GuestScope.INTERNET_GUEST,)
    assert observation.to_dict()["effect_success_claimed"] is False
    assert qr_onboarding_effect_observation_from_dict(observation.to_dict()) == observation

    receipt = verify_qr_onboarding_effect_post_condition(
        request=request, handoff=handoff, observation=observation, now_epoch=2_030
    )
    payload = receipt.to_dict()
    assert payload["state"] == "verified"
    assert payload["authoritative_readback_verified"] is True
    assert payload["post_condition_verified"] is True
    assert payload["effect_success_claimed"] is True
    assert payload["effect_execution_authorized"] is False
    assert payload["durable_state_change_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False
    assert qr_onboarding_effect_verification_receipt_from_dict(payload) == receipt


def test_device_success_is_bound_to_exact_device_and_job() -> None:
    handoff, request = _device_request()
    observation = _satisfied(handoff, request)
    assert observation.device_id == "tablet-1"
    receipt = verify_qr_onboarding_effect_post_condition(
        request=request, handoff=handoff, observation=observation, now_epoch=2_010
    )
    assert receipt.device_id == "tablet-1"
    assert receipt.effect_job_id == request.effect_job_id
    assert receipt.observed_post_condition is QrOnboardingPostCondition.DEVICE_BINDING_EFFECTIVE


def test_unknown_not_satisfied_stale_and_future_observations_fail_closed() -> None:
    handoff, request = _guest_request()
    unknown = build_qr_onboarding_effect_observation(
        request=request,
        handoff=handoff,
        observed_post_condition=request.expected_post_condition,
        state=QrOnboardingEffectObservationState.UNKNOWN,
        source_id="authoritative-reader",
        observed_at_epoch=2_000,
        valid_until_epoch=2_100,
    )
    with pytest.raises(QrOnboardingEffectPostConditionError, match="qr_effect_post_condition_unknown"):
        verify_qr_onboarding_effect_post_condition(
            request=request, handoff=handoff, observation=unknown, now_epoch=2_010
        )

    denied = build_qr_onboarding_effect_observation(
        request=request,
        handoff=handoff,
        observed_post_condition=request.expected_post_condition,
        state=QrOnboardingEffectObservationState.NOT_SATISFIED,
        source_id="authoritative-reader",
        observed_at_epoch=2_000,
        valid_until_epoch=2_100,
    )
    with pytest.raises(QrOnboardingEffectPostConditionError, match="qr_effect_post_condition_not_satisfied"):
        verify_qr_onboarding_effect_post_condition(
            request=request, handoff=handoff, observation=denied, now_epoch=2_010
        )

    fresh = _satisfied(handoff, request, now=2_000)
    with pytest.raises(QrOnboardingEffectPostConditionError, match="qr_effect_post_condition_observation_stale"):
        verify_qr_onboarding_effect_post_condition(
            request=request, handoff=handoff, observation=fresh, now_epoch=2_121
        )
    with pytest.raises(QrOnboardingEffectPostConditionError, match="qr_effect_post_condition_observation_from_future"):
        verify_qr_onboarding_effect_post_condition(
            request=request, handoff=handoff, observation=fresh, now_epoch=1_999
        )


def test_cross_job_relabel_and_authority_escalation_are_rejected() -> None:
    handoff, request = _guest_request()
    observation = _satisfied(handoff, request)

    cross_job = copy.copy(observation)
    object.__setattr__(cross_job, "effect_job_id", "job-other")
    with pytest.raises(QrOnboardingEffectPostConditionError, match="qr_effect_post_condition_binding_mismatch"):
        verify_qr_onboarding_effect_post_condition(
            request=request, handoff=handoff, observation=cross_job, now_epoch=2_010
        )

    relabeled = observation.to_dict()
    relabeled["observed_post_condition"] = "access-revoked"
    with pytest.raises(QrOnboardingEffectPostConditionError, match="qr_effect_observation_rejected"):
        qr_onboarding_effect_observation_from_dict(relabeled)

    escalated = observation.to_dict()
    escalated["effect_execution_authorized"] = True
    with pytest.raises(QrOnboardingEffectPostConditionError, match="qr_effect_observation_rejected"):
        qr_onboarding_effect_observation_from_dict(escalated)


def test_observation_and_receipt_match_closed_contracts_and_wheel_membership() -> None:
    handoff, request = _guest_request()
    observation = _satisfied(handoff, request)
    receipt = verify_qr_onboarding_effect_post_condition(
        request=request, handoff=handoff, observation=observation, now_epoch=2_010
    )
    observation_schema = json.loads(
        (ROOT / "contracts/household/qr-onboarding-effect-observation.v1.schema.json").read_text(encoding="utf-8")
    )
    receipt_schema = json.loads(
        (ROOT / "contracts/household/qr-onboarding-effect-verification-receipt.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(observation_schema).validate(observation.to_dict())
    jsonschema.Draft202012Validator(receipt_schema).validate(receipt.to_dict())
    assert "home_center/qr_onboarding_effect_post_condition.py" in REQUIRED_MEMBERS
