from __future__ import annotations

import copy
import hashlib
import json

import pytest

from home_center.household_policy_reconciliation import (
    DECISION_SCHEMA,
    OBSERVATION_SCHEMA,
    REQUEST_SCHEMA,
    HouseholdPolicyReconciliationError,
    build_reconciliation_request,
    evaluate_reconciliation,
)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _desired() -> dict[str, object]:
    policy = {
        "schema": "home-center.household-composed-policy.v1",
        "policy_id": "hcpol-0123456789abcdef01234567",
        "household_id": "home",
        "member_id": "member-child",
        "role": "child",
        "base_policy_id": "hpol-0123456789abcdef01234567",
        "bundle_id": "hpb-0123456789abcdef012345678",
        "internet_policy": "filtered",
        "vpn_allowed": False,
        "managed_device_required": True,
        "home_files_allowed": False,
        "smart_home_control_allowed": False,
        "administration_allowed": False,
        "external_publication_allowed": False,
        "enforcement_verified": False,
        "production_mutation_enabled": False,
        "explanation_ru": "Безопасный семейный профиль",
    }
    return {
        "schema": "home-center.household-policy-desired-state.v1",
        "household_id": "home",
        "member_id": "member-child",
        "generation": 7,
        "plan_id": "hpcp-0123456789abcdef01234567",
        "policy": policy,
        "policy_sha256": _digest(policy),
        "reason": "Apply safe child policy",
        "enforcement_verified": False,
        "reconciliation_required": True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _request(desired: dict[str, object]) -> dict[str, object]:
    return build_reconciliation_request(
        desired_state=desired,
        adapter_id="network-policy-adapter",
        adapter_revision="adapter-r17",
        target_id="lan-policy/member-child",
        correlation_id="policy-reconcile-0001",
    )


def _observation(
    desired: dict[str, object],
    request: dict[str, object],
    *,
    outcome: str = "verified",
) -> dict[str, object]:
    return {
        "schema": OBSERVATION_SCHEMA,
        "request_sha256": request["request_sha256"],
        "adapter_id": request["adapter_id"],
        "adapter_revision": request["adapter_revision"],
        "target_id": request["target_id"],
        "household_id": desired["household_id"],
        "member_id": desired["member_id"],
        "desired_generation": desired["generation"],
        "plan_id": desired["plan_id"],
        "policy_sha256": desired["policy_sha256"],
        "outcome": outcome,
        "actual_state_revision": "actual-r42",
        "observed_policy_sha256": desired["policy_sha256"],
        "evidence_sha256": "a" * 64,
        "provider_receipt_id": "provider-receipt-42" if outcome == "verified" else None,
    }


def test_verified_observation_produces_only_a_non_authoritative_candidate() -> None:
    desired = _desired()
    request = _request(desired)
    decision = evaluate_reconciliation(
        desired_state=desired,
        request=request,
        observation=_observation(desired, request),
    )

    assert request["schema"] == REQUEST_SCHEMA
    assert decision["schema"] == DECISION_SCHEMA
    assert decision["status"] == "verified_candidate"
    assert decision["eligible_for_enforcement_verification"] is True
    assert decision["enforcement_verified"] is False
    assert decision["reconciliation_required"] is True
    assert decision["infrastructure_mutation_authorized"] is False
    assert decision["external_publication_authorized"] is False


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("desired_generation", 8, "household_policy_reconciliation_observation_stale"),
        ("policy_sha256", "b" * 64, "household_policy_reconciliation_observation_stale"),
        ("adapter_revision", "adapter-r18", "household_policy_reconciliation_observation_stale"),
        ("target_id", "lan-policy/other", "household_policy_reconciliation_observation_stale"),
    ],
)
def test_observation_must_bind_to_exact_request(
    field: str, replacement: object, code: str
) -> None:
    desired = _desired()
    request = _request(desired)
    observation = _observation(desired, request)
    observation[field] = replacement

    with pytest.raises(HouseholdPolicyReconciliationError, match=code):
        evaluate_reconciliation(
            desired_state=desired,
            request=request,
            observation=observation,
        )


def test_verified_observation_requires_provider_receipt() -> None:
    desired = _desired()
    request = _request(desired)
    observation = _observation(desired, request)
    observation["provider_receipt_id"] = None

    with pytest.raises(
        HouseholdPolicyReconciliationError,
        match="household_policy_reconciliation_verified_evidence_incomplete",
    ):
        evaluate_reconciliation(
            desired_state=desired,
            request=request,
            observation=observation,
        )


def test_mismatch_never_becomes_verification_candidate() -> None:
    desired = _desired()
    request = _request(desired)
    observation = _observation(desired, request, outcome="mismatch")
    observation["observed_policy_sha256"] = "c" * 64

    decision = evaluate_reconciliation(
        desired_state=desired,
        request=request,
        observation=observation,
    )

    assert decision["status"] == "mismatch"
    assert decision["eligible_for_enforcement_verification"] is False
    assert decision["enforcement_verified"] is False


def test_request_tampering_is_rejected_before_observation() -> None:
    desired = _desired()
    request = _request(desired)
    tampered = copy.deepcopy(request)
    tampered["target_id"] = "lan-policy/other"

    with pytest.raises(
        HouseholdPolicyReconciliationError,
        match="household_policy_reconciliation_request_invalid",
    ):
        evaluate_reconciliation(
            desired_state=desired,
            request=tampered,
            observation=_observation(desired, request),
        )


def test_desired_policy_hash_mismatch_is_rejected() -> None:
    desired = _desired()
    desired["policy_sha256"] = "d" * 64

    with pytest.raises(
        HouseholdPolicyReconciliationError,
        match="household_policy_desired_state_digest_mismatch",
    ):
        build_reconciliation_request(
            desired_state=desired,
            adapter_id="network-policy-adapter",
            adapter_revision="adapter-r17",
            target_id="lan-policy/member-child",
            correlation_id="policy-reconcile-0001",
        )
