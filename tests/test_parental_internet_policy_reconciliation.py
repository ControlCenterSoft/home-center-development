from __future__ import annotations

import hashlib

import pytest

from home_center.parental_internet_policy_adapter import (
    ParentalInternetEnforcementAdapterCapabilities,
    ParentalInternetEnforcementApplyResult,
    ParentalInternetEnforcementObservation,
    build_parental_internet_apply_request,
)
from home_center.parental_internet_policy_reconciliation import (
    ParentalInternetEnforcementVerificationError,
    verify_parental_internet_enforcement,
)
from home_center.util import canonical_json


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _policy():
    return {
        "schema": "home-center.parental-internet-policy.v1",
        "policy_id": "hcip-" + "a" * 24,
        "household_id": "home",
        "member_id": "child",
        "subject_role": "child",
        "base_policy_id": "hcpol-" + "b" * 24,
        "base_policy_sha256": "c" * 64,
        "rule_source_id": "family-filter",
        "rule_source_version": "2026.09.13",
        "rule_source_sha256": "d" * 64,
        "allow_domains": ["school.example"],
        "deny_domains": ["blocked.example"],
        "allow_categories": ["education"],
        "deny_categories": ["adult"],
        "schedule": [],
        "daily_quota_minutes": 180,
        "weekly_quota_minutes": 900,
        "continuous_session_minutes": 60,
        "break_minutes": 15,
        "grace_minutes": 5,
        "bonus_minutes": 0,
        "default_decision": "deny",
        "dns_policy_required": True,
        "proxy_policy_required": True,
        "enforcement_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _desired():
    policy = _policy()
    return {
        "schema": "home-center.parental-internet-policy-desired-state.v1",
        "household_id": "home",
        "member_id": "child",
        "generation": 4,
        "plan_id": "hpip-" + "e" * 24,
        "verified_base_state_sha256": "f" * 64,
        "base_policy_id": policy["base_policy_id"],
        "base_policy_sha256": policy["base_policy_sha256"],
        "policy": policy,
        "policy_sha256": _digest(policy),
        "reason": "family rules",
        "enforcement_verified": False,
        "reconciliation_required": True,
        "dns_policy_applied": False,
        "proxy_policy_applied": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _inputs(*, observed_at: str = "2026-09-13T00:00:00Z"):
    desired = _desired()
    capabilities = ParentalInternetEnforcementAdapterCapabilities(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        supports_dns=True,
        supports_proxy=True,
        supports_readback=True,
        supports_rollback=True,
    )
    request = build_parental_internet_apply_request(
        desired_state=desired,
        job_id="job-parental-001",
        capabilities=capabilities,
    )
    result = ParentalInternetEnforcementApplyResult(
        adapter_id=capabilities.adapter_id,
        adapter_version=capabilities.adapter_version,
        provider_operation_id="op-001",
    )
    observation = ParentalInternetEnforcementObservation(
        adapter_id=capabilities.adapter_id,
        adapter_version=capabilities.adapter_version,
        provider_operation_id=result.provider_operation_id,
        desired_state_sha256=_digest(desired),
        policy_sha256=desired["policy_sha256"],
        observed_at=observed_at,
        dns_state="enforced",
        proxy_state="enforced",
        dns_policy_sha256=desired["policy_sha256"],
        proxy_policy_sha256=desired["policy_sha256"],
        blocker=None,
    )
    return desired, request, result, observation


def test_fresh_exact_readback_is_the_only_path_to_verified_enforcement() -> None:
    desired, request, result, observation = _inputs()
    decision = verify_parental_internet_enforcement(
        current_desired_state=desired,
        apply_request=request,
        apply_result=result,
        observation=observation,
        verified_at="2026-09-13T00:01:00Z",
    )
    assert decision.enforcement_verified is True
    assert decision.blockers == ()
    assert decision.dns_verified is True
    assert decision.proxy_verified is True
    raw = decision.to_dict()
    assert raw["enforcement_verified"] is True
    assert raw["backend_mutation_performed"] is False
    assert raw["infrastructure_mutation_performed"] is False
    assert raw["external_publication_performed"] is False


def test_provider_acceptance_without_matching_readback_cannot_verify() -> None:
    desired, request, result, observation = _inputs()
    observation = ParentalInternetEnforcementObservation(
        adapter_id=observation.adapter_id,
        adapter_version=observation.adapter_version,
        provider_operation_id=observation.provider_operation_id,
        desired_state_sha256=observation.desired_state_sha256,
        policy_sha256=observation.policy_sha256,
        observed_at=observation.observed_at,
        dns_state="enforced",
        proxy_state="unknown",
        dns_policy_sha256=observation.policy_sha256,
        proxy_policy_sha256=None,
        blocker="proxy-state-unknown",
    )
    decision = verify_parental_internet_enforcement(
        current_desired_state=desired,
        apply_request=request,
        apply_result=result,
        observation=observation,
        verified_at="2026-09-13T00:01:00Z",
    )
    assert decision.enforcement_verified is False
    assert decision.dns_verified is True
    assert decision.proxy_verified is False
    assert "proxy_not_enforced" in decision.blockers
    assert "adapter_blocker:proxy-state-unknown" in decision.blockers


def test_stale_observation_is_fail_closed_even_when_both_planes_match() -> None:
    desired, request, result, observation = _inputs(observed_at="2026-09-12T23:00:00Z")
    decision = verify_parental_internet_enforcement(
        current_desired_state=desired,
        apply_request=request,
        apply_result=result,
        observation=observation,
        verified_at="2026-09-13T00:00:00Z",
        freshness_seconds=300,
    )
    assert decision.enforcement_verified is False
    assert decision.dns_verified is True
    assert decision.proxy_verified is True
    assert decision.blockers == ("observation_stale",)


def test_future_observation_is_fail_closed() -> None:
    desired, request, result, observation = _inputs(observed_at="2026-09-13T00:02:00Z")
    decision = verify_parental_internet_enforcement(
        current_desired_state=desired,
        apply_request=request,
        apply_result=result,
        observation=observation,
        verified_at="2026-09-13T00:00:00Z",
    )
    assert decision.enforcement_verified is False
    assert "observation_from_future" in decision.blockers


def test_current_desired_state_drift_invalidates_old_apply_and_observation() -> None:
    desired, request, result, observation = _inputs()
    changed = _desired()
    changed["reason"] = "new parental write"
    decision = verify_parental_internet_enforcement(
        current_desired_state=changed,
        apply_request=request,
        apply_result=result,
        observation=observation,
        verified_at="2026-09-13T00:01:00Z",
    )
    assert decision.enforcement_verified is False
    assert "apply_request_binding_mismatch" in decision.blockers
    assert "observation_binding_mismatch" in decision.blockers


def test_policy_digest_mismatch_cannot_verify_even_if_adapter_says_enforced() -> None:
    desired, request, result, observation = _inputs()
    observation = ParentalInternetEnforcementObservation(
        adapter_id=observation.adapter_id,
        adapter_version=observation.adapter_version,
        provider_operation_id=observation.provider_operation_id,
        desired_state_sha256=observation.desired_state_sha256,
        policy_sha256=observation.policy_sha256,
        observed_at=observation.observed_at,
        dns_state="enforced",
        proxy_state="enforced",
        dns_policy_sha256="9" * 64,
        proxy_policy_sha256=observation.policy_sha256,
        blocker=None,
    )
    decision = verify_parental_internet_enforcement(
        current_desired_state=desired,
        apply_request=request,
        apply_result=result,
        observation=observation,
        verified_at="2026-09-13T00:01:00Z",
    )
    assert decision.enforcement_verified is False
    assert decision.dns_verified is False
    assert "dns_policy_mismatch" in decision.blockers


def test_freshness_budget_is_bounded() -> None:
    desired, request, result, observation = _inputs()
    with pytest.raises(
        ParentalInternetEnforcementVerificationError,
        match="parental_enforcement_freshness_invalid",
    ):
        verify_parental_internet_enforcement(
            current_desired_state=desired,
            apply_request=request,
            apply_result=result,
            observation=observation,
            verified_at="2026-09-13T00:01:00Z",
            freshness_seconds=86400,
        )
