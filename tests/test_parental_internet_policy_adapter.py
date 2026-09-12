from __future__ import annotations

import hashlib

import pytest

from home_center.parental_internet_policy_adapter import (
    ParentalInternetEnforcementAdapterCapabilities,
    ParentalInternetEnforcementAdapterError,
    ParentalInternetEnforcementAdapterRegistry,
    ParentalInternetEnforcementApplyResult,
    ParentalInternetEnforcementObservation,
    ParentalInternetEnforcementReadbackRequest,
    apply_result_from_dict,
    build_parental_internet_apply_request,
    observation_from_dict,
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


def _capabilities(**overrides):
    values = dict(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        supports_dns=True,
        supports_proxy=True,
        supports_readback=True,
        supports_rollback=True,
    )
    values.update(overrides)
    return ParentalInternetEnforcementAdapterCapabilities(**values)


def test_apply_request_is_exact_bound_and_has_no_secret_or_publication_authority() -> None:
    desired = _desired()
    request = build_parental_internet_apply_request(
        desired_state=desired,
        job_id="job-parental-001",
        capabilities=_capabilities(),
    )
    raw = request.to_dict()
    assert raw["desired_state_sha256"] == _digest(desired)
    assert raw["policy_sha256"] == desired["policy_sha256"]
    assert raw["verified_base_state_sha256"] == desired["verified_base_state_sha256"]
    assert raw["policy"] == desired["policy"]
    assert raw["adapter_execution_authorized"] is True
    assert raw["credential_value_access_authorized"] is False
    assert raw["external_publication_authorized"] is False
    assert raw["enforcement_verified"] is False
    serialized = canonical_json(raw).lower()
    assert "password" not in serialized
    assert "secret://" not in serialized


def test_provider_acceptance_is_never_enforcement_success() -> None:
    result = ParentalInternetEnforcementApplyResult(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        provider_operation_id="op-001",
    )
    raw = result.to_dict()
    assert raw["state"] == "accepted"
    assert raw["post_condition_verified"] is False
    assert raw["enforcement_verified"] is False
    assert raw["actual_state_readback_required"] is True
    assert apply_result_from_dict(raw) == result

    false_success = dict(raw)
    false_success["enforcement_verified"] = True
    with pytest.raises(ParentalInternetEnforcementAdapterError, match="parental_adapter_apply_result_rejected"):
        apply_result_from_dict(false_success)


def test_observation_requires_exact_digest_for_each_enforced_plane() -> None:
    policy_sha = "1" * 64
    observation = ParentalInternetEnforcementObservation(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        provider_operation_id="op-001",
        desired_state_sha256="2" * 64,
        policy_sha256=policy_sha,
        observed_at="2026-09-13T00:00:00Z",
        dns_state="enforced",
        proxy_state="enforced",
        dns_policy_sha256=policy_sha,
        proxy_policy_sha256=policy_sha,
        blocker=None,
    )
    assert observation_from_dict(observation.to_dict()) == observation
    assert observation.to_dict()["enforcement_verified"] is False

    with pytest.raises(ParentalInternetEnforcementAdapterError):
        ParentalInternetEnforcementObservation(
            adapter_id="local-dns-proxy",
            adapter_version="1.0.0",
            provider_operation_id="op-001",
            desired_state_sha256="2" * 64,
            policy_sha256=policy_sha,
            observed_at="2026-09-13T00:00:00Z",
            dns_state="enforced",
            proxy_state="unknown",
            dns_policy_sha256=policy_sha,
            proxy_policy_sha256=None,
            blocker=None,
        )


def test_non_enforced_or_unknown_observation_requires_bounded_blocker() -> None:
    observation = ParentalInternetEnforcementObservation(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        provider_operation_id="op-001",
        desired_state_sha256="2" * 64,
        policy_sha256="1" * 64,
        observed_at="2026-09-13T00:00:00Z",
        dns_state="enforced",
        proxy_state="unknown",
        dns_policy_sha256="1" * 64,
        proxy_policy_sha256=None,
        blocker="proxy-state-unknown",
    )
    assert observation_from_dict(observation.to_dict()) == observation


def test_readback_contract_is_read_only() -> None:
    request = ParentalInternetEnforcementReadbackRequest(
        adapter_id="local-dns-proxy",
        adapter_version="1.0.0",
        provider_operation_id="op-001",
        desired_state_sha256="2" * 64,
        policy_sha256="1" * 64,
    )
    raw = request.to_dict()
    assert raw["backend_mutation_authorized"] is False
    assert raw["infrastructure_mutation_authorized"] is False
    assert raw["external_publication_authorized"] is False


def test_capabilities_require_both_planes_and_readback() -> None:
    with pytest.raises(ParentalInternetEnforcementAdapterError, match="parental_adapter_readback_required"):
        _capabilities(supports_readback=False)
    with pytest.raises(ParentalInternetEnforcementAdapterError, match="parental_adapter_dns_proxy_required"):
        _capabilities(supports_proxy=False)


class _Adapter:
    def __init__(self, adapter_id: str = "local-dns-proxy") -> None:
        self.capabilities = ParentalInternetEnforcementAdapterCapabilities(
            adapter_id=adapter_id,
            adapter_version="1.0.0",
            supports_dns=True,
            supports_proxy=True,
            supports_readback=True,
            supports_rollback=True,
        )

    def apply(self, request):
        raise AssertionError("must not execute in registry test")

    def read_actual_state(self, request):
        raise AssertionError("must not execute in registry test")

    def rollback(self, request):
        raise AssertionError("must not execute in registry test")


def test_registry_is_empty_by_default_and_fails_closed() -> None:
    registry = ParentalInternetEnforcementAdapterRegistry()
    assert registry.capabilities() == ()
    with pytest.raises(ParentalInternetEnforcementAdapterError, match="parental_adapter_not_registered"):
        registry.resolve("local-dns-proxy")


def test_registry_rejects_duplicate_adapter_and_does_not_invoke_it() -> None:
    registry = ParentalInternetEnforcementAdapterRegistry()
    adapter = _Adapter()
    registry.register(adapter)
    assert registry.resolve("local-dns-proxy") is adapter
    assert registry.capabilities() == (adapter.capabilities,)
    with pytest.raises(ParentalInternetEnforcementAdapterError, match="parental_adapter_already_registered"):
        registry.register(_Adapter())
