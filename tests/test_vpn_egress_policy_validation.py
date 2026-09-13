from __future__ import annotations

import pytest

from home_center.household import EffectivePolicy, HouseholdRole, InternetPolicy
from home_center.household_policy_composer import build_policy_bundle, compose_policy
from home_center.vpn_egress_policy import (
    DnsStrategy,
    FallbackMode,
    RouteMode,
    VpnEgressObservation,
    VpnEgressProviderCandidate,
    build_vpn_egress_policy,
    evaluate_vpn_route,
)
from home_center.vpn_egress_policy_validation import (
    VpnEgressEvidenceValidationError,
    observation_from_dict,
    policy_from_dict,
    provider_candidate_from_dict,
    route_decision_from_dict,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def _base():
    effective = EffectivePolicy(
        policy_id="hep-base",
        household_id="household-1",
        member_id="member-1",
        role=HouseholdRole.PARENT,
        internet_policy=InternetPolicy.FULL,
        vpn_allowed=True,
        managed_device_required=False,
        home_files_allowed=True,
        smart_home_control_allowed=True,
        administration_allowed=True,
        external_publication_allowed=False,
    )
    bundle = build_policy_bundle(
        role=HouseholdRole.PARENT,
        value={
            "internet_policy": "full",
            "vpn_allowed": True,
            "managed_device_required": False,
            "home_files_allowed": True,
            "smart_home_control_allowed": True,
            "administration_allowed": True,
            "external_publication_allowed": False,
        },
    )
    return compose_policy(base=effective, bundle=bundle)


def _provider():
    return VpnEgressProviderCandidate(
        provider_id="provider-a",
        provider_version="1.0.0",
        location_id="nl-ams",
        reachable=True,
        latency_ms=20,
        stability_bps=9980,
        split_routing_supported=True,
        kill_switch_supported=True,
        supported_dns_strategies=(DnsStrategy.PROVIDER, DnsStrategy.PARENTAL, DnsStrategy.SYSTEM),
        evidence_sha256=DIGEST_A,
    )


def _policy():
    return build_vpn_egress_policy(
        base=_base(),
        provider=_provider(),
        dns_strategy=DnsStrategy.PROVIDER,
        split_domains=("example.com",),
        kill_switch=True,
        fallback_mode=FallbackMode.DENY,
        max_latency_ms=200,
        min_stability_bps=9500,
    )


def _observation():
    return VpnEgressObservation(
        provider_id="provider-a",
        provider_version="1.0.0",
        location_id="nl-ams",
        reachable=True,
        latency_ms=25,
        stability_bps=9970,
        evidence_sha256=DIGEST_B,
    )


def test_strict_reconstruction_accepts_exact_objects() -> None:
    provider = _provider()
    policy = _policy()
    observation = _observation()
    decision = evaluate_vpn_route(policy=policy, observation=observation, domain="api.example.com")

    assert provider_candidate_from_dict(provider.to_dict()) == provider
    assert policy_from_dict(policy.to_dict()) == policy
    assert observation_from_dict(observation.to_dict()) == observation
    assert route_decision_from_dict(decision.to_dict()) == decision
    assert decision.route is RouteMode.VPN


def test_extra_provider_field_is_rejected() -> None:
    raw = _provider().to_dict()
    raw["hidden_authority"] = True
    with pytest.raises(VpnEgressEvidenceValidationError, match="vpn_provider_candidate_rejected"):
        provider_candidate_from_dict(raw)


def test_policy_identity_tampering_is_rejected() -> None:
    raw = _policy().to_dict()
    raw["policy_id"] = "hcvpn-" + "f" * 24
    with pytest.raises(VpnEgressEvidenceValidationError, match="vpn_policy_rejected"):
        policy_from_dict(raw)


def test_policy_authority_escalation_is_rejected() -> None:
    raw = _policy().to_dict()
    raw["execution_authorized"] = True
    with pytest.raises(VpnEgressEvidenceValidationError, match="vpn_policy_rejected"):
        policy_from_dict(raw)


def test_kill_switch_direct_fallback_tampering_is_rejected() -> None:
    raw = _policy().to_dict()
    raw["fallback_mode"] = "direct"
    with pytest.raises(VpnEgressEvidenceValidationError, match="vpn_policy_rejected"):
        policy_from_dict(raw)


def test_observation_cannot_claim_write_authority() -> None:
    raw = _observation().to_dict()
    raw["read_only"] = False
    with pytest.raises(VpnEgressEvidenceValidationError, match="vpn_observation_rejected"):
        observation_from_dict(raw)


def test_non_vpn_route_cannot_smuggle_provider_selection() -> None:
    raw = evaluate_vpn_route(policy=_policy(), observation=_observation(), domain="other.net").to_dict()
    assert raw["route"] == "direct"
    raw["provider_id"] = "provider-a"
    with pytest.raises(VpnEgressEvidenceValidationError, match="vpn_route_decision_rejected"):
        route_decision_from_dict(raw)
