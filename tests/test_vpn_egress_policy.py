from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import EffectivePolicy, HouseholdRole, InternetPolicy
from home_center.household_policy_composer import build_policy_bundle, compose_policy
from home_center.parental_internet_policy import AccessDecision, InternetPolicyDecision
from home_center.vpn_egress_policy import (
    DnsStrategy,
    FallbackMode,
    RouteMode,
    VpnEgressObservation,
    VpnEgressPolicy,
    VpnEgressPolicyError,
    VpnEgressProviderCandidate,
    build_vpn_egress_policy,
    evaluate_vpn_route,
    select_vpn_egress_provider,
)

ROOT = Path(__file__).resolve().parents[1]
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def _composed(*, role: HouseholdRole = HouseholdRole.PARENT, internet: InternetPolicy = InternetPolicy.FULL,
              vpn_allowed: bool = True):
    base = EffectivePolicy(
        policy_id="hep-base",
        household_id="household-1",
        member_id="member-1",
        role=role,
        internet_policy=internet,
        vpn_allowed=vpn_allowed,
        managed_device_required=role is HouseholdRole.CHILD,
        home_files_allowed=True,
        smart_home_control_allowed=role is HouseholdRole.PARENT,
        administration_allowed=role is HouseholdRole.PARENT,
        external_publication_allowed=False,
    )
    bundle = build_policy_bundle(
        role=role,
        value={
            "internet_policy": internet.value,
            "vpn_allowed": vpn_allowed,
            "managed_device_required": role is HouseholdRole.CHILD,
            "home_files_allowed": True,
            "smart_home_control_allowed": role is HouseholdRole.PARENT,
            "administration_allowed": role is HouseholdRole.PARENT,
            "external_publication_allowed": False,
        },
    )
    return compose_policy(base=base, bundle=bundle)


def _provider(*, provider_id: str = "provider-a", latency_ms: int = 30, stability_bps: int = 9950,
              reachable: bool = True, split: bool = True, kill_switch: bool = True,
              dns=(DnsStrategy.PROVIDER, DnsStrategy.PARENTAL, DnsStrategy.SYSTEM), digest: str = DIGEST_A):
    return VpnEgressProviderCandidate(
        provider_id=provider_id,
        provider_version="1.0.0",
        location_id="nl-ams",
        reachable=reachable,
        latency_ms=latency_ms,
        stability_bps=stability_bps,
        split_routing_supported=split,
        kill_switch_supported=kill_switch,
        supported_dns_strategies=tuple(dns),
        evidence_sha256=digest,
    )


def _observation(*, reachable: bool = True, latency_ms: int = 35, stability_bps: int = 9920,
                 provider_id: str = "provider-a", digest: str = DIGEST_B):
    return VpnEgressObservation(
        provider_id=provider_id,
        provider_version="1.0.0",
        location_id="nl-ams",
        reachable=reachable,
        latency_ms=latency_ms,
        stability_bps=stability_bps,
        evidence_sha256=digest,
    )


def _manual_policy(*, parental_policy_id: str | None = None, kill_switch: bool = True,
                   fallback_mode: FallbackMode = FallbackMode.DENY, split_domains=()):
    return VpnEgressPolicy(
        policy_id="hcvpn-" + "1" * 24,
        household_id="household-1",
        member_id="member-1",
        base_policy_id="hcpol-base",
        base_policy_sha256=DIGEST_A,
        parental_policy_id=parental_policy_id,
        parental_policy_sha256=DIGEST_C if parental_policy_id else None,
        provider_id="provider-a",
        provider_version="1.0.0",
        provider_evidence_sha256=DIGEST_A,
        location_id="nl-ams",
        dns_strategy=DnsStrategy.PARENTAL if parental_policy_id else DnsStrategy.PROVIDER,
        split_domains=tuple(split_domains),
        kill_switch=kill_switch,
        fallback_mode=fallback_mode,
        max_latency_ms=250,
        min_stability_bps=9500,
    )


def test_provider_selection_is_deterministic_and_capability_gated() -> None:
    candidates = [
        _provider(provider_id="provider-c", latency_ms=20, stability_bps=9300, digest="c" * 64),
        _provider(provider_id="provider-b", latency_ms=28, stability_bps=9990, digest="d" * 64),
        _provider(provider_id="provider-a", latency_ms=28, stability_bps=9990, digest="e" * 64),
    ]
    selected = select_vpn_egress_provider(
        candidates,
        location_id="nl-ams",
        dns_strategy=DnsStrategy.PROVIDER,
        split_routing=True,
        kill_switch=True,
        max_latency_ms=100,
        min_stability_bps=9500,
    )
    assert selected.provider_id == "provider-a"


def test_provider_selection_fails_closed_when_no_candidate_meets_thresholds() -> None:
    with pytest.raises(VpnEgressPolicyError, match="vpn_provider_unavailable"):
        select_vpn_egress_provider(
            [_provider(latency_ms=800), _provider(provider_id="provider-b", reachable=False)],
            location_id="nl-ams",
            dns_strategy=DnsStrategy.PROVIDER,
            split_routing=False,
            kill_switch=True,
            max_latency_ms=100,
            min_stability_bps=9500,
        )


def test_current_child_role_cannot_gain_vpn_through_061() -> None:
    child = _composed(role=HouseholdRole.CHILD, internet=InternetPolicy.FILTERED, vpn_allowed=False)
    with pytest.raises(VpnEgressPolicyError, match="vpn_not_allowed_by_effective_policy"):
        build_vpn_egress_policy(base=child, provider=_provider(), dns_strategy=DnsStrategy.PARENTAL)


def test_filtered_policy_cannot_use_system_dns_as_bypass() -> None:
    filtered_parent = _composed(role=HouseholdRole.PARENT, internet=InternetPolicy.FILTERED, vpn_allowed=True)
    with pytest.raises(VpnEgressPolicyError, match="vpn_system_dns_would_bypass_filtering"):
        build_vpn_egress_policy(
            base=filtered_parent,
            provider=_provider(),
            dns_strategy=DnsStrategy.SYSTEM,
            parental_policy=None,
        )


def test_kill_switch_and_direct_fallback_are_mutually_exclusive() -> None:
    with pytest.raises(VpnEgressPolicyError, match="vpn_kill_switch_fallback_conflict"):
        build_vpn_egress_policy(
            base=_composed(),
            provider=_provider(),
            dns_strategy=DnsStrategy.PROVIDER,
            kill_switch=True,
            fallback_mode=FallbackMode.DIRECT,
        )


def test_parental_deny_always_beats_healthy_vpn_route() -> None:
    policy = _manual_policy(parental_policy_id="hcip-" + "2" * 24)
    denied = InternetPolicyDecision(
        policy_id=policy.parental_policy_id or "",
        decision=AccessDecision.DENY,
        reason="category_deny",
        rule_source_id="rules",
        rule_source_version="1",
        rule_source_sha256=DIGEST_C,
    )
    decision = evaluate_vpn_route(policy=policy, observation=_observation(), parental_decision=denied)
    assert decision.route is RouteMode.DENY
    assert decision.reason == "parental_deny"
    assert decision.provider_id is None


def test_missing_parental_decision_fails_closed() -> None:
    decision = evaluate_vpn_route(
        policy=_manual_policy(parental_policy_id="hcip-" + "2" * 24),
        observation=_observation(),
    )
    assert decision.route is RouteMode.DENY
    assert decision.reason == "parental_decision_required"


def test_unhealthy_vpn_with_kill_switch_denies_instead_of_leaking_direct() -> None:
    decision = evaluate_vpn_route(
        policy=_manual_policy(),
        observation=_observation(reachable=False),
    )
    assert decision.route is RouteMode.DENY
    assert decision.reason == "vpn_unhealthy_fail_closed"


def test_explicit_direct_fallback_is_possible_only_without_kill_switch() -> None:
    policy = _manual_policy(kill_switch=False, fallback_mode=FallbackMode.DIRECT)
    decision = evaluate_vpn_route(policy=policy, observation=_observation(reachable=False))
    assert decision.route is RouteMode.DIRECT
    assert decision.reason == "vpn_unhealthy_direct_fallback"


def test_split_routing_with_deny_fallback_does_not_leak_nonmatching_domains_direct() -> None:
    policy = _manual_policy(split_domains=("example.com",))
    denied = evaluate_vpn_route(policy=policy, observation=_observation(), domain="other.example.net")
    tunneled = evaluate_vpn_route(policy=policy, observation=_observation(), domain="api.example.com")
    assert denied.route is RouteMode.DENY
    assert denied.reason == "split_route_direct_not_authorized"
    assert tunneled.route is RouteMode.VPN
    assert tunneled.reason == "vpn_route_selected"


def test_split_routing_nonmatch_can_use_direct_only_when_explicitly_permitted() -> None:
    policy = _manual_policy(
        split_domains=("example.com",),
        kill_switch=False,
        fallback_mode=FallbackMode.DIRECT,
    )
    direct = evaluate_vpn_route(policy=policy, observation=_observation(), domain="other.example.net")
    tunneled = evaluate_vpn_route(policy=policy, observation=_observation(), domain="api.example.com")
    assert direct.route is RouteMode.DIRECT
    assert direct.reason == "split_route_direct"
    assert tunneled.route is RouteMode.VPN
    assert tunneled.reason == "vpn_route_selected"


def test_observation_identity_mismatch_fails_closed() -> None:
    decision = evaluate_vpn_route(
        policy=_manual_policy(),
        observation=_observation(provider_id="provider-other"),
    )
    assert decision.route is RouteMode.DENY
    assert decision.reason == "provider_observation_binding_mismatch"


def test_policy_and_evidence_contracts_are_closed() -> None:
    provider_schema = json.loads((ROOT / "contracts/household/vpn-egress-provider-candidate.v1.schema.json").read_text())
    policy_schema = json.loads((ROOT / "contracts/household/vpn-egress-policy.v1.schema.json").read_text())
    observation_schema = json.loads((ROOT / "contracts/household/vpn-egress-observation.v1.schema.json").read_text())
    decision_schema = json.loads((ROOT / "contracts/household/vpn-egress-route-decision.v1.schema.json").read_text())

    provider = _provider()
    policy = build_vpn_egress_policy(
        base=_composed(),
        provider=provider,
        dns_strategy=DnsStrategy.PROVIDER,
        split_domains=("example.com",),
        kill_switch=True,
        fallback_mode=FallbackMode.DENY,
    )
    observation = _observation()
    decision = evaluate_vpn_route(policy=policy, observation=observation, domain="api.example.com")

    jsonschema.Draft202012Validator(provider_schema).validate(provider.to_dict())
    jsonschema.Draft202012Validator(policy_schema).validate(policy.to_dict())
    jsonschema.Draft202012Validator(observation_schema).validate(observation.to_dict())
    jsonschema.Draft202012Validator(decision_schema).validate(decision.to_dict())

    assert provider.to_dict()["execution_authorized"] is False
    assert policy.to_dict()["parental_deny_has_priority"] is True
    assert decision.to_dict()["execution_authorized"] is False
