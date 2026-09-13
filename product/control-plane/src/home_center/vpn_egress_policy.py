"""Home Center 0.61 VPN egress policy foundation.

The module is deliberately side-effect free.  It selects and evaluates a
provider-bound VPN egress policy, but never configures routing, DNS, firewall,
a VPN client, a remote provider, or external publication.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable

from .home_services import _identifier
from .household import InternetPolicy
from .household_policy_composer import ComposedPolicy
from .parental_internet_policy import AccessDecision, InternetPolicyDecision, ParentalInternetPolicy
from .util import canonical_json

VPN_PROVIDER_SCHEMA = "home-center.vpn-egress-provider-candidate.v1"
VPN_POLICY_SCHEMA = "home-center.vpn-egress-policy.v1"
VPN_OBSERVATION_SCHEMA = "home-center.vpn-egress-observation.v1"
VPN_ROUTE_DECISION_SCHEMA = "home-center.vpn-egress-route-decision.v1"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}\Z")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class VpnEgressPolicyError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DnsStrategy(StrEnum):
    PROVIDER = "provider"
    PARENTAL = "parental"
    SYSTEM = "system"


class FallbackMode(StrEnum):
    DENY = "deny"
    DIRECT = "direct"


class RouteMode(StrEnum):
    VPN = "vpn"
    DIRECT = "direct"
    DENY = "deny"


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise VpnEgressPolicyError(code)
    return value


def _bounded_int(value: object, low: int, high: int, code: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise VpnEgressPolicyError(code)
    return value


def _version(value: object, code: str) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise VpnEgressPolicyError(code)
    return value


def _domain(value: object) -> str:
    if not isinstance(value, str):
        raise VpnEgressPolicyError("vpn_split_domain_invalid")
    raw = value.strip().rstrip(".").lower()
    try:
        normalized = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise VpnEgressPolicyError("vpn_split_domain_invalid") from exc
    labels = normalized.split(".")
    if not normalized or len(normalized) > 253 or len(labels) < 2:
        raise VpnEgressPolicyError("vpn_split_domain_invalid")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise VpnEgressPolicyError("vpn_split_domain_invalid")
    return normalized


def _domain_matches(domain: str, rule: str) -> bool:
    return domain == rule or domain.endswith("." + rule)


def _dns_strategies(values: object) -> tuple[DnsStrategy, ...]:
    if not isinstance(values, (tuple, list)) or not values or len(values) > len(DnsStrategy):
        raise VpnEgressPolicyError("vpn_provider_dns_strategies_invalid")
    try:
        result = tuple(sorted({DnsStrategy(value) for value in values}, key=lambda item: item.value))
    except (TypeError, ValueError) as exc:
        raise VpnEgressPolicyError("vpn_provider_dns_strategies_invalid") from exc
    if len(result) != len(values):
        raise VpnEgressPolicyError("vpn_provider_dns_strategies_invalid")
    return result


@dataclass(frozen=True, slots=True)
class VpnEgressProviderCandidate:
    provider_id: str
    provider_version: str
    location_id: str
    reachable: bool
    latency_ms: int
    stability_bps: int
    split_routing_supported: bool
    kill_switch_supported: bool
    supported_dns_strategies: tuple[DnsStrategy, ...]
    evidence_sha256: str
    schema: str = field(default=VPN_PROVIDER_SCHEMA, init=False)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "provider_id", _identifier(self.provider_id, "vpn_provider_id_invalid"))
            object.__setattr__(self, "location_id", _identifier(self.location_id, "vpn_location_id_invalid"))
        except (TypeError, ValueError) as exc:
            raise VpnEgressPolicyError(str(exc)) from exc
        object.__setattr__(self, "provider_version", _version(self.provider_version, "vpn_provider_version_invalid"))
        if type(self.reachable) is not bool:
            raise VpnEgressPolicyError("vpn_provider_reachability_invalid")
        object.__setattr__(self, "latency_ms", _bounded_int(self.latency_ms, 0, 5000, "vpn_provider_latency_invalid"))
        object.__setattr__(self, "stability_bps", _bounded_int(self.stability_bps, 0, 10000, "vpn_provider_stability_invalid"))
        if type(self.split_routing_supported) is not bool or type(self.kill_switch_supported) is not bool:
            raise VpnEgressPolicyError("vpn_provider_capabilities_invalid")
        object.__setattr__(self, "supported_dns_strategies", _dns_strategies(self.supported_dns_strategies))
        object.__setattr__(self, "evidence_sha256", _sha256(self.evidence_sha256, "vpn_provider_evidence_invalid"))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "location_id": self.location_id,
            "reachable": self.reachable,
            "latency_ms": self.latency_ms,
            "stability_bps": self.stability_bps,
            "split_routing_supported": self.split_routing_supported,
            "kill_switch_supported": self.kill_switch_supported,
            "supported_dns_strategies": [item.value for item in self.supported_dns_strategies],
            "evidence_sha256": self.evidence_sha256,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class VpnEgressObservation:
    provider_id: str
    provider_version: str
    location_id: str
    reachable: bool
    latency_ms: int
    stability_bps: int
    evidence_sha256: str
    schema: str = field(default=VPN_OBSERVATION_SCHEMA, init=False)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "provider_id", _identifier(self.provider_id, "vpn_observation_provider_invalid"))
            object.__setattr__(self, "location_id", _identifier(self.location_id, "vpn_observation_location_invalid"))
        except (TypeError, ValueError) as exc:
            raise VpnEgressPolicyError(str(exc)) from exc
        object.__setattr__(self, "provider_version", _version(self.provider_version, "vpn_observation_provider_version_invalid"))
        if type(self.reachable) is not bool:
            raise VpnEgressPolicyError("vpn_observation_reachability_invalid")
        object.__setattr__(self, "latency_ms", _bounded_int(self.latency_ms, 0, 5000, "vpn_observation_latency_invalid"))
        object.__setattr__(self, "stability_bps", _bounded_int(self.stability_bps, 0, 10000, "vpn_observation_stability_invalid"))
        object.__setattr__(self, "evidence_sha256", _sha256(self.evidence_sha256, "vpn_observation_evidence_invalid"))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "location_id": self.location_id,
            "reachable": self.reachable,
            "latency_ms": self.latency_ms,
            "stability_bps": self.stability_bps,
            "evidence_sha256": self.evidence_sha256,
            "read_only": True,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class VpnEgressPolicy:
    policy_id: str
    household_id: str
    member_id: str
    base_policy_id: str
    base_policy_sha256: str
    parental_policy_id: str | None
    parental_policy_sha256: str | None
    provider_id: str
    provider_version: str
    provider_evidence_sha256: str
    location_id: str
    dns_strategy: DnsStrategy
    split_domains: tuple[str, ...]
    kill_switch: bool
    fallback_mode: FallbackMode
    max_latency_ms: int
    min_stability_bps: int
    schema: str = field(default=VPN_POLICY_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "base_policy_id": self.base_policy_id,
            "base_policy_sha256": self.base_policy_sha256,
            "parental_policy_id": self.parental_policy_id,
            "parental_policy_sha256": self.parental_policy_sha256,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "location_id": self.location_id,
            "dns_strategy": self.dns_strategy.value,
            "split_domains": list(self.split_domains),
            "kill_switch": self.kill_switch,
            "fallback_mode": self.fallback_mode.value,
            "max_latency_ms": self.max_latency_ms,
            "min_stability_bps": self.min_stability_bps,
            "parental_deny_has_priority": True,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class VpnRouteDecision:
    policy_id: str
    route: RouteMode
    reason: str
    provider_id: str | None
    location_id: str | None
    dns_strategy: DnsStrategy | None
    observation_evidence_sha256: str | None
    schema: str = field(default=VPN_ROUTE_DECISION_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "route": self.route.value,
            "reason": self.reason,
            "provider_id": self.provider_id,
            "location_id": self.location_id,
            "dns_strategy": None if self.dns_strategy is None else self.dns_strategy.value,
            "observation_evidence_sha256": self.observation_evidence_sha256,
            "parental_deny_has_priority": True,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def select_vpn_egress_provider(
    candidates: Iterable[VpnEgressProviderCandidate],
    *,
    location_id: str,
    dns_strategy: DnsStrategy,
    split_routing: bool,
    kill_switch: bool,
    max_latency_ms: int,
    min_stability_bps: int,
) -> VpnEgressProviderCandidate:
    """Select deterministic current evidence without authorizing execution."""
    try:
        location = _identifier(location_id, "vpn_location_id_invalid")
    except (TypeError, ValueError) as exc:
        raise VpnEgressPolicyError("vpn_location_id_invalid") from exc
    if not isinstance(dns_strategy, DnsStrategy):
        raise VpnEgressPolicyError("vpn_dns_strategy_invalid")
    max_latency = _bounded_int(max_latency_ms, 1, 5000, "vpn_max_latency_invalid")
    min_stability = _bounded_int(min_stability_bps, 0, 10000, "vpn_min_stability_invalid")
    if type(split_routing) is not bool or type(kill_switch) is not bool:
        raise VpnEgressPolicyError("vpn_selection_capability_invalid")

    eligible = []
    for candidate in candidates:
        if not isinstance(candidate, VpnEgressProviderCandidate):
            raise VpnEgressPolicyError("vpn_provider_candidate_invalid")
        if candidate.location_id != location or not candidate.reachable:
            continue
        if candidate.latency_ms > max_latency or candidate.stability_bps < min_stability:
            continue
        if dns_strategy not in candidate.supported_dns_strategies:
            continue
        if split_routing and not candidate.split_routing_supported:
            continue
        if kill_switch and not candidate.kill_switch_supported:
            continue
        eligible.append(candidate)
    if not eligible:
        raise VpnEgressPolicyError("vpn_provider_unavailable")
    eligible.sort(
        key=lambda item: (
            item.latency_ms,
            -item.stability_bps,
            item.provider_id,
            item.provider_version,
            item.evidence_sha256,
        )
    )
    return eligible[0]


def build_vpn_egress_policy(
    *,
    base: ComposedPolicy,
    provider: VpnEgressProviderCandidate,
    dns_strategy: DnsStrategy,
    split_domains: Iterable[str] = (),
    kill_switch: bool = True,
    fallback_mode: FallbackMode = FallbackMode.DENY,
    max_latency_ms: int = 500,
    min_stability_bps: int = 9500,
    parental_policy: ParentalInternetPolicy | None = None,
) -> VpnEgressPolicy:
    if not isinstance(base, ComposedPolicy) or not isinstance(provider, VpnEgressProviderCandidate):
        raise TypeError("vpn_policy_input_invalid")
    if not base.vpn_allowed:
        raise VpnEgressPolicyError("vpn_not_allowed_by_effective_policy")
    if not isinstance(dns_strategy, DnsStrategy) or not isinstance(fallback_mode, FallbackMode):
        raise VpnEgressPolicyError("vpn_policy_mode_invalid")
    if type(kill_switch) is not bool:
        raise VpnEgressPolicyError("vpn_kill_switch_invalid")
    max_latency = _bounded_int(max_latency_ms, 1, 5000, "vpn_max_latency_invalid")
    min_stability = _bounded_int(min_stability_bps, 0, 10000, "vpn_min_stability_invalid")

    try:
        domains = tuple(sorted({_domain(value) for value in split_domains}))
    except TypeError as exc:
        raise VpnEgressPolicyError("vpn_split_domains_invalid") from exc
    if len(domains) > 256:
        raise VpnEgressPolicyError("vpn_split_domains_invalid")
    if domains and not provider.split_routing_supported:
        raise VpnEgressPolicyError("vpn_split_routing_not_supported")
    if kill_switch and not provider.kill_switch_supported:
        raise VpnEgressPolicyError("vpn_kill_switch_not_supported")
    if kill_switch and fallback_mode is not FallbackMode.DENY:
        raise VpnEgressPolicyError("vpn_kill_switch_fallback_conflict")
    if dns_strategy not in provider.supported_dns_strategies:
        raise VpnEgressPolicyError("vpn_dns_strategy_not_supported")
    if dns_strategy is DnsStrategy.SYSTEM and base.internet_policy is not InternetPolicy.FULL:
        raise VpnEgressPolicyError("vpn_system_dns_would_bypass_filtering")
    if not provider.reachable or provider.latency_ms > max_latency or provider.stability_bps < min_stability:
        raise VpnEgressPolicyError("vpn_provider_not_healthy_enough")

    parental_id: str | None = None
    parental_sha: str | None = None
    base_sha = _digest(base.to_dict())
    if parental_policy is not None:
        if not isinstance(parental_policy, ParentalInternetPolicy):
            raise VpnEgressPolicyError("vpn_parental_policy_invalid")
        if (
            parental_policy.household_id != base.household_id
            or parental_policy.member_id != base.member_id
            or parental_policy.base_policy_id != base.policy_id
            or parental_policy.base_policy_sha256 != base_sha
        ):
            raise VpnEgressPolicyError("vpn_parental_policy_binding_mismatch")
        parental_id = parental_policy.policy_id
        parental_sha = _digest(parental_policy.to_dict())
        if not kill_switch or fallback_mode is not FallbackMode.DENY:
            raise VpnEgressPolicyError("vpn_parental_policy_requires_fail_closed_egress")
        if dns_strategy is DnsStrategy.SYSTEM:
            raise VpnEgressPolicyError("vpn_parental_policy_requires_controlled_dns")
    elif base.internet_policy is not InternetPolicy.FULL:
        raise VpnEgressPolicyError("vpn_filtered_policy_requires_parental_binding")

    canonical = {
        "household_id": base.household_id,
        "member_id": base.member_id,
        "base_policy_id": base.policy_id,
        "base_policy_sha256": base_sha,
        "parental_policy_id": parental_id,
        "parental_policy_sha256": parental_sha,
        "provider_id": provider.provider_id,
        "provider_version": provider.provider_version,
        "provider_evidence_sha256": provider.evidence_sha256,
        "location_id": provider.location_id,
        "dns_strategy": dns_strategy.value,
        "split_domains": list(domains),
        "kill_switch": kill_switch,
        "fallback_mode": fallback_mode.value,
        "max_latency_ms": max_latency,
        "min_stability_bps": min_stability,
        "parental_deny_has_priority": True,
    }
    return VpnEgressPolicy(
        policy_id="hcvpn-" + _digest(canonical)[:24],
        household_id=base.household_id,
        member_id=base.member_id,
        base_policy_id=base.policy_id,
        base_policy_sha256=base_sha,
        parental_policy_id=parental_id,
        parental_policy_sha256=parental_sha,
        provider_id=provider.provider_id,
        provider_version=provider.provider_version,
        provider_evidence_sha256=provider.evidence_sha256,
        location_id=provider.location_id,
        dns_strategy=dns_strategy,
        split_domains=domains,
        kill_switch=kill_switch,
        fallback_mode=fallback_mode,
        max_latency_ms=max_latency,
        min_stability_bps=min_stability,
    )


def evaluate_vpn_route(
    *,
    policy: VpnEgressPolicy,
    observation: VpnEgressObservation,
    domain: str | None = None,
    parental_decision: InternetPolicyDecision | None = None,
) -> VpnRouteDecision:
    if not isinstance(policy, VpnEgressPolicy) or not isinstance(observation, VpnEgressObservation):
        raise TypeError("vpn_route_input_invalid")

    def out(route: RouteMode, reason: str, *, provider: bool = False) -> VpnRouteDecision:
        return VpnRouteDecision(
            policy_id=policy.policy_id,
            route=route,
            reason=reason,
            provider_id=policy.provider_id if provider else None,
            location_id=policy.location_id if provider else None,
            dns_strategy=policy.dns_strategy if provider else None,
            observation_evidence_sha256=observation.evidence_sha256,
        )

    if policy.parental_policy_id is not None:
        if not isinstance(parental_decision, InternetPolicyDecision):
            return out(RouteMode.DENY, "parental_decision_required")
        if parental_decision.policy_id != policy.parental_policy_id:
            return out(RouteMode.DENY, "parental_decision_binding_mismatch")
        if parental_decision.decision is AccessDecision.DENY:
            return out(RouteMode.DENY, "parental_deny")
        if parental_decision.decision is not AccessDecision.ALLOW:
            return out(RouteMode.DENY, "parental_decision_unknown")

    if (
        observation.provider_id != policy.provider_id
        or observation.provider_version != policy.provider_version
        or observation.location_id != policy.location_id
    ):
        return out(RouteMode.DENY, "provider_observation_binding_mismatch")

    healthy = (
        observation.reachable
        and observation.latency_ms <= policy.max_latency_ms
        and observation.stability_bps >= policy.min_stability_bps
    )
    if not healthy:
        if policy.kill_switch or policy.fallback_mode is FallbackMode.DENY:
            return out(RouteMode.DENY, "vpn_unhealthy_fail_closed")
        return out(RouteMode.DIRECT, "vpn_unhealthy_direct_fallback")

    if policy.split_domains:
        if domain is None:
            return out(RouteMode.DENY, "split_route_domain_required")
        try:
            normalized = _domain(domain)
        except VpnEgressPolicyError:
            return out(RouteMode.DENY, "split_route_domain_invalid")
        if not any(_domain_matches(normalized, rule) for rule in policy.split_domains):
            # A split-route non-match is a request to leave the VPN path. It
            # may use direct egress only when the policy explicitly permits
            # direct fallback. A kill-switch/deny policy must never leak
            # traffic to direct egress merely because the domain is outside
            # the VPN split set.
            if not policy.kill_switch and policy.fallback_mode is FallbackMode.DIRECT:
                return out(RouteMode.DIRECT, "split_route_direct")
            return out(RouteMode.DENY, "split_route_direct_not_authorized")

    return out(RouteMode.VPN, "vpn_route_selected", provider=True)