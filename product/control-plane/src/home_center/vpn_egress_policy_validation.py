"""Strict reconstruction of Home Center 0.61 VPN egress evidence objects."""
from __future__ import annotations

from .home_services import _identifier
from .vpn_egress_policy import (
    DnsStrategy,
    FallbackMode,
    RouteMode,
    VPN_OBSERVATION_SCHEMA,
    VPN_POLICY_SCHEMA,
    VPN_PROVIDER_SCHEMA,
    VPN_ROUTE_DECISION_SCHEMA,
    VpnEgressObservation,
    VpnEgressPolicy,
    VpnEgressPolicyError,
    VpnEgressProviderCandidate,
    VpnRouteDecision,
    _digest,
    _domain,
    _sha256,
    _version,
)


class VpnEgressEvidenceValidationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _exact(value: object, keys: set[str], schema: str, code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys or value.get("schema") != schema:
        raise VpnEgressEvidenceValidationError(code)
    return value


def _false_authority(value: dict[str, object], code: str) -> None:
    if (
        value.get("execution_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise VpnEgressEvidenceValidationError(code)


def provider_candidate_from_dict(value: object) -> VpnEgressProviderCandidate:
    raw = _exact(
        value,
        {
            "schema", "provider_id", "provider_version", "location_id", "reachable", "latency_ms",
            "stability_bps", "split_routing_supported", "kill_switch_supported",
            "supported_dns_strategies", "evidence_sha256", "execution_authorized",
            "infrastructure_mutation_authorized", "external_publication_authorized",
        },
        VPN_PROVIDER_SCHEMA,
        "vpn_provider_candidate_rejected",
    )
    _false_authority(raw, "vpn_provider_candidate_rejected")
    try:
        strategies = raw["supported_dns_strategies"]
        if not isinstance(strategies, list):
            raise TypeError
        result = VpnEgressProviderCandidate(
            provider_id=raw["provider_id"],
            provider_version=raw["provider_version"],
            location_id=raw["location_id"],
            reachable=raw["reachable"],
            latency_ms=raw["latency_ms"],
            stability_bps=raw["stability_bps"],
            split_routing_supported=raw["split_routing_supported"],
            kill_switch_supported=raw["kill_switch_supported"],
            supported_dns_strategies=tuple(DnsStrategy(item) for item in strategies),
            evidence_sha256=raw["evidence_sha256"],
        )
    except (KeyError, TypeError, ValueError, VpnEgressPolicyError) as exc:
        raise VpnEgressEvidenceValidationError("vpn_provider_candidate_rejected") from exc
    if result.to_dict() != raw:
        raise VpnEgressEvidenceValidationError("vpn_provider_candidate_rejected")
    return result


def observation_from_dict(value: object) -> VpnEgressObservation:
    raw = _exact(
        value,
        {
            "schema", "provider_id", "provider_version", "location_id", "reachable", "latency_ms",
            "stability_bps", "evidence_sha256", "read_only", "execution_authorized",
            "infrastructure_mutation_authorized", "external_publication_authorized",
        },
        VPN_OBSERVATION_SCHEMA,
        "vpn_observation_rejected",
    )
    _false_authority(raw, "vpn_observation_rejected")
    if raw.get("read_only") is not True:
        raise VpnEgressEvidenceValidationError("vpn_observation_rejected")
    try:
        result = VpnEgressObservation(
            provider_id=raw["provider_id"],
            provider_version=raw["provider_version"],
            location_id=raw["location_id"],
            reachable=raw["reachable"],
            latency_ms=raw["latency_ms"],
            stability_bps=raw["stability_bps"],
            evidence_sha256=raw["evidence_sha256"],
        )
    except (KeyError, TypeError, ValueError, VpnEgressPolicyError) as exc:
        raise VpnEgressEvidenceValidationError("vpn_observation_rejected") from exc
    if result.to_dict() != raw:
        raise VpnEgressEvidenceValidationError("vpn_observation_rejected")
    return result


def policy_from_dict(value: object) -> VpnEgressPolicy:
    raw = _exact(
        value,
        {
            "schema", "policy_id", "household_id", "member_id", "base_policy_id", "base_policy_sha256",
            "parental_policy_id", "parental_policy_sha256", "provider_id", "provider_version",
            "provider_evidence_sha256", "location_id", "dns_strategy", "split_domains", "kill_switch",
            "fallback_mode", "max_latency_ms", "min_stability_bps", "parental_deny_has_priority",
            "execution_authorized", "infrastructure_mutation_authorized", "external_publication_authorized",
        },
        VPN_POLICY_SCHEMA,
        "vpn_policy_rejected",
    )
    _false_authority(raw, "vpn_policy_rejected")
    if raw.get("parental_deny_has_priority") is not True:
        raise VpnEgressEvidenceValidationError("vpn_policy_rejected")
    try:
        household_id = _identifier(raw["household_id"], "vpn_household_id_invalid")
        member_id = _identifier(raw["member_id"], "vpn_member_id_invalid")
        base_policy_id = _identifier(raw["base_policy_id"], "vpn_base_policy_id_invalid")
        provider_id = _identifier(raw["provider_id"], "vpn_provider_id_invalid")
        location_id = _identifier(raw["location_id"], "vpn_location_id_invalid")
        base_sha = _sha256(raw["base_policy_sha256"], "vpn_base_policy_sha256_invalid")
        provider_sha = _sha256(raw["provider_evidence_sha256"], "vpn_provider_evidence_invalid")
        provider_version = _version(raw["provider_version"], "vpn_provider_version_invalid")
        dns_strategy = DnsStrategy(raw["dns_strategy"])
        fallback_mode = FallbackMode(raw["fallback_mode"])
        split_raw = raw["split_domains"]
        if not isinstance(split_raw, list) or len(split_raw) > 256:
            raise TypeError
        split_domains = tuple(sorted({_domain(item) for item in split_raw}))
        if len(split_domains) != len(split_raw):
            raise ValueError
        kill_switch = raw["kill_switch"]
        if type(kill_switch) is not bool:
            raise TypeError
        max_latency = raw["max_latency_ms"]
        min_stability = raw["min_stability_bps"]
        if type(max_latency) is not int or not 1 <= max_latency <= 5000:
            raise ValueError
        if type(min_stability) is not int or not 0 <= min_stability <= 10000:
            raise ValueError
        parental_id = raw["parental_policy_id"]
        parental_sha = raw["parental_policy_sha256"]
        if (parental_id is None) != (parental_sha is None):
            raise ValueError
        if parental_id is not None:
            if not isinstance(parental_id, str) or not parental_id.startswith("hcip-") or len(parental_id) != 29:
                raise ValueError
            _sha256(parental_sha, "vpn_parental_policy_sha256_invalid")
            if not kill_switch or fallback_mode is not FallbackMode.DENY or dns_strategy is DnsStrategy.SYSTEM:
                raise ValueError
        if kill_switch and fallback_mode is not FallbackMode.DENY:
            raise ValueError
    except (KeyError, TypeError, ValueError, VpnEgressPolicyError) as exc:
        raise VpnEgressEvidenceValidationError("vpn_policy_rejected") from exc

    canonical = {
        "household_id": household_id,
        "member_id": member_id,
        "base_policy_id": base_policy_id,
        "base_policy_sha256": base_sha,
        "parental_policy_id": parental_id,
        "parental_policy_sha256": parental_sha,
        "provider_id": provider_id,
        "provider_version": provider_version,
        "provider_evidence_sha256": provider_sha,
        "location_id": location_id,
        "dns_strategy": dns_strategy.value,
        "split_domains": list(split_domains),
        "kill_switch": kill_switch,
        "fallback_mode": fallback_mode.value,
        "max_latency_ms": max_latency,
        "min_stability_bps": min_stability,
        "parental_deny_has_priority": True,
    }
    expected_policy_id = "hcvpn-" + _digest(canonical)[:24]
    if raw.get("policy_id") != expected_policy_id:
        raise VpnEgressEvidenceValidationError("vpn_policy_rejected")
    result = VpnEgressPolicy(
        policy_id=expected_policy_id,
        household_id=household_id,
        member_id=member_id,
        base_policy_id=base_policy_id,
        base_policy_sha256=base_sha,
        parental_policy_id=parental_id,
        parental_policy_sha256=parental_sha,
        provider_id=provider_id,
        provider_version=provider_version,
        provider_evidence_sha256=provider_sha,
        location_id=location_id,
        dns_strategy=dns_strategy,
        split_domains=split_domains,
        kill_switch=kill_switch,
        fallback_mode=fallback_mode,
        max_latency_ms=max_latency,
        min_stability_bps=min_stability,
    )
    if result.to_dict() != raw:
        raise VpnEgressEvidenceValidationError("vpn_policy_rejected")
    return result


def route_decision_from_dict(value: object) -> VpnRouteDecision:
    raw = _exact(
        value,
        {
            "schema", "policy_id", "route", "reason", "provider_id", "location_id", "dns_strategy",
            "observation_evidence_sha256", "parental_deny_has_priority", "execution_authorized",
            "infrastructure_mutation_authorized", "external_publication_authorized",
        },
        VPN_ROUTE_DECISION_SCHEMA,
        "vpn_route_decision_rejected",
    )
    _false_authority(raw, "vpn_route_decision_rejected")
    if raw.get("parental_deny_has_priority") is not True:
        raise VpnEgressEvidenceValidationError("vpn_route_decision_rejected")
    try:
        policy_id = raw["policy_id"]
        if not isinstance(policy_id, str) or not policy_id.startswith("hcvpn-") or len(policy_id) != 30:
            raise ValueError
        route = RouteMode(raw["route"])
        provider_id = raw["provider_id"]
        location_id = raw["location_id"]
        dns_raw = raw["dns_strategy"]
        dns = None if dns_raw is None else DnsStrategy(dns_raw)
        observation_sha = _sha256(
            raw["observation_evidence_sha256"],
            "vpn_observation_evidence_invalid",
        )
        if route is RouteMode.VPN:
            provider_id = _identifier(provider_id, "vpn_provider_id_invalid")
            location_id = _identifier(location_id, "vpn_location_id_invalid")
            if dns is None or raw.get("reason") != "vpn_route_selected":
                raise ValueError
        else:
            if provider_id is not None or location_id is not None or dns is not None:
                raise ValueError
            reason = raw.get("reason")
            if route is RouteMode.DIRECT:
                if reason not in {"vpn_unhealthy_direct_fallback", "split_route_direct"}:
                    raise ValueError
            elif reason not in {
                "parental_decision_required",
                "parental_decision_binding_mismatch",
                "parental_deny",
                "parental_decision_unknown",
                "provider_observation_binding_mismatch",
                "vpn_unhealthy_fail_closed",
                "split_route_domain_required",
                "split_route_domain_invalid",
                "split_route_direct_not_authorized",
            }:
                raise ValueError
        result = VpnRouteDecision(
            policy_id=policy_id,
            route=route,
            reason=raw["reason"],
            provider_id=provider_id,
            location_id=location_id,
            dns_strategy=dns,
            observation_evidence_sha256=observation_sha,
        )
    except (KeyError, TypeError, ValueError, VpnEgressPolicyError) as exc:
        raise VpnEgressEvidenceValidationError("vpn_route_decision_rejected") from exc
    if result.to_dict() != raw:
        raise VpnEgressEvidenceValidationError("vpn_route_decision_rejected")
    return result