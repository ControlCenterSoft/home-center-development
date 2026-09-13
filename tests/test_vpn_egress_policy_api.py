from __future__ import annotations

import pytest

from home_center.vpn_egress_policy import DnsStrategy, RouteMode, VpnRouteDecision
from home_center.vpn_egress_policy_api import (
    VpnEgressPolicyAPIError,
    cozy_vpn_route_projection,
    full_vpn_route_projection,
)

DIGEST = "a" * 64
POLICY_ID = "hcvpn-" + "1" * 24


def _decision(*, route: RouteMode, reason: str) -> VpnRouteDecision:
    provider = route is RouteMode.VPN
    return VpnRouteDecision(
        policy_id=POLICY_ID,
        route=route,
        reason=reason,
        provider_id="provider-a" if provider else None,
        location_id="nl-ams" if provider else None,
        dns_strategy=DnsStrategy.PROVIDER if provider else None,
        observation_evidence_sha256=DIGEST,
    )


def test_cozy_projection_explains_parental_deny_without_provider_details() -> None:
    projection = cozy_vpn_route_projection(_decision(route=RouteMode.DENY, reason="parental_deny"))
    assert projection["route"] == "deny"
    assert projection["title"] == "Доступ запрещён семейным правилом"
    assert projection["parental_deny_has_priority"] is True
    assert projection["active_state_verified"] is False
    assert "provider_id" not in projection


def test_cozy_projection_does_not_claim_vpn_is_active() -> None:
    projection = cozy_vpn_route_projection(_decision(route=RouteMode.VPN, reason="vpn_route_selected"))
    assert projection["route"] == "vpn"
    assert projection["title"] == "VPN выбран"
    assert projection["active_state_verified"] is False
    assert projection["execution_authorized"] is False


def test_cozy_projection_preserves_fail_closed_split_route_denial() -> None:
    projection = cozy_vpn_route_projection(
        _decision(route=RouteMode.DENY, reason="split_route_direct_not_authorized")
    )
    assert projection["route"] == "deny"
    assert projection["reason"] == "split_route_direct_not_authorized"
    assert projection["title"] == "Прямой маршрут запрещён"
    assert "Доступ закрыт безопасно" in projection["explanation"]
    assert projection["active_state_verified"] is False
    assert projection["execution_authorized"] is False


def test_full_projection_preserves_exact_provider_evidence() -> None:
    projection = full_vpn_route_projection(_decision(route=RouteMode.VPN, reason="vpn_route_selected"))
    decision = projection["decision"]
    assert decision["provider_id"] == "provider-a"
    assert decision["location_id"] == "nl-ams"
    assert decision["observation_evidence_sha256"] == DIGEST
    assert projection["active_state_verified"] is False


def test_full_projection_preserves_fail_closed_split_route_denial_reason() -> None:
    projection = full_vpn_route_projection(
        _decision(route=RouteMode.DENY, reason="split_route_direct_not_authorized")
    )
    decision = projection["decision"]
    assert decision["route"] == "deny"
    assert decision["reason"] == "split_route_direct_not_authorized"
    assert decision["provider_id"] is None
    assert decision["location_id"] is None
    assert decision["dns_strategy"] is None
    assert projection["active_state_verified"] is False


def test_invalid_vpn_route_shape_is_rejected() -> None:
    bad = VpnRouteDecision(
        policy_id=POLICY_ID,
        route=RouteMode.DIRECT,
        reason="split_route_direct",
        provider_id="provider-a",
        location_id=None,
        dns_strategy=None,
        observation_evidence_sha256=DIGEST,
    )
    with pytest.raises(VpnEgressPolicyAPIError, match="invalid_vpn_route_decision"):
        cozy_vpn_route_projection(bad)
