"""Transport-neutral UI projections for Home Center 0.61 VPN egress decisions.

The projections accept only server-produced route decisions.  They do not accept
provider observations or policy evidence from a client and grant no execution
authority.
"""
from __future__ import annotations

import re

from .vpn_egress_policy import DnsStrategy, RouteMode, VpnRouteDecision

COZY_VPN_ROUTE_SCHEMA = "home-center.cozy-vpn-egress-route.v1"
FULL_VPN_ROUTE_SCHEMA = "home-center.full-vpn-egress-route.v1"
_POLICY_ID = re.compile(r"hcvpn-[0-9a-f]{24}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class VpnEgressPolicyAPIError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_REASON_TEXT = {
    "parental_decision_required": (
        "Доступ временно закрыт",
        "Не удалось подтвердить актуальное семейное правило. Доступ закрыт безопасно.",
    ),
    "parental_decision_binding_mismatch": (
        "Доступ временно закрыт",
        "Семейное правило относится к другому состоянию. Доступ закрыт безопасно.",
    ),
    "parental_deny": (
        "Доступ запрещён семейным правилом",
        "VPN не обходит более строгое семейное ограничение.",
    ),
    "parental_decision_unknown": (
        "Доступ временно закрыт",
        "Результат семейного правила не удалось подтвердить.",
    ),
    "provider_observation_binding_mismatch": (
        "VPN временно недоступен",
        "Текущее состояние VPN относится к другой конфигурации.",
    ),
    "vpn_unhealthy_fail_closed": (
        "VPN временно недоступен",
        "Безопасный режим блокирует доступ, пока VPN не восстановится.",
    ),
    "vpn_unhealthy_direct_fallback": (
        "VPN временно недоступен",
        "Политика разрешает временный прямой доступ без VPN.",
    ),
    "split_route_domain_required": (
        "Не удалось выбрать маршрут",
        "Для split routing не хватает адреса назначения. Доступ закрыт безопасно.",
    ),
    "split_route_domain_invalid": (
        "Не удалось выбрать маршрут",
        "Адрес назначения не прошёл проверку. Доступ закрыт безопасно.",
    ),
    "split_route_direct": (
        "Прямое подключение",
        "Для этого адреса политика использует прямой маршрут.",
    ),
    "split_route_direct_not_authorized": (
        "Прямой маршрут запрещён",
        "Адрес не входит в VPN split-набор, но политика не разрешает прямой выход. Доступ закрыт безопасно.",
    ),
    "vpn_route_selected": (
        "VPN выбран",
        "Политика выбрала VPN-маршрут. Фактическое применение проверяется отдельно.",
    ),
}


def _validate(decision: VpnRouteDecision) -> None:
    if not isinstance(decision, VpnRouteDecision):
        raise TypeError("invalid_vpn_route_decision")
    if not _POLICY_ID.fullmatch(decision.policy_id) or decision.reason not in _REASON_TEXT:
        raise VpnEgressPolicyAPIError("invalid_vpn_route_decision")
    if not isinstance(decision.route, RouteMode):
        raise VpnEgressPolicyAPIError("invalid_vpn_route_decision")
    if decision.observation_evidence_sha256 is not None and not _SHA256.fullmatch(decision.observation_evidence_sha256):
        raise VpnEgressPolicyAPIError("invalid_vpn_route_decision")
    if decision.route is RouteMode.VPN:
        if (
            not decision.provider_id
            or not decision.location_id
            or not isinstance(decision.dns_strategy, DnsStrategy)
            or decision.reason != "vpn_route_selected"
        ):
            raise VpnEgressPolicyAPIError("invalid_vpn_route_decision")
    elif decision.provider_id is not None or decision.location_id is not None or decision.dns_strategy is not None:
        raise VpnEgressPolicyAPIError("invalid_vpn_route_decision")


def cozy_vpn_route_projection(decision: VpnRouteDecision) -> dict[str, object]:
    _validate(decision)
    title, explanation = _REASON_TEXT[decision.reason]
    return {
        "schema": COZY_VPN_ROUTE_SCHEMA,
        "policy_id": decision.policy_id,
        "route": decision.route.value,
        "reason": decision.reason,
        "title": title,
        "explanation": explanation,
        "active_state_verified": False,
        "parental_deny_has_priority": True,
        "execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def full_vpn_route_projection(decision: VpnRouteDecision) -> dict[str, object]:
    _validate(decision)
    return {
        "schema": FULL_VPN_ROUTE_SCHEMA,
        "decision": decision.to_dict(),
        "active_state_verified": False,
        "parental_deny_has_priority": True,
        "execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
