"""Plan-only remote-access publication for arbitrary runtime environments."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
PLAN_STEPS = (
    "validate-readiness",
    "validate-authentication",
    "validate-tls",
    "prepare-publication",
    "health-check",
    "activate-publication",
)
PLAN_BLOCKERS = frozenset(
    {
        "provider_identity_mismatch",
        "publication_mode_mismatch",
        "public_hostname_unavailable",
        "hostname_mismatch",
        "tls_not_ready",
        "authentication_not_ready",
        "network_not_ready",
        "dns_not_ready",
        "trusted_proxy_not_ready",
    }
)


class RemoteAccessError(ValueError):
    """Stable remote-access boundary rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PublicationMode(StrEnum):
    REVERSE_PROXY = "reverse-proxy"
    VPN = "vpn"
    DIRECT = "direct"


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def _valid_hostname(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or value.endswith("."):
        return False
    labels = value.split(".")
    return all(HOST_LABEL.fullmatch(label) is not None for label in labels)


@dataclass(frozen=True, slots=True)
class ReadinessSnapshot:
    provider_id: str
    mode: PublicationMode
    public_hostname: str | None
    tls_ready: bool
    dns_ready: bool
    network_ready: bool
    authentication_ready: bool
    trusted_proxy_ready: bool = False

    def __post_init__(self) -> None:
        if not _valid_id(self.provider_id):
            raise RemoteAccessError("invalid_provider_id")
        if not isinstance(self.mode, PublicationMode):
            raise RemoteAccessError("invalid_publication_mode")
        if self.public_hostname is not None and not _valid_hostname(self.public_hostname):
            raise RemoteAccessError("invalid_public_hostname")
        flags = (
            self.tls_ready,
            self.dns_ready,
            self.network_ready,
            self.authentication_ready,
            self.trusted_proxy_ready,
        )
        if any(type(value) is not bool for value in flags):
            raise RemoteAccessError("invalid_readiness_flags")


@dataclass(frozen=True, slots=True)
class PublicationIntent:
    intent_id: str
    service_id: str
    provider_id: str
    mode: PublicationMode
    hostname: str | None = None
    require_tls: bool = True
    require_authentication: bool = True

    def __post_init__(self) -> None:
        if any(
            not _valid_id(value)
            for value in (self.intent_id, self.service_id, self.provider_id)
        ):
            raise RemoteAccessError("invalid_intent_identity")
        if not isinstance(self.mode, PublicationMode):
            raise RemoteAccessError("invalid_publication_mode")
        if self.hostname is not None and not _valid_hostname(self.hostname):
            raise RemoteAccessError("invalid_hostname")
        if type(self.require_tls) is not bool or type(self.require_authentication) is not bool:
            raise RemoteAccessError("invalid_security_requirements")
        if not self.require_authentication:
            raise RemoteAccessError("authentication_required")
        if self.mode in {PublicationMode.REVERSE_PROXY, PublicationMode.DIRECT}:
            if self.hostname is None:
                raise RemoteAccessError("hostname_required")
            if not self.require_tls:
                raise RemoteAccessError("tls_required")


@dataclass(frozen=True, slots=True)
class PublicationPlan:
    intent_id: str
    service_id: str
    state: str
    steps: tuple[str, ...]
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(
        default="home-center.remote-access-publication-plan.v1", init=False
    )

    def __post_init__(self) -> None:
        if not _valid_id(self.intent_id) or not _valid_id(self.service_id):
            raise RemoteAccessError("invalid_plan_identity")
        if self.state not in {"planned", "blocked"}:
            raise RemoteAccessError("invalid_plan_state")
        if type(self.steps) is not tuple or type(self.blockers) is not tuple:
            raise RemoteAccessError("invalid_plan_shape")
        if len(self.blockers) > len(PLAN_BLOCKERS):
            raise RemoteAccessError("invalid_plan_blockers")
        if any(blocker not in PLAN_BLOCKERS for blocker in self.blockers):
            raise RemoteAccessError("invalid_plan_blocker")
        if len(set(self.blockers)) != len(self.blockers):
            raise RemoteAccessError("duplicate_plan_blocker")
        if self.state == "planned" and (self.steps != PLAN_STEPS or self.blockers):
            raise RemoteAccessError("inconsistent_plan_state")
        if self.state == "blocked" and (self.steps or not self.blockers):
            raise RemoteAccessError("inconsistent_plan_state")
        if self.production_mutation_enabled is not False:
            raise RemoteAccessError("production_mutation_forbidden")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "intent_id": self.intent_id,
            "service_id": self.service_id,
            "state": self.state,
            "steps": list(self.steps),
            "blockers": list(self.blockers),
            "production_mutation_enabled": self.production_mutation_enabled,
        }


class RemoteAccessPlanner:
    """Evaluate readiness facts and return an immutable, non-executable plan."""

    def plan(
        self, intent: PublicationIntent, snapshot: ReadinessSnapshot
    ) -> PublicationPlan:
        if not isinstance(intent, PublicationIntent):
            raise RemoteAccessError("invalid_publication_intent")
        if not isinstance(snapshot, ReadinessSnapshot):
            raise RemoteAccessError("invalid_readiness_snapshot")

        blockers: list[str] = []
        if intent.provider_id != snapshot.provider_id:
            blockers.append("provider_identity_mismatch")
        if intent.mode != snapshot.mode:
            blockers.append("publication_mode_mismatch")
        if intent.hostname is not None:
            if snapshot.public_hostname is None:
                blockers.append("public_hostname_unavailable")
            elif intent.hostname.casefold() != snapshot.public_hostname.casefold():
                blockers.append("hostname_mismatch")
        if intent.require_tls and not snapshot.tls_ready:
            blockers.append("tls_not_ready")
        if intent.require_authentication and not snapshot.authentication_ready:
            blockers.append("authentication_not_ready")
        if not snapshot.network_ready:
            blockers.append("network_not_ready")
        if intent.hostname is not None and not snapshot.dns_ready:
            blockers.append("dns_not_ready")
        if intent.mode is PublicationMode.REVERSE_PROXY and not snapshot.trusted_proxy_ready:
            blockers.append("trusted_proxy_not_ready")
        return PublicationPlan(
            intent_id=intent.intent_id,
            service_id=intent.service_id,
            state="blocked" if blockers else "planned",
            steps=() if blockers else PLAN_STEPS,
            blockers=tuple(blockers),
        )
