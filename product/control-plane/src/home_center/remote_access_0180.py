"""Plan-only remote-access publication for arbitrary runtime environments."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import StrEnum
ID=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$"); HOST=re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
class RemoteAccessError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
class PublicationMode(StrEnum): REVERSE_PROXY="reverse-proxy"; VPN="vpn"; DIRECT="direct"
@dataclass(frozen=True,slots=True)
class ReadinessSnapshot:
    provider_id:str; mode:PublicationMode; public_hostname:str|None; tls_ready:bool; dns_ready:bool; network_ready:bool; authentication_ready:bool; trusted_proxy_ready:bool=True
    def __post_init__(self)->None:
        if ID.fullmatch(self.provider_id) is None: raise RemoteAccessError("invalid_provider_id")
        if self.public_hostname is not None and HOST.fullmatch(self.public_hostname) is None: raise RemoteAccessError("invalid_public_hostname")
@dataclass(frozen=True,slots=True)
class PublicationIntent:
    intent_id:str; service_id:str; provider_id:str; mode:PublicationMode; hostname:str|None=None; require_tls:bool=True; require_authentication:bool=True
    def __post_init__(self)->None:
        if any(ID.fullmatch(v) is None for v in (self.intent_id,self.service_id,self.provider_id)): raise RemoteAccessError("invalid_intent_identity")
        if self.hostname is not None and HOST.fullmatch(self.hostname) is None: raise RemoteAccessError("invalid_hostname")
@dataclass(frozen=True,slots=True)
class PublicationPlan:
    intent_id:str; service_id:str; state:str; steps:tuple[str,...]; blockers:tuple[str,...]; production_mutation_enabled:bool=False; schema:str=field(default="home-center.remote-access-publication-plan.v1",init=False)
class RemoteAccessPlanner:
    def plan(self,intent:PublicationIntent,snapshot:ReadinessSnapshot)->PublicationPlan:
        blockers=[]
        if intent.provider_id!=snapshot.provider_id: blockers.append("provider_identity_mismatch")
        if intent.mode!=snapshot.mode: blockers.append("publication_mode_mismatch")
        if intent.hostname and snapshot.public_hostname and intent.hostname.casefold()!=snapshot.public_hostname.casefold(): blockers.append("hostname_mismatch")
        if intent.require_tls and not snapshot.tls_ready: blockers.append("tls_not_ready")
        if intent.require_authentication and not snapshot.authentication_ready: blockers.append("authentication_not_ready")
        if not snapshot.network_ready: blockers.append("network_not_ready")
        if intent.hostname and not snapshot.dns_ready: blockers.append("dns_not_ready")
        if intent.mode is PublicationMode.REVERSE_PROXY and not snapshot.trusted_proxy_ready: blockers.append("trusted_proxy_not_ready")
        steps=("validate-readiness","validate-authentication","validate-tls","prepare-publication","health-check","activate-publication")
        return PublicationPlan(intent.intent_id,intent.service_id,"blocked" if blockers else "planned",steps if not blockers else (),tuple(blockers))
