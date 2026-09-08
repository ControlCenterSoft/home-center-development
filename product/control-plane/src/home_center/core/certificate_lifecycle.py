"""Secret-free certificate lifecycle inventory and renewal planning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")

class CertificateLifecycleError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

class CertificateStatus(StrEnum):
    VALID = "valid"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    INVALID = "invalid"

class CertificatePlanState(StrEnum):
    PLANNED = "planned"
    BLOCKED = "blocked"

@dataclass(frozen=True, slots=True)
class CertificateRecord:
    certificate_id: str
    fingerprint_sha256: str
    service_id: str
    not_after: datetime
    chain_valid: bool
    name_valid: bool

    def __post_init__(self) -> None:
        if IDENTIFIER.fullmatch(self.certificate_id) is None or IDENTIFIER.fullmatch(self.service_id) is None:
            raise CertificateLifecycleError("invalid_certificate_identity")
        if FINGERPRINT.fullmatch(self.fingerprint_sha256) is None:
            raise CertificateLifecycleError("invalid_certificate_fingerprint")
        if self.not_after.tzinfo is None:
            raise CertificateLifecycleError("certificate_expiry_must_be_timezone_aware")

@dataclass(frozen=True, slots=True)
class CertificateRenewalPlan:
    certificate_id: str
    service_id: str
    status: CertificateStatus
    state: CertificatePlanState
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.certificate-renewal-plan.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {"schema": self.schema, "certificate_id": self.certificate_id, "service_id": self.service_id, "status": self.status.value, "state": self.state.value, "blockers": list(self.blockers), "production_mutation_enabled": self.production_mutation_enabled}

def classify_certificate(record: CertificateRecord, *, now: datetime, warning_days: int = 30) -> CertificateStatus:
    if now.tzinfo is None:
        raise CertificateLifecycleError("current_time_must_be_timezone_aware")
    if not isinstance(warning_days, int) or isinstance(warning_days, bool) or not 1 <= warning_days <= 365:
        raise CertificateLifecycleError("invalid_certificate_warning_window")
    if not record.chain_valid or not record.name_valid:
        return CertificateStatus.INVALID
    if record.not_after <= now:
        return CertificateStatus.EXPIRED
    if record.not_after <= now + timedelta(days=warning_days):
        return CertificateStatus.EXPIRING
    return CertificateStatus.VALID

class CertificateLifecyclePlanner:
    def plan_renewal(self, record: CertificateRecord, *, now: datetime, issuer_available: bool, service_reload_supported: bool, warning_days: int = 30) -> CertificateRenewalPlan:
        status = classify_certificate(record, now=now, warning_days=warning_days)
        blockers: list[str] = []
        if not issuer_available:
            blockers.append("certificate_issuer_unavailable")
        if not service_reload_supported:
            blockers.append("certificate_service_reload_unsupported")
        if status is CertificateStatus.INVALID:
            blockers.append("certificate_identity_invalid")
        if status is CertificateStatus.VALID:
            blockers.append("certificate_renewal_not_required")
        return CertificateRenewalPlan(certificate_id=record.certificate_id, service_id=record.service_id, status=status, state=CertificatePlanState.BLOCKED if blockers else CertificatePlanState.PLANNED, blockers=tuple(blockers))
