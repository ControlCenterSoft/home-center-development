"""Secret-free certificate lifecycle inventory and renewal planning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum

FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")

class CertificateLifecycleError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

class CertificateStatus(StrEnum):
    VALID = "valid"
    RENEWAL_DUE = "renewal_due"
    # Compatibility alias for callers compiled against the original 0.14
    # planning foundation. New serialized contracts use ``renewal_due``.
    EXPIRING = "renewal_due"
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
        if not isinstance(self.certificate_id, str) or not isinstance(self.service_id, str):
            raise CertificateLifecycleError("invalid_certificate_identity")
        if IDENTIFIER.fullmatch(self.certificate_id) is None or IDENTIFIER.fullmatch(self.service_id) is None:
            raise CertificateLifecycleError("invalid_certificate_identity")
        if not isinstance(self.fingerprint_sha256, str):
            raise CertificateLifecycleError("invalid_certificate_fingerprint")
        if FINGERPRINT.fullmatch(self.fingerprint_sha256) is None:
            raise CertificateLifecycleError("invalid_certificate_fingerprint")
        if not isinstance(self.not_after, datetime):
            raise CertificateLifecycleError("certificate_expiry_must_be_timezone_aware")
        try:
            offset = self.not_after.utcoffset()
        except (OverflowError, ValueError) as exc:
            raise CertificateLifecycleError("certificate_expiry_must_be_timezone_aware") from exc
        if offset is None:
            raise CertificateLifecycleError("certificate_expiry_must_be_timezone_aware")
        if not isinstance(self.chain_valid, bool) or not isinstance(self.name_valid, bool):
            raise CertificateLifecycleError("invalid_certificate_validation_state")
        try:
            normalized = self.not_after.astimezone(timezone.utc).replace(microsecond=0)
        except (OverflowError, ValueError) as exc:
            raise CertificateLifecycleError("certificate_expiry_must_be_timezone_aware") from exc
        object.__setattr__(self, "not_after", normalized)

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
    if not isinstance(record, CertificateRecord):
        raise CertificateLifecycleError("invalid_certificate_record")
    if not isinstance(now, datetime):
        raise CertificateLifecycleError("current_time_must_be_timezone_aware")
    try:
        offset = now.utcoffset()
    except (OverflowError, ValueError) as exc:
        raise CertificateLifecycleError("current_time_must_be_timezone_aware") from exc
    if offset is None:
        raise CertificateLifecycleError("current_time_must_be_timezone_aware")
    if not isinstance(warning_days, int) or isinstance(warning_days, bool) or not 1 <= warning_days <= 365:
        raise CertificateLifecycleError("invalid_certificate_warning_window")
    try:
        evaluated_at = now.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise CertificateLifecycleError("current_time_must_be_timezone_aware") from exc
    if record.not_after <= evaluated_at:
        return CertificateStatus.EXPIRED
    if not record.chain_valid or not record.name_valid:
        return CertificateStatus.INVALID
    try:
        renewal_threshold = evaluated_at + timedelta(days=warning_days)
    except OverflowError as exc:
        raise CertificateLifecycleError("invalid_certificate_evaluation_window") from exc
    if record.not_after <= renewal_threshold:
        return CertificateStatus.RENEWAL_DUE
    return CertificateStatus.VALID

class CertificateLifecyclePlanner:
    def plan_renewal(self, record: CertificateRecord, *, now: datetime, issuer_available: bool, service_reload_supported: bool, warning_days: int = 30) -> CertificateRenewalPlan:
        if not isinstance(issuer_available, bool):
            raise CertificateLifecycleError("invalid_certificate_issuer_availability")
        if not isinstance(service_reload_supported, bool):
            raise CertificateLifecycleError("invalid_certificate_service_reload_capability")
        status = classify_certificate(record, now=now, warning_days=warning_days)
        blockers: list[str] = []
        if not issuer_available:
            blockers.append("certificate_issuer_unavailable")
        if not service_reload_supported:
            blockers.append("certificate_service_reload_unsupported")
        if not record.chain_valid or not record.name_valid:
            blockers.append("certificate_identity_invalid")
        if status is CertificateStatus.VALID:
            blockers.append("certificate_renewal_not_required")
        return CertificateRenewalPlan(certificate_id=record.certificate_id, service_id=record.service_id, status=status, state=CertificatePlanState.BLOCKED if blockers else CertificatePlanState.PLANNED, blockers=tuple(blockers))
