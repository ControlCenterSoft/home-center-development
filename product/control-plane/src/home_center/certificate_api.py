"""Authenticated, secret-free certificate inventory and renewal planning."""

from __future__ import annotations

import hashlib
import json
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable, Final, Iterable, Mapping

from .core.certificate_lifecycle import (
    CertificateLifecycleError,
    CertificateLifecyclePlanner,
    CertificatePlanState,
    CertificateRecord,
    CertificateStatus,
    classify_certificate,
)
from .tls_status import status as tls_status


DEFAULT_WARNING_DAYS: Final = 30
MAX_CERTIFICATES: Final = 128
RFC3339_SECONDS: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


class CertificateApiError(ValueError):
    """Stable, bounded rejection code for the certificate API boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CertificateInventoryUnavailable(RuntimeError):
    code = "certificate_inventory_unavailable"


class CertificateNotFound(CertificateApiError):
    def __init__(self) -> None:
        super().__init__("certificate_not_found")


class CertificateApiStatus(StrEnum):
    VALID = "valid"
    RENEWAL_DUE = "renewal_due"
    EXPIRED = "expired"


def _aware_utc(value: datetime, *, code: str) -> datetime:
    if not isinstance(value, datetime):
        raise CertificateApiError(code)
    try:
        offset = value.utcoffset()
    except (OverflowError, ValueError) as exc:
        raise CertificateApiError(code) from exc
    if offset is None:
        raise CertificateApiError(code)
    try:
        return value.astimezone(timezone.utc).replace(microsecond=0)
    except (OverflowError, ValueError) as exc:
        raise CertificateApiError(code) from exc


def _timestamp(value: datetime) -> str:
    return _aware_utc(value, code="invalid_certificate_timestamp").isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or RFC3339_SECONDS.fullmatch(value) is None:
        raise CertificateApiError("invalid_evaluated_at")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
    except ValueError as exc:
        raise CertificateApiError("invalid_evaluated_at") from exc
    return _aware_utc(parsed, code="invalid_evaluated_at")


def _warning_days(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 365:
        raise CertificateApiError("invalid_certificate_warning_window")
    return value


def _api_status(status: CertificateStatus) -> CertificateApiStatus:
    if status is CertificateStatus.VALID:
        return CertificateApiStatus.VALID
    if status is CertificateStatus.EXPIRED:
        return CertificateApiStatus.EXPIRED
    return CertificateApiStatus.RENEWAL_DUE


@dataclass(frozen=True, slots=True)
class CertificateRenewalPolicy:
    certificate_id: str
    evaluated_at: datetime
    warning_days: int
    issuer_available: bool
    service_reload_supported: bool
    mode: str = "plan"
    schema: str = field(default="home-center.certificate-renewal-policy.v1", init=False)

    def __post_init__(self) -> None:
        # Constructing a minimal record reuses the core identity validator and
        # avoids a second, subtly different certificate identifier grammar.
        try:
            CertificateRecord(
                certificate_id=self.certificate_id,
                fingerprint_sha256="0" * 64,
                service_id="validation",
                not_after=datetime(2000, 1, 1, tzinfo=timezone.utc),
                chain_valid=True,
                name_valid=True,
            )
        except CertificateLifecycleError as exc:
            raise CertificateApiError(exc.code) from exc
        object.__setattr__(self, "evaluated_at", _aware_utc(self.evaluated_at, code="invalid_evaluated_at"))
        object.__setattr__(self, "warning_days", _warning_days(self.warning_days))
        if not isinstance(self.issuer_available, bool):
            raise CertificateApiError("invalid_issuer_availability")
        if not isinstance(self.service_reload_supported, bool):
            raise CertificateApiError("invalid_service_reload_capability")
        if self.mode != "plan":
            raise CertificateApiError("certificate_execution_not_available")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CertificateRenewalPolicy":
        required = {
            "schema",
            "certificate_id",
            "evaluated_at",
            "warning_days",
            "issuer_available",
            "service_reload_supported",
            "mode",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise CertificateApiError("invalid_certificate_policy_envelope")
        if value.get("schema") != "home-center.certificate-renewal-policy.v1":
            raise CertificateApiError("invalid_certificate_policy_envelope")
        return cls(
            certificate_id=value["certificate_id"],
            evaluated_at=_parse_timestamp(value["evaluated_at"]),
            warning_days=value["warning_days"],
            issuer_available=value["issuer_available"],
            service_reload_supported=value["service_reload_supported"],
            mode=value["mode"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "certificate_id": self.certificate_id,
            "evaluated_at": _timestamp(self.evaluated_at),
            "warning_days": self.warning_days,
            "issuer_available": self.issuer_available,
            "service_reload_supported": self.service_reload_supported,
            "mode": self.mode,
        }


class CertificateLifecycleApi:
    """Project local certificate facts onto a bounded plan-only API."""

    def __init__(
        self,
        record_provider: Callable[[], Iterable[CertificateRecord]],
        *,
        clock: Callable[[], datetime] | None = None,
        planner: CertificateLifecyclePlanner | None = None,
    ) -> None:
        self._record_provider = record_provider
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._planner = planner or CertificateLifecyclePlanner()

    def _records(self) -> tuple[CertificateRecord, ...]:
        try:
            supplied = tuple(self._record_provider())
        except Exception as exc:
            raise CertificateInventoryUnavailable from exc
        if len(supplied) > MAX_CERTIFICATES or any(not isinstance(item, CertificateRecord) for item in supplied):
            raise CertificateInventoryUnavailable
        records = tuple(sorted(supplied, key=lambda item: item.certificate_id))
        if len({item.certificate_id for item in records}) != len(records):
            raise CertificateInventoryUnavailable
        return records

    def inventory(self, *, warning_days: int = DEFAULT_WARNING_DAYS) -> dict[str, Any]:
        checked_warning_days = _warning_days(warning_days)
        evaluated_at = _aware_utc(self._clock(), code="invalid_evaluated_at")
        items: list[dict[str, Any]] = []
        for record in self._records():
            try:
                lifecycle_status = classify_certificate(
                    record,
                    now=evaluated_at,
                    warning_days=checked_warning_days,
                )
            except CertificateLifecycleError as exc:
                raise CertificateInventoryUnavailable from exc
            items.append(self._inventory_item(record, lifecycle_status))
        return {
            "schema": "home-center.certificate-inventory.v1",
            "evaluated_at": _timestamp(evaluated_at),
            "warning_days": checked_warning_days,
            "items": items,
            "production_mutation_enabled": False,
        }

    def plan(self, policy: CertificateRenewalPolicy) -> dict[str, Any]:
        if not isinstance(policy, CertificateRenewalPolicy):
            raise CertificateApiError("invalid_certificate_policy_envelope")
        record = next((item for item in self._records() if item.certificate_id == policy.certificate_id), None)
        if record is None:
            raise CertificateNotFound
        try:
            core_plan = self._planner.plan_renewal(
                record,
                now=policy.evaluated_at,
                issuer_available=policy.issuer_available,
                service_reload_supported=policy.service_reload_supported,
                warning_days=policy.warning_days,
            )
        except CertificateLifecycleError as exc:
            raise CertificateApiError(exc.code) from exc

        status = _api_status(core_plan.status)
        blockers = tuple(sorted(set(core_plan.blockers)))
        steps = self._steps(record) if core_plan.state is CertificatePlanState.PLANNED else ()
        plan_body = {
            "certificate_id": record.certificate_id,
            "service_id": record.service_id,
            "fingerprint_sha256": record.fingerprint_sha256,
            "not_after": _timestamp(record.not_after),
            "evaluated_at": _timestamp(policy.evaluated_at),
            "warning_days": policy.warning_days,
            "status": status.value,
            "validation": {
                "chain_valid": record.chain_valid,
                "name_valid": record.name_valid,
            },
            "state": core_plan.state.value,
            "code": "certificate_renewal_planned"
            if core_plan.state is CertificatePlanState.PLANNED
            else "certificate_renewal_blocked",
            "steps": list(steps),
            "blockers": list(blockers),
            "production_execution_enabled": False,
        }
        identity = {"policy": policy.to_dict(), "plan": plan_body}
        plan_id = hashlib.sha256(
            json.dumps(identity, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        ).hexdigest()
        return {
            "schema": "home-center.certificate-renewal-plan.v2",
            "plan_id": plan_id,
            **plan_body,
        }

    @staticmethod
    def _inventory_item(record: CertificateRecord, lifecycle_status: CertificateStatus) -> dict[str, Any]:
        return {
            "schema": "home-center.certificate-inventory-item.v1",
            "certificate_id": record.certificate_id,
            "service_id": record.service_id,
            "fingerprint_sha256": record.fingerprint_sha256,
            "not_after": _timestamp(record.not_after),
            "status": _api_status(lifecycle_status).value,
            "validation": {
                "chain_valid": record.chain_valid,
                "name_valid": record.name_valid,
            },
        }

    @staticmethod
    def _steps(record: CertificateRecord) -> tuple[dict[str, Any], ...]:
        actions = (
            "certificate.request.v1",
            "certificate.validate.v1",
            "certificate.stage.v1",
            "service.reload.v1",
        )
        return tuple(
            {
                "schema": "home-center.certificate-renewal-step.v1",
                "sequence": sequence,
                "action": action,
                "certificate_id": record.certificate_id,
                "service_id": record.service_id,
                "execution_requires_approval": True,
            }
            for sequence, action in enumerate(actions, start=1)
        )


def runtime_certificate_records(config: object) -> tuple[CertificateRecord, ...]:
    """Collect the two runtime TLS identities without exposing key material."""

    try:
        observed = tls_status(config)  # type: ignore[arg-type]
        definitions = (
            ("peer-mtls", "cluster-peer", observed["peer"]),
            ("web-tls", "web-api", observed["web"]),
        )
        records: list[CertificateRecord] = []
        for certificate_id, service_id, item in definitions:
            not_after = item.get("not_after")
            if not isinstance(not_after, str):
                raise ValueError("certificate expiry unavailable")
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
            records.append(
                CertificateRecord(
                    certificate_id=certificate_id,
                    fingerprint_sha256=item.get("fingerprint_sha256"),
                    service_id=service_id,
                    not_after=expires,
                    chain_valid=item.get("chain_valid"),
                    name_valid=bool(
                        item.get("hostname_match")
                        and item.get("san_policy_valid")
                        and item.get("profile_valid")
                    ),
                )
            )
        return tuple(records)
    except (CertificateLifecycleError, KeyError, OSError, TypeError, ValueError, ssl.SSLError) as exc:
        raise CertificateInventoryUnavailable from exc
