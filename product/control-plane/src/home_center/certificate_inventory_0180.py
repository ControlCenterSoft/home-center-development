"""Secret-free certificate inventory and plan-only batch renewal planning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any


ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
MAX_RECORDS = 4096
MAX_WARNING_DAYS = 365
ITEM_BLOCKERS = frozenset(
    {
        "certificate_not_renewable",
        "issuer_unavailable",
        "service_reload_unsupported",
        "certificate_identity_invalid",
    }
)


class CertificateInventoryError(ValueError):
    """Stable certificate-inventory boundary rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CertificateState(StrEnum):
    VALID = "valid"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    INVALID = "invalid"


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def _aware(value: object) -> bool:
    if not isinstance(value, datetime) or value.tzinfo is None:
        return False
    try:
        return value.utcoffset() is not None
    except (OverflowError, ValueError):
        return False


def _iso8601(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_warning_days(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_WARNING_DAYS:
        raise CertificateInventoryError("invalid_warning_window")
    return value


@dataclass(frozen=True, slots=True)
class CertificateInventoryRecord:
    certificate_id: str
    service_id: str
    issuer_id: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    chain_valid: bool
    name_valid: bool
    renewable: bool

    def __post_init__(self) -> None:
        if any(
            not _valid_id(value)
            for value in (self.certificate_id, self.service_id, self.issuer_id)
        ):
            raise CertificateInventoryError("invalid_identity")
        if not isinstance(self.fingerprint_sha256, str) or FINGERPRINT.fullmatch(
            self.fingerprint_sha256
        ) is None:
            raise CertificateInventoryError("invalid_fingerprint")
        if not _aware(self.not_before) or not _aware(self.not_after):
            raise CertificateInventoryError("invalid_validity_window")
        if self.not_after <= self.not_before:
            raise CertificateInventoryError("invalid_validity_window")
        if any(type(value) is not bool for value in (self.chain_valid, self.name_valid, self.renewable)):
            raise CertificateInventoryError("invalid_certificate_flags")

    def state_at(self, now: datetime, warning_days: int = 30) -> CertificateState:
        if not _aware(now):
            raise CertificateInventoryError("timezone_required")
        warning_days = _validate_warning_days(warning_days)
        if not self.chain_valid or not self.name_valid or now < self.not_before:
            return CertificateState.INVALID
        if self.not_after <= now:
            return CertificateState.EXPIRED
        try:
            warning_boundary = now + timedelta(days=warning_days)
        except OverflowError as exc:
            raise CertificateInventoryError("invalid_evaluation_time") from exc
        if self.not_after <= warning_boundary:
            return CertificateState.EXPIRING
        return CertificateState.VALID

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "service_id": self.service_id,
            "issuer_id": self.issuer_id,
            "fingerprint_sha256": self.fingerprint_sha256,
            "not_before": _iso8601(self.not_before),
            "not_after": _iso8601(self.not_after),
            "chain_valid": self.chain_valid,
            "name_valid": self.name_valid,
            "renewable": self.renewable,
        }


@dataclass(frozen=True, slots=True)
class CertificateInventory:
    observed_at: datetime
    records: tuple[CertificateInventoryRecord, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.certificate-inventory.v1", init=False)

    def __post_init__(self) -> None:
        if not _aware(self.observed_at):
            raise CertificateInventoryError("timezone_required")
        if type(self.records) is not tuple or len(self.records) > MAX_RECORDS:
            raise CertificateInventoryError("invalid_inventory_records")
        if any(not isinstance(record, CertificateInventoryRecord) for record in self.records):
            raise CertificateInventoryError("invalid_inventory_record")
        if len({record.certificate_id for record in self.records}) != len(self.records):
            raise CertificateInventoryError("duplicate_certificate_id")
        if self.production_mutation_enabled is not False:
            raise CertificateInventoryError("production_mutation_forbidden")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "observed_at": _iso8601(self.observed_at),
            "records": [
                record.to_dict()
                for record in sorted(self.records, key=lambda item: item.certificate_id)
            ],
            "production_mutation_enabled": self.production_mutation_enabled,
        }


@dataclass(frozen=True, slots=True)
class RenewalBatchItem:
    certificate_id: str
    service_id: str
    state: CertificateState
    action: str
    blockers: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _valid_id(self.certificate_id) or not _valid_id(self.service_id):
            raise CertificateInventoryError("invalid_batch_item_identity")
        if (
            not isinstance(self.state, CertificateState)
            or self.state is CertificateState.VALID
        ):
            raise CertificateInventoryError("invalid_certificate_state")
        if self.action != "renew":
            raise CertificateInventoryError("invalid_batch_action")
        if type(self.blockers) is not tuple or len(self.blockers) > len(ITEM_BLOCKERS):
            raise CertificateInventoryError("invalid_batch_item_blockers")
        if any(blocker not in ITEM_BLOCKERS for blocker in self.blockers):
            raise CertificateInventoryError("invalid_batch_item_blocker")
        if len(set(self.blockers)) != len(self.blockers):
            raise CertificateInventoryError("duplicate_batch_item_blocker")

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "service_id": self.service_id,
            "state": self.state.value,
            "action": self.action,
            "blockers": list(self.blockers),
        }


@dataclass(frozen=True, slots=True)
class CertificateRenewalBatch:
    batch_id: str
    state: str
    items: tuple[RenewalBatchItem, ...]
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.certificate-renewal-batch.v1", init=False)

    def __post_init__(self) -> None:
        if not _valid_id(self.batch_id):
            raise CertificateInventoryError("invalid_batch_id")
        if self.state not in {"planned", "blocked"}:
            raise CertificateInventoryError("invalid_batch_state")
        if type(self.items) is not tuple or len(self.items) > MAX_RECORDS:
            raise CertificateInventoryError("invalid_batch_items")
        if any(not isinstance(item, RenewalBatchItem) for item in self.items):
            raise CertificateInventoryError("invalid_batch_item")
        if len({item.certificate_id for item in self.items}) != len(self.items):
            raise CertificateInventoryError("duplicate_batch_certificate_id")
        if type(self.blockers) is not tuple or len(self.blockers) > MAX_RECORDS:
            raise CertificateInventoryError("invalid_batch_blockers")
        expected_blockers = tuple(
            f"blocked:{item.certificate_id}" for item in self.items if item.blockers
        )
        if self.blockers != expected_blockers:
            raise CertificateInventoryError("inconsistent_batch_blockers")
        expected_state = "blocked" if expected_blockers else "planned"
        if self.state != expected_state:
            raise CertificateInventoryError("inconsistent_batch_state")
        if self.production_mutation_enabled is not False:
            raise CertificateInventoryError("production_mutation_forbidden")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "batch_id": self.batch_id,
            "state": self.state,
            "items": [item.to_dict() for item in self.items],
            "blockers": list(self.blockers),
            "production_mutation_enabled": self.production_mutation_enabled,
        }


class CertificateInventoryPlanner:
    """Build a deterministic renewal plan without handling keys or certificates."""

    def plan_batch(
        self,
        inventory: CertificateInventory,
        *,
        batch_id: str,
        issuer_availability: dict[str, bool],
        reload_support: dict[str, bool],
        warning_days: int = 30,
    ) -> CertificateRenewalBatch:
        if not isinstance(inventory, CertificateInventory):
            raise CertificateInventoryError("invalid_inventory")
        if not _valid_id(batch_id):
            raise CertificateInventoryError("invalid_batch_id")
        _validate_warning_days(warning_days)
        self._validate_readiness_map(issuer_availability, "invalid_issuer_availability")
        self._validate_readiness_map(reload_support, "invalid_reload_support")

        items: list[RenewalBatchItem] = []
        batch_blockers: list[str] = []
        for record in sorted(inventory.records, key=lambda item: item.certificate_id):
            state = record.state_at(inventory.observed_at, warning_days)
            if state is CertificateState.VALID:
                continue
            blockers: list[str] = []
            if not record.renewable:
                blockers.append("certificate_not_renewable")
            if not issuer_availability.get(record.issuer_id, False):
                blockers.append("issuer_unavailable")
            if not reload_support.get(record.service_id, False):
                blockers.append("service_reload_unsupported")
            if state is CertificateState.INVALID:
                blockers.append("certificate_identity_invalid")
            item = RenewalBatchItem(
                certificate_id=record.certificate_id,
                service_id=record.service_id,
                state=state,
                action="renew",
                blockers=tuple(blockers),
            )
            items.append(item)
            if blockers:
                batch_blockers.append(f"blocked:{record.certificate_id}")
        return CertificateRenewalBatch(
            batch_id=batch_id,
            state="blocked" if batch_blockers else "planned",
            items=tuple(items),
            blockers=tuple(batch_blockers),
        )

    @staticmethod
    def _validate_readiness_map(value: object, code: str) -> None:
        if type(value) is not dict or len(value) > MAX_RECORDS:
            raise CertificateInventoryError(code)
        if any(not _valid_id(key) or type(ready) is not bool for key, ready in value.items()):
            raise CertificateInventoryError(code)
