"""Exact-state revalidation for aggregate module Home Service compatibility."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .module_home_service_multi_compatibility import (
    ModuleHomeServiceMultiCompatibilityBinding,
    ModuleHomeServiceMultiCompatibilityError,
    bind_module_home_service_multi_compatibility,
    validate_module_home_service_multi_compatibility_binding,
)


REVALIDATION_SCHEMA = (
    "home-center.module-home-service-contract-multi-compatibility-"
    "binding-revalidation.v1"
)
ID24 = re.compile(r"^[0-9a-f]{24}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
MODULE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$"
)
SERVICE_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)
DRIFT_REASONS = frozenset(
    {
        "aggregate_compatibility_evidence_changed",
        "blocked_service_set_changed",
        "compatibility_status_changed",
        "home_center_version_changed",
        "module_identity_changed",
        "module_version_changed",
        "multi_requirement_set_changed",
        "service_compatibility_evidence_changed",
        "service_set_changed",
    }
)
REVALIDATION_FIELDS = frozenset(
    {
        "schema",
        "revalidation_id",
        "status",
        "original_multi_compatibility_binding_id",
        "fresh_multi_compatibility_binding_id",
        "original_multi_requirement_set_id",
        "fresh_multi_requirement_set_id",
        "original_home_center_version",
        "fresh_home_center_version",
        "original_module_id",
        "fresh_module_id",
        "original_module_version",
        "fresh_module_version",
        "original_service_ids",
        "fresh_service_ids",
        "original_service_evidence_sha256",
        "fresh_service_evidence_sha256",
        "original_blocked_service_ids",
        "fresh_blocked_service_ids",
        "original_compatibility_status",
        "fresh_compatibility_status",
        "drift_reasons",
        *AUTHORITY_FLAGS,
    }
)


class ModuleHomeServiceMultiCompatibilityRevalidationError(ValueError):
    """Stable rejection code for invalid aggregate revalidation evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceMultiCompatibilityRevalidation:
    """Evidence describing whether exact aggregate compatibility is current."""

    revalidation_id: str
    status: str
    original_multi_compatibility_binding_id: str
    fresh_multi_compatibility_binding_id: str
    original_multi_requirement_set_id: str
    fresh_multi_requirement_set_id: str
    original_home_center_version: str
    fresh_home_center_version: str
    original_module_id: str
    fresh_module_id: str
    original_module_version: str
    fresh_module_version: str
    original_service_ids: tuple[str, ...]
    fresh_service_ids: tuple[str, ...]
    original_service_evidence_sha256: str
    fresh_service_evidence_sha256: str
    original_blocked_service_ids: tuple[str, ...]
    fresh_blocked_service_ids: tuple[str, ...]
    original_compatibility_status: str
    fresh_compatibility_status: str
    drift_reasons: tuple[str, ...]
    schema: str = REVALIDATION_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    @property
    def current(self) -> bool:
        return self.status == "current"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "revalidation_id": self.revalidation_id,
            "status": self.status,
            "original_multi_compatibility_binding_id": (
                self.original_multi_compatibility_binding_id
            ),
            "fresh_multi_compatibility_binding_id": (
                self.fresh_multi_compatibility_binding_id
            ),
            "original_multi_requirement_set_id": (
                self.original_multi_requirement_set_id
            ),
            "fresh_multi_requirement_set_id": self.fresh_multi_requirement_set_id,
            "original_home_center_version": self.original_home_center_version,
            "fresh_home_center_version": self.fresh_home_center_version,
            "original_module_id": self.original_module_id,
            "fresh_module_id": self.fresh_module_id,
            "original_module_version": self.original_module_version,
            "fresh_module_version": self.fresh_module_version,
            "original_service_ids": list(self.original_service_ids),
            "fresh_service_ids": list(self.fresh_service_ids),
            "original_service_evidence_sha256": (
                self.original_service_evidence_sha256
            ),
            "fresh_service_evidence_sha256": self.fresh_service_evidence_sha256,
            "original_blocked_service_ids": list(
                self.original_blocked_service_ids
            ),
            "fresh_blocked_service_ids": list(self.fresh_blocked_service_ids),
            "original_compatibility_status": self.original_compatibility_status,
            "fresh_compatibility_status": self.fresh_compatibility_status,
            "drift_reasons": list(self.drift_reasons),
            "admission_authorized": self.admission_authorized,
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": (
                self.external_publication_authorized
            ),
        }


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (
        TypeError,
        ValueError,
        UnicodeEncodeError,
        RecursionError,
    ) as exc:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        payload = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleHomeServiceMultiCompatibilityRevalidationError(
                "multi_compatibility_revalidation_evidence_rejected"
            )
        try:
            payload = to_dict()
        except (TypeError, ValueError) as exc:
            raise ModuleHomeServiceMultiCompatibilityRevalidationError(
                "multi_compatibility_revalidation_evidence_rejected"
            ) from exc
    if not isinstance(payload, dict):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    return payload


def _reconstruct_original(
    multi_requirement_set: object,
    module_binding: object,
    service_profiles: object,
    original_binding: object,
) -> ModuleHomeServiceMultiCompatibilityBinding:
    try:
        validated = validate_module_home_service_multi_compatibility_binding(
            original_binding
        )
        reconstructed = bind_module_home_service_multi_compatibility(
            multi_requirement_set,
            module_binding,
            service_profiles,
        )
    except (
        ModuleHomeServiceMultiCompatibilityError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "original_multi_compatibility_binding_rejected"
        ) from exc
    if validated.to_dict() != reconstructed.to_dict():
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "original_multi_compatibility_binding_rejected"
        )
    return reconstructed


def _fresh_binding(
    multi_requirement_set: object,
    module_binding: object,
    service_profiles: object,
) -> ModuleHomeServiceMultiCompatibilityBinding:
    try:
        return bind_module_home_service_multi_compatibility(
            multi_requirement_set,
            module_binding,
            service_profiles,
        )
    except (
        ModuleHomeServiceMultiCompatibilityError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "fresh_multi_compatibility_binding_rejected"
        ) from exc


def _service_projection(
    binding: ModuleHomeServiceMultiCompatibilityBinding,
) -> tuple[tuple[str, ...], str]:
    payload = [item.to_dict() for item in binding.service_compatibility_bindings]
    service_ids = tuple(
        item.service_id for item in binding.service_compatibility_bindings
    )
    return service_ids, _canonical_sha256(payload)


def _drift_reasons(
    original: ModuleHomeServiceMultiCompatibilityBinding,
    fresh: ModuleHomeServiceMultiCompatibilityBinding,
    original_service_ids: tuple[str, ...],
    fresh_service_ids: tuple[str, ...],
    original_service_evidence_sha256: str,
    fresh_service_evidence_sha256: str,
) -> tuple[str, ...]:
    drift: set[str] = set()
    comparisons = (
        (
            "multi_requirement_set_changed",
            original.multi_requirement_set_id,
            fresh.multi_requirement_set_id,
        ),
        (
            "home_center_version_changed",
            original.home_center_version,
            fresh.home_center_version,
        ),
        ("module_identity_changed", original.module_id, fresh.module_id),
        ("module_version_changed", original.module_version, fresh.module_version),
        ("service_set_changed", original_service_ids, fresh_service_ids),
        (
            "service_compatibility_evidence_changed",
            original_service_evidence_sha256,
            fresh_service_evidence_sha256,
        ),
        (
            "blocked_service_set_changed",
            original.blocked_service_ids,
            fresh.blocked_service_ids,
        ),
        (
            "compatibility_status_changed",
            original.compatibility_status,
            fresh.compatibility_status,
        ),
    )
    for reason, old, new in comparisons:
        if old != new:
            drift.add(reason)
    if (
        original.multi_compatibility_binding_id
        != fresh.multi_compatibility_binding_id
        and not drift
    ):
        drift.add("aggregate_compatibility_evidence_changed")
    return tuple(sorted(drift))


def revalidate_module_home_service_multi_compatibility(
    original_multi_requirement_set: object,
    original_module_binding: object,
    original_service_profiles: object,
    original_binding: object,
    *,
    fresh_multi_requirement_set: object,
    fresh_module_binding: object,
    fresh_service_profiles: object,
) -> ModuleHomeServiceMultiCompatibilityRevalidation:
    """Reconstruct old evidence and compare it with a fresh aggregate binding."""

    original = _reconstruct_original(
        original_multi_requirement_set,
        original_module_binding,
        original_service_profiles,
        original_binding,
    )
    fresh = _fresh_binding(
        fresh_multi_requirement_set,
        fresh_module_binding,
        fresh_service_profiles,
    )
    original_service_ids, original_service_sha = _service_projection(original)
    fresh_service_ids, fresh_service_sha = _service_projection(fresh)
    drift_reasons = _drift_reasons(
        original,
        fresh,
        original_service_ids,
        fresh_service_ids,
        original_service_sha,
        fresh_service_sha,
    )
    status = "current" if not drift_reasons else "stale"
    evidence = {
        "schema": REVALIDATION_SCHEMA,
        "status": status,
        "original_multi_compatibility_binding_id": (
            original.multi_compatibility_binding_id
        ),
        "fresh_multi_compatibility_binding_id": fresh.multi_compatibility_binding_id,
        "original_multi_requirement_set_id": original.multi_requirement_set_id,
        "fresh_multi_requirement_set_id": fresh.multi_requirement_set_id,
        "original_home_center_version": original.home_center_version,
        "fresh_home_center_version": fresh.home_center_version,
        "original_module_id": original.module_id,
        "fresh_module_id": fresh.module_id,
        "original_module_version": original.module_version,
        "fresh_module_version": fresh.module_version,
        "original_service_ids": list(original_service_ids),
        "fresh_service_ids": list(fresh_service_ids),
        "original_service_evidence_sha256": original_service_sha,
        "fresh_service_evidence_sha256": fresh_service_sha,
        "original_blocked_service_ids": list(original.blocked_service_ids),
        "fresh_blocked_service_ids": list(fresh.blocked_service_ids),
        "original_compatibility_status": original.compatibility_status,
        "fresh_compatibility_status": fresh.compatibility_status,
        "drift_reasons": list(drift_reasons),
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    revalidation_id = "mhsmcbr-" + _canonical_sha256(evidence)[:24]
    return ModuleHomeServiceMultiCompatibilityRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_multi_compatibility_binding_id=(
            original.multi_compatibility_binding_id
        ),
        fresh_multi_compatibility_binding_id=fresh.multi_compatibility_binding_id,
        original_multi_requirement_set_id=original.multi_requirement_set_id,
        fresh_multi_requirement_set_id=fresh.multi_requirement_set_id,
        original_home_center_version=original.home_center_version,
        fresh_home_center_version=fresh.home_center_version,
        original_module_id=original.module_id,
        fresh_module_id=fresh.module_id,
        original_module_version=original.module_version,
        fresh_module_version=fresh.module_version,
        original_service_ids=original_service_ids,
        fresh_service_ids=fresh_service_ids,
        original_service_evidence_sha256=original_service_sha,
        fresh_service_evidence_sha256=fresh_service_sha,
        original_blocked_service_ids=original.blocked_service_ids,
        fresh_blocked_service_ids=fresh.blocked_service_ids,
        original_compatibility_status=original.compatibility_status,
        fresh_compatibility_status=fresh.compatibility_status,
        drift_reasons=drift_reasons,
    )


def _id(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or ID24.fullmatch(value[len(prefix) :]) is None
    ):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    return value


def _semver(value: object) -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    return value


def _module_id(value: object) -> str:
    if not isinstance(value, str) or MODULE_ID.fullmatch(value) is None:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    return value


def _service_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    result = tuple(value)
    if (
        any(
            not isinstance(item, str)
            or SERVICE_ID.fullmatch(item) is None
            for item in result
        )
        or len(result) != len(set(result))
        or list(result) != sorted(result)
    ):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    return result


def _digest(value: object) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    return value


def validate_module_home_service_multi_compatibility_revalidation(
    value: object,
) -> ModuleHomeServiceMultiCompatibilityRevalidation:
    """Validate closed serialized revalidation evidence and canonical identity."""

    payload = _mapping(value)
    if (
        set(payload) != REVALIDATION_FIELDS
        or payload.get("schema") != REVALIDATION_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    revalidation_id = _id(payload.get("revalidation_id"), "mhsmcbr-")
    status = payload.get("status")
    if status not in {"current", "stale"}:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    original_binding_id = _id(
        payload.get("original_multi_compatibility_binding_id"), "mhsmcb-"
    )
    fresh_binding_id = _id(
        payload.get("fresh_multi_compatibility_binding_id"), "mhsmcb-"
    )
    original_requirement_id = _id(
        payload.get("original_multi_requirement_set_id"), "mhsmr-"
    )
    fresh_requirement_id = _id(
        payload.get("fresh_multi_requirement_set_id"), "mhsmr-"
    )
    original_version = _semver(payload.get("original_home_center_version"))
    fresh_version = _semver(payload.get("fresh_home_center_version"))
    original_module_id = _module_id(payload.get("original_module_id"))
    fresh_module_id = _module_id(payload.get("fresh_module_id"))
    original_module_version = _semver(payload.get("original_module_version"))
    fresh_module_version = _semver(payload.get("fresh_module_version"))
    original_service_ids = _service_ids(payload.get("original_service_ids"))
    fresh_service_ids = _service_ids(payload.get("fresh_service_ids"))
    original_service_sha = _digest(
        payload.get("original_service_evidence_sha256")
    )
    fresh_service_sha = _digest(payload.get("fresh_service_evidence_sha256"))
    original_blocked = payload.get("original_blocked_service_ids")
    fresh_blocked = payload.get("fresh_blocked_service_ids")
    if not isinstance(original_blocked, list) or not isinstance(fresh_blocked, list):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    original_blocked_ids = tuple(original_blocked)
    fresh_blocked_ids = tuple(fresh_blocked)
    for blocked, services in (
        (original_blocked_ids, original_service_ids),
        (fresh_blocked_ids, fresh_service_ids),
    ):
        if (
            any(
                not isinstance(item, str)
                or SERVICE_ID.fullmatch(item) is None
                or item not in services
                for item in blocked
            )
            or len(blocked) != len(set(blocked))
            or list(blocked) != sorted(blocked)
        ):
            raise ModuleHomeServiceMultiCompatibilityRevalidationError(
                "multi_compatibility_revalidation_evidence_rejected"
            )
    original_compatibility = payload.get("original_compatibility_status")
    fresh_compatibility = payload.get("fresh_compatibility_status")
    if (
        original_compatibility not in {"compatible", "blocked"}
        or fresh_compatibility not in {"compatible", "blocked"}
    ):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    raw_reasons = payload.get("drift_reasons")
    if not isinstance(raw_reasons, list):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    drift_reasons = tuple(raw_reasons)
    if (
        any(
            not isinstance(reason, str) or reason not in DRIFT_REASONS
            for reason in drift_reasons
        )
        or len(drift_reasons) != len(set(drift_reasons))
        or list(drift_reasons) != sorted(drift_reasons)
        or (status == "current") != (not drift_reasons)
        or (status == "current" and original_binding_id != fresh_binding_id)
    ):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    expected_drift: set[str] = set()
    serialized_comparisons = (
        (
            "multi_requirement_set_changed",
            original_requirement_id,
            fresh_requirement_id,
        ),
        ("home_center_version_changed", original_version, fresh_version),
        ("module_identity_changed", original_module_id, fresh_module_id),
        (
            "module_version_changed",
            original_module_version,
            fresh_module_version,
        ),
        ("service_set_changed", original_service_ids, fresh_service_ids),
        (
            "service_compatibility_evidence_changed",
            original_service_sha,
            fresh_service_sha,
        ),
        (
            "blocked_service_set_changed",
            original_blocked_ids,
            fresh_blocked_ids,
        ),
        (
            "compatibility_status_changed",
            original_compatibility,
            fresh_compatibility,
        ),
    )
    for reason, old, new in serialized_comparisons:
        if old != new:
            expected_drift.add(reason)
    if original_binding_id != fresh_binding_id and not expected_drift:
        expected_drift.add("aggregate_compatibility_evidence_changed")
    if drift_reasons != tuple(sorted(expected_drift)):
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    evidence = dict(payload)
    evidence.pop("revalidation_id")
    expected_id = "mhsmcbr-" + _canonical_sha256(evidence)[:24]
    if revalidation_id != expected_id:
        raise ModuleHomeServiceMultiCompatibilityRevalidationError(
            "multi_compatibility_revalidation_evidence_rejected"
        )
    return ModuleHomeServiceMultiCompatibilityRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_multi_compatibility_binding_id=original_binding_id,
        fresh_multi_compatibility_binding_id=fresh_binding_id,
        original_multi_requirement_set_id=original_requirement_id,
        fresh_multi_requirement_set_id=fresh_requirement_id,
        original_home_center_version=original_version,
        fresh_home_center_version=fresh_version,
        original_module_id=original_module_id,
        fresh_module_id=fresh_module_id,
        original_module_version=original_module_version,
        fresh_module_version=fresh_module_version,
        original_service_ids=original_service_ids,
        fresh_service_ids=fresh_service_ids,
        original_service_evidence_sha256=original_service_sha,
        fresh_service_evidence_sha256=fresh_service_sha,
        original_blocked_service_ids=original_blocked_ids,
        fresh_blocked_service_ids=fresh_blocked_ids,
        original_compatibility_status=original_compatibility,
        fresh_compatibility_status=fresh_compatibility,
        drift_reasons=drift_reasons,
    )
