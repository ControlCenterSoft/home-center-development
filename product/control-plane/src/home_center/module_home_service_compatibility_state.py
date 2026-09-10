"""Read-only effective state for module Home Service compatibility evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .module_home_service_multi_compatibility import (
    ModuleHomeServiceMultiCompatibilityError,
    validate_module_home_service_multi_compatibility_binding,
)
from .module_home_service_multi_compatibility_revalidation import (
    ModuleHomeServiceMultiCompatibilityRevalidationError,
    validate_module_home_service_multi_compatibility_revalidation,
)


STATE_SCHEMA = "home-center.module-home-service-compatibility-state.v1"
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
STATE_FIELDS = frozenset(
    {
        "schema",
        "state_id",
        "resource_version",
        "etag",
        "home_center_version",
        "module_id",
        "module_version",
        "source_multi_compatibility_binding_id",
        "fresh_multi_compatibility_binding_id",
        "revalidation_id",
        "freshness",
        "effective_status",
        "observed_compatibility_status",
        "service_ids",
        "blocked_service_ids",
        "drift_reasons",
        *AUTHORITY_FLAGS,
    }
)


class ModuleHomeServiceCompatibilityStateError(ValueError):
    """Stable rejection code for malformed or mismatched state evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceCompatibilityState:
    """Canonical read-only projection for one module compatibility state."""

    state_id: str
    resource_version: str
    etag: str
    home_center_version: str
    module_id: str
    module_version: str
    source_multi_compatibility_binding_id: str
    fresh_multi_compatibility_binding_id: str
    revalidation_id: str
    freshness: str
    effective_status: str
    observed_compatibility_status: str
    service_ids: tuple[str, ...]
    blocked_service_ids: tuple[str, ...]
    drift_reasons: tuple[str, ...]
    schema: str = STATE_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state_id": self.state_id,
            "resource_version": self.resource_version,
            "etag": self.etag,
            "home_center_version": self.home_center_version,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "source_multi_compatibility_binding_id": (
                self.source_multi_compatibility_binding_id
            ),
            "fresh_multi_compatibility_binding_id": (
                self.fresh_multi_compatibility_binding_id
            ),
            "revalidation_id": self.revalidation_id,
            "freshness": self.freshness,
            "effective_status": self.effective_status,
            "observed_compatibility_status": (
                self.observed_compatibility_status
            ),
            "service_ids": list(self.service_ids),
            "blocked_service_ids": list(self.blocked_service_ids),
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
        payload = json.dumps(
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
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        payload = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleHomeServiceCompatibilityStateError(
                "compatibility_state_evidence_rejected"
            )
        try:
            payload = to_dict()
        except (TypeError, ValueError) as exc:
            raise ModuleHomeServiceCompatibilityStateError(
                "compatibility_state_evidence_rejected"
            ) from exc
    if not isinstance(payload, dict):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    return payload


def _service_evidence_sha(binding: object) -> str:
    items = getattr(binding, "service_compatibility_bindings", None)
    if not isinstance(items, tuple):
        raise ModuleHomeServiceCompatibilityStateError(
            "aggregate_compatibility_evidence_rejected"
        )
    try:
        payload = [item.to_dict() for item in items]
    except (AttributeError, TypeError, ValueError) as exc:
        raise ModuleHomeServiceCompatibilityStateError(
            "aggregate_compatibility_evidence_rejected"
        ) from exc
    return _canonical_sha256(payload)


def _validate_context(binding: object, revalidation: object) -> None:
    original_pairs = (
        (
            getattr(binding, "multi_compatibility_binding_id", None),
            getattr(
                revalidation,
                "original_multi_compatibility_binding_id",
                None,
            ),
        ),
        (
            getattr(binding, "multi_requirement_set_id", None),
            getattr(revalidation, "original_multi_requirement_set_id", None),
        ),
        (
            getattr(binding, "home_center_version", None),
            getattr(revalidation, "original_home_center_version", None),
        ),
        (
            getattr(binding, "module_id", None),
            getattr(revalidation, "original_module_id", None),
        ),
        (
            getattr(binding, "module_version", None),
            getattr(revalidation, "original_module_version", None),
        ),
        (
            tuple(
                item.service_id
                for item in getattr(
                    binding,
                    "service_compatibility_bindings",
                    (),
                )
            ),
            getattr(revalidation, "original_service_ids", None),
        ),
        (
            getattr(binding, "blocked_service_ids", None),
            getattr(revalidation, "original_blocked_service_ids", None),
        ),
        (
            getattr(binding, "compatibility_status", None),
            getattr(revalidation, "original_compatibility_status", None),
        ),
        (
            _service_evidence_sha(binding),
            getattr(
                revalidation,
                "original_service_evidence_sha256",
                None,
            ),
        ),
    )
    if any(actual != expected for actual, expected in original_pairs):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_context_mismatch"
        )


def _state_evidence(
    *,
    revalidation: object,
    effective_status: str,
) -> dict[str, object]:
    return {
        "schema": STATE_SCHEMA,
        "home_center_version": revalidation.fresh_home_center_version,
        "module_id": revalidation.fresh_module_id,
        "module_version": revalidation.fresh_module_version,
        "source_multi_compatibility_binding_id": (
            revalidation.original_multi_compatibility_binding_id
        ),
        "fresh_multi_compatibility_binding_id": (
            revalidation.fresh_multi_compatibility_binding_id
        ),
        "revalidation_id": revalidation.revalidation_id,
        "freshness": revalidation.status,
        "effective_status": effective_status,
        "observed_compatibility_status": (
            revalidation.fresh_compatibility_status
        ),
        "service_ids": list(revalidation.fresh_service_ids),
        "blocked_service_ids": list(revalidation.fresh_blocked_service_ids),
        "drift_reasons": list(revalidation.drift_reasons),
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }


def build_module_home_service_compatibility_state(
    multi_compatibility_binding: object,
    revalidation: object,
) -> ModuleHomeServiceCompatibilityState:
    """Build a deterministic fail-closed state projection without side effects."""

    try:
        binding = validate_module_home_service_multi_compatibility_binding(
            multi_compatibility_binding
        )
    except (
        ModuleHomeServiceMultiCompatibilityError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceCompatibilityStateError(
            "aggregate_compatibility_evidence_rejected"
        ) from exc
    try:
        checked = validate_module_home_service_multi_compatibility_revalidation(
            revalidation
        )
    except (
        ModuleHomeServiceMultiCompatibilityRevalidationError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_revalidation_evidence_rejected"
        ) from exc

    _validate_context(binding, checked)
    effective_status = (
        checked.fresh_compatibility_status
        if checked.status == "current"
        else "stale"
    )
    evidence = _state_evidence(
        revalidation=checked,
        effective_status=effective_status,
    )
    resource_version = _canonical_sha256(evidence)
    state_id = "mhscs-" + resource_version[:24]
    etag = f'"mhscs-{resource_version}"'
    return ModuleHomeServiceCompatibilityState(
        state_id=state_id,
        resource_version=resource_version,
        etag=etag,
        home_center_version=checked.fresh_home_center_version,
        module_id=checked.fresh_module_id,
        module_version=checked.fresh_module_version,
        source_multi_compatibility_binding_id=(
            checked.original_multi_compatibility_binding_id
        ),
        fresh_multi_compatibility_binding_id=(
            checked.fresh_multi_compatibility_binding_id
        ),
        revalidation_id=checked.revalidation_id,
        freshness=checked.status,
        effective_status=effective_status,
        observed_compatibility_status=(
            checked.fresh_compatibility_status
        ),
        service_ids=checked.fresh_service_ids,
        blocked_service_ids=checked.fresh_blocked_service_ids,
        drift_reasons=checked.drift_reasons,
    )


def _identifier(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or ID24.fullmatch(value[len(prefix) :]) is None
    ):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    return value


def _semver(value: object) -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    return value


def _module_id(value: object) -> str:
    if not isinstance(value, str) or MODULE_ID.fullmatch(value) is None:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    return value


def _service_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    result = tuple(value)
    if (
        len(result) != len(set(result))
        or list(result) != sorted(result)
        or any(
            not isinstance(item, str)
            or SERVICE_ID.fullmatch(item) is None
            for item in result
        )
    ):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    return result


def validate_module_home_service_compatibility_state(
    value: object,
) -> ModuleHomeServiceCompatibilityState:
    """Validate a closed serialized state and its exact resource identity."""

    payload = _mapping(value)
    if (
        set(payload) != STATE_FIELDS
        or payload.get("schema") != STATE_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )

    state_id = _identifier(payload.get("state_id"), "mhscs-")
    resource_version = payload.get("resource_version")
    if not isinstance(resource_version, str) or DIGEST.fullmatch(
        resource_version
    ) is None:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    if payload.get("etag") != f'"mhscs-{resource_version}"':
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    home_center_version = _semver(payload.get("home_center_version"))
    module_id = _module_id(payload.get("module_id"))
    module_version = _semver(payload.get("module_version"))
    source_binding_id = _identifier(
        payload.get("source_multi_compatibility_binding_id"),
        "mhsmcb-",
    )
    fresh_binding_id = _identifier(
        payload.get("fresh_multi_compatibility_binding_id"),
        "mhsmcb-",
    )
    revalidation_id = _identifier(
        payload.get("revalidation_id"),
        "mhsmcbr-",
    )
    freshness = payload.get("freshness")
    if freshness not in {"current", "stale"}:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    observed = payload.get("observed_compatibility_status")
    if observed not in {"compatible", "blocked"}:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    effective_status = payload.get("effective_status")
    expected_effective = observed if freshness == "current" else "stale"
    if effective_status != expected_effective:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    service_ids = _service_ids(payload.get("service_ids"))
    blocked_service_ids = payload.get("blocked_service_ids")
    if not isinstance(blocked_service_ids, list):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    blocked = tuple(blocked_service_ids)
    if (
        len(blocked) != len(set(blocked))
        or list(blocked) != sorted(blocked)
        or any(item not in service_ids for item in blocked)
    ):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    expected_observed = "compatible" if not blocked else "blocked"
    if observed != expected_observed:
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    drift_reasons = payload.get("drift_reasons")
    if not isinstance(drift_reasons, list):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )
    drift = tuple(drift_reasons)
    if (
        len(drift) != len(set(drift))
        or list(drift) != sorted(drift)
        or any(
            not isinstance(item, str) or item not in DRIFT_REASONS
            for item in drift
        )
        or (freshness == "current") != (not drift)
        or (freshness == "current" and source_binding_id != fresh_binding_id)
    ):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )

    evidence = dict(payload)
    for field in ("state_id", "resource_version", "etag"):
        evidence.pop(field)
    expected_resource_version = _canonical_sha256(evidence)
    if (
        resource_version != expected_resource_version
        or state_id != "mhscs-" + expected_resource_version[:24]
    ):
        raise ModuleHomeServiceCompatibilityStateError(
            "compatibility_state_evidence_rejected"
        )

    return ModuleHomeServiceCompatibilityState(
        state_id=state_id,
        resource_version=resource_version,
        etag=str(payload["etag"]),
        home_center_version=home_center_version,
        module_id=module_id,
        module_version=module_version,
        source_multi_compatibility_binding_id=source_binding_id,
        fresh_multi_compatibility_binding_id=fresh_binding_id,
        revalidation_id=revalidation_id,
        freshness=str(freshness),
        effective_status=str(effective_status),
        observed_compatibility_status=str(observed),
        service_ids=service_ids,
        blocked_service_ids=blocked,
        drift_reasons=drift,
    )
