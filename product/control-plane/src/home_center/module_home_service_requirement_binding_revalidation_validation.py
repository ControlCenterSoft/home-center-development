"""Validate serialized module Home Service requirement-binding revalidation evidence."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .module_home_service_requirement_binding_revalidation import (
    REVALIDATION_SCHEMA,
    ModuleHomeServiceRequirementBindingRevalidation,
    ModuleHomeServiceRequirementBindingRevalidationError,
)


_ID24 = re.compile(r"^[0-9a-f]{24}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
_MODULE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$"
)
_SERVICE_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
_SERVICE_CONTRACT = re.compile(
    r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$"
)
_AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)
_DRIFT_REASONS = frozenset(
    {
        "compatibility_status_changed",
        "home_center_version_changed",
        "home_service_contract_binding_changed",
        "home_service_identity_changed",
        "home_service_profile_changed",
        "module_identity_changed",
        "module_version_changed",
        "requirement_binding_evidence_changed",
        "requirement_set_changed",
        "required_service_contracts_changed",
    }
)
_FIELDS = frozenset(
    {
        "schema",
        "revalidation_id",
        "status",
        "original_requirement_binding_id",
        "fresh_requirement_binding_id",
        "original_requirement_set_id",
        "fresh_requirement_set_id",
        "original_home_service_contract_binding_id",
        "fresh_home_service_contract_binding_id",
        "original_home_center_version",
        "fresh_home_center_version",
        "original_module_id",
        "fresh_module_id",
        "original_module_version",
        "fresh_module_version",
        "original_service_id",
        "fresh_service_id",
        "original_service_profile_sha256",
        "fresh_service_profile_sha256",
        "original_required_service_contracts",
        "fresh_required_service_contracts",
        "original_compatibility_status",
        "fresh_compatibility_status",
        "drift_reasons",
        *_AUTHORITY_FLAGS,
    }
)


def _reject() -> ModuleHomeServiceRequirementBindingRevalidationError:
    return ModuleHomeServiceRequirementBindingRevalidationError(
        "requirement_binding_revalidation_rejected"
    )


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
        raise _reject() from exc
    return hashlib.sha256(encoded).hexdigest()


def _payload(value: object) -> dict[str, Any]:
    if type(value) is dict:
        return dict(value)
    if isinstance(value, ModuleHomeServiceRequirementBindingRevalidation):
        try:
            raw = value.to_dict()
        except (TypeError, ValueError, RuntimeError, RecursionError) as exc:
            raise _reject() from exc
        if type(raw) is not dict:
            raise _reject()
        return raw
    raise _reject()


def _identifier(value: object, prefix: str) -> str:
    if (
        type(value) is not str
        or not value.startswith(prefix)
        or _ID24.fullmatch(value[len(prefix) :]) is None
    ):
        raise _reject()
    return value


def _semver(value: object) -> str:
    if type(value) is not str or _SEMVER.fullmatch(value) is None:
        raise _reject()
    return value


def _module_id(value: object) -> str:
    if type(value) is not str or _MODULE_ID.fullmatch(value) is None:
        raise _reject()
    return value


def _service_id(value: object) -> str:
    if type(value) is not str or _SERVICE_ID.fullmatch(value) is None:
        raise _reject()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _reject()
    return value


def _contracts(value: object) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= 64:
        raise _reject()
    if any(
        type(item) is not str or _SERVICE_CONTRACT.fullmatch(item) is None
        for item in value
    ):
        raise _reject()
    if len(value) != len(set(value)):
        raise _reject()
    result = tuple(sorted(value))
    if list(result) != value:
        raise _reject()
    return result


def _compatibility(value: object) -> str:
    if value not in {"compatible", "blocked"} or type(value) is not str:
        raise _reject()
    return value


def _drift_reasons(value: object) -> tuple[str, ...]:
    if type(value) is not list or len(value) > len(_DRIFT_REASONS):
        raise _reject()
    if any(type(item) is not str or item not in _DRIFT_REASONS for item in value):
        raise _reject()
    if len(value) != len(set(value)):
        raise _reject()
    result = tuple(sorted(value))
    if list(result) != value:
        raise _reject()
    return result


def validate_module_home_service_requirement_binding_revalidation(
    value: object,
) -> ModuleHomeServiceRequirementBindingRevalidation:
    """Validate closed serialized evidence, semantic drift and deterministic ID."""

    payload = _payload(value)
    if (
        set(payload) != _FIELDS
        or payload.get("schema") != REVALIDATION_SCHEMA
        or any(payload.get(flag) is not False for flag in _AUTHORITY_FLAGS)
    ):
        raise _reject()

    revalidation_id = _identifier(payload.get("revalidation_id"), "mhsrbr-")
    status = payload.get("status")
    if type(status) is not str or status not in {"current", "stale"}:
        raise _reject()

    original_requirement_binding_id = _identifier(
        payload.get("original_requirement_binding_id"), "mhsrb-"
    )
    fresh_requirement_binding_id = _identifier(
        payload.get("fresh_requirement_binding_id"), "mhsrb-"
    )
    original_requirement_set_id = _identifier(
        payload.get("original_requirement_set_id"), "mhscr-"
    )
    fresh_requirement_set_id = _identifier(
        payload.get("fresh_requirement_set_id"), "mhscr-"
    )
    original_home_service_contract_binding_id = _identifier(
        payload.get("original_home_service_contract_binding_id"), "mhscb-"
    )
    fresh_home_service_contract_binding_id = _identifier(
        payload.get("fresh_home_service_contract_binding_id"), "mhscb-"
    )
    original_home_center_version = _semver(
        payload.get("original_home_center_version")
    )
    fresh_home_center_version = _semver(payload.get("fresh_home_center_version"))
    original_module_id = _module_id(payload.get("original_module_id"))
    fresh_module_id = _module_id(payload.get("fresh_module_id"))
    original_module_version = _semver(payload.get("original_module_version"))
    fresh_module_version = _semver(payload.get("fresh_module_version"))
    original_service_id = _service_id(payload.get("original_service_id"))
    fresh_service_id = _service_id(payload.get("fresh_service_id"))
    original_service_profile_sha256 = _digest(
        payload.get("original_service_profile_sha256")
    )
    fresh_service_profile_sha256 = _digest(
        payload.get("fresh_service_profile_sha256")
    )
    original_required_service_contracts = _contracts(
        payload.get("original_required_service_contracts")
    )
    fresh_required_service_contracts = _contracts(
        payload.get("fresh_required_service_contracts")
    )
    original_compatibility_status = _compatibility(
        payload.get("original_compatibility_status")
    )
    fresh_compatibility_status = _compatibility(
        payload.get("fresh_compatibility_status")
    )
    drift_reasons = _drift_reasons(payload.get("drift_reasons"))

    comparisons = (
        (
            "requirement_set_changed",
            original_requirement_set_id,
            fresh_requirement_set_id,
        ),
        (
            "home_service_contract_binding_changed",
            original_home_service_contract_binding_id,
            fresh_home_service_contract_binding_id,
        ),
        (
            "home_center_version_changed",
            original_home_center_version,
            fresh_home_center_version,
        ),
        ("module_identity_changed", original_module_id, fresh_module_id),
        ("module_version_changed", original_module_version, fresh_module_version),
        ("home_service_identity_changed", original_service_id, fresh_service_id),
        (
            "home_service_profile_changed",
            original_service_profile_sha256,
            fresh_service_profile_sha256,
        ),
        (
            "required_service_contracts_changed",
            original_required_service_contracts,
            fresh_required_service_contracts,
        ),
        (
            "compatibility_status_changed",
            original_compatibility_status,
            fresh_compatibility_status,
        ),
    )
    expected_drift = {reason for reason, old, new in comparisons if old != new}
    if not expected_drift and (
        original_requirement_binding_id != fresh_requirement_binding_id
    ):
        expected_drift.add("requirement_binding_evidence_changed")
    expected_drift_reasons = tuple(sorted(expected_drift))
    expected_status = "current" if not expected_drift_reasons else "stale"
    if status != expected_status or drift_reasons != expected_drift_reasons:
        raise _reject()

    evidence = dict(payload)
    evidence.pop("revalidation_id")
    expected_id = "mhsrbr-" + _canonical_sha256(evidence)[:24]
    if revalidation_id != expected_id:
        raise _reject()

    return ModuleHomeServiceRequirementBindingRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_requirement_binding_id=original_requirement_binding_id,
        fresh_requirement_binding_id=fresh_requirement_binding_id,
        original_requirement_set_id=original_requirement_set_id,
        fresh_requirement_set_id=fresh_requirement_set_id,
        original_home_service_contract_binding_id=(
            original_home_service_contract_binding_id
        ),
        fresh_home_service_contract_binding_id=fresh_home_service_contract_binding_id,
        original_home_center_version=original_home_center_version,
        fresh_home_center_version=fresh_home_center_version,
        original_module_id=original_module_id,
        fresh_module_id=fresh_module_id,
        original_module_version=original_module_version,
        fresh_module_version=fresh_module_version,
        original_service_id=original_service_id,
        fresh_service_id=fresh_service_id,
        original_service_profile_sha256=original_service_profile_sha256,
        fresh_service_profile_sha256=fresh_service_profile_sha256,
        original_required_service_contracts=original_required_service_contracts,
        fresh_required_service_contracts=fresh_required_service_contracts,
        original_compatibility_status=original_compatibility_status,
        fresh_compatibility_status=fresh_compatibility_status,
        drift_reasons=drift_reasons,
    )
