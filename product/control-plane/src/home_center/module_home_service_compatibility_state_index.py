"""Canonical read-only index over validated module/Home Service compatibility states."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from .module_home_service_compatibility_state import (
    ModuleHomeServiceCompatibilityState,
    ModuleHomeServiceCompatibilityStateError,
    validate_module_home_service_compatibility_state,
)


INDEX_SCHEMA = "home-center.module-home-service-compatibility-state-index.v1"
MAX_STATES = 512
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ID24 = re.compile(r"^[0-9a-f]{24}$")
AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)
INDEX_FIELDS = frozenset(
    {
        "schema",
        "index_id",
        "resource_version",
        "etag",
        "home_center_version",
        "summary_status",
        "module_count",
        "compatible_count",
        "blocked_count",
        "stale_count",
        "states",
        *AUTHORITY_FLAGS,
    }
)


class ModuleHomeServiceCompatibilityStateIndexError(ValueError):
    """Stable fail-closed rejection code for malformed compatibility indexes."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceCompatibilityStateIndex:
    index_id: str
    resource_version: str
    etag: str
    home_center_version: str
    summary_status: str
    module_count: int
    compatible_count: int
    blocked_count: int
    stale_count: int
    states: tuple[ModuleHomeServiceCompatibilityState, ...]
    schema: str = INDEX_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "index_id": self.index_id,
            "resource_version": self.resource_version,
            "etag": self.etag,
            "home_center_version": self.home_center_version,
            "summary_status": self.summary_status,
            "module_count": self.module_count,
            "compatible_count": self.compatible_count,
            "blocked_count": self.blocked_count,
            "stale_count": self.stale_count,
            "states": [state.to_dict() for state in self.states],
            "admission_authorized": False,
            "installation_authorized": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
            "external_publication_authorized": False,
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
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _mapping(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        payload = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleHomeServiceCompatibilityStateIndexError(
                "compatibility_state_index_evidence_rejected"
            )
        try:
            payload = to_dict()
        except (TypeError, ValueError) as exc:
            raise ModuleHomeServiceCompatibilityStateIndexError(
                "compatibility_state_index_evidence_rejected"
            ) from exc
    if not isinstance(payload, dict):
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_evidence_rejected"
        )
    return payload


def _version(value: object) -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_version_rejected"
        )
    return value


def _validated_states(
    values: Iterable[object],
    *,
    home_center_version: str,
) -> tuple[ModuleHomeServiceCompatibilityState, ...]:
    if isinstance(values, (str, bytes, Mapping)):
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_states_rejected"
        )
    try:
        raw_states = tuple(values)
    except TypeError as exc:
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_states_rejected"
        ) from exc
    if len(raw_states) > MAX_STATES:
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_too_large"
        )

    states: list[ModuleHomeServiceCompatibilityState] = []
    seen_modules: set[str] = set()
    for raw_state in raw_states:
        try:
            state = validate_module_home_service_compatibility_state(raw_state)
        except (ModuleHomeServiceCompatibilityStateError, TypeError, ValueError) as exc:
            raise ModuleHomeServiceCompatibilityStateIndexError(
                "compatibility_state_index_member_rejected"
            ) from exc
        if state.home_center_version != home_center_version:
            raise ModuleHomeServiceCompatibilityStateIndexError(
                "compatibility_state_index_version_mismatch"
            )
        if state.module_id in seen_modules:
            raise ModuleHomeServiceCompatibilityStateIndexError(
                "compatibility_state_index_duplicate_module"
            )
        seen_modules.add(state.module_id)
        states.append(state)

    return tuple(sorted(states, key=lambda item: item.module_id))


def _summary(
    states: tuple[ModuleHomeServiceCompatibilityState, ...],
) -> tuple[str, int, int, int]:
    stale_count = sum(state.effective_status == "stale" for state in states)
    blocked_count = sum(state.effective_status == "blocked" for state in states)
    compatible_count = sum(state.effective_status == "compatible" for state in states)
    if stale_count:
        summary_status = "stale"
    elif blocked_count:
        summary_status = "blocked"
    elif compatible_count:
        summary_status = "compatible"
    else:
        summary_status = "empty"
    return summary_status, compatible_count, blocked_count, stale_count


def _evidence(
    *,
    home_center_version: str,
    summary_status: str,
    compatible_count: int,
    blocked_count: int,
    stale_count: int,
    states: tuple[ModuleHomeServiceCompatibilityState, ...],
) -> dict[str, object]:
    return {
        "schema": INDEX_SCHEMA,
        "home_center_version": home_center_version,
        "summary_status": summary_status,
        "module_count": len(states),
        "compatible_count": compatible_count,
        "blocked_count": blocked_count,
        "stale_count": stale_count,
        "states": [state.to_dict() for state in states],
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }


def build_module_home_service_compatibility_state_index(
    *,
    home_center_version: str,
    states: Iterable[object],
) -> ModuleHomeServiceCompatibilityStateIndex:
    """Build a deterministic index; stale evidence always wins aggregate status."""

    version = _version(home_center_version)
    checked = _validated_states(states, home_center_version=version)
    summary_status, compatible_count, blocked_count, stale_count = _summary(checked)
    evidence = _evidence(
        home_center_version=version,
        summary_status=summary_status,
        compatible_count=compatible_count,
        blocked_count=blocked_count,
        stale_count=stale_count,
        states=checked,
    )
    resource_version = _canonical_sha256(evidence)
    return ModuleHomeServiceCompatibilityStateIndex(
        index_id="mhscsi-" + resource_version[:24],
        resource_version=resource_version,
        etag=f'"mhscsi-{resource_version}"',
        home_center_version=version,
        summary_status=summary_status,
        module_count=len(checked),
        compatible_count=compatible_count,
        blocked_count=blocked_count,
        stale_count=stale_count,
        states=checked,
    )


def validate_module_home_service_compatibility_state_index(
    value: object,
) -> ModuleHomeServiceCompatibilityStateIndex:
    """Validate a closed serialized index and recalculate every derived identity."""

    payload = _mapping(value)
    if (
        set(payload) != INDEX_FIELDS
        or payload.get("schema") != INDEX_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_evidence_rejected"
        )

    version = _version(payload.get("home_center_version"))
    raw_states = payload.get("states")
    if not isinstance(raw_states, list):
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_states_rejected"
        )
    states = _validated_states(raw_states, home_center_version=version)
    if [state.to_dict() for state in states] != raw_states:
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_noncanonical_order"
        )

    summary_status, compatible_count, blocked_count, stale_count = _summary(states)
    expected_counts = {
        "module_count": len(states),
        "compatible_count": compatible_count,
        "blocked_count": blocked_count,
        "stale_count": stale_count,
    }
    if payload.get("summary_status") != summary_status or any(
        isinstance(payload.get(field), bool)
        or not isinstance(payload.get(field), int)
        or payload.get(field) != expected
        for field, expected in expected_counts.items()
    ):
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_summary_rejected"
        )

    resource_version = payload.get("resource_version")
    index_id = payload.get("index_id")
    etag = payload.get("etag")
    if (
        not isinstance(resource_version, str)
        or DIGEST.fullmatch(resource_version) is None
        or not isinstance(index_id, str)
        or not index_id.startswith("mhscsi-")
        or ID24.fullmatch(index_id[len("mhscsi-") :]) is None
        or etag != f'"mhscsi-{resource_version}"'
    ):
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_identity_rejected"
        )

    evidence = _evidence(
        home_center_version=version,
        summary_status=summary_status,
        compatible_count=compatible_count,
        blocked_count=blocked_count,
        stale_count=stale_count,
        states=states,
    )
    expected_resource_version = _canonical_sha256(evidence)
    if (
        resource_version != expected_resource_version
        or index_id != "mhscsi-" + expected_resource_version[:24]
    ):
        raise ModuleHomeServiceCompatibilityStateIndexError(
            "compatibility_state_index_identity_rejected"
        )

    return ModuleHomeServiceCompatibilityStateIndex(
        index_id=index_id,
        resource_version=resource_version,
        etag=etag,
        home_center_version=version,
        summary_status=summary_status,
        module_count=len(states),
        compatible_count=compatible_count,
        blocked_count=blocked_count,
        stale_count=stale_count,
        states=states,
    )
