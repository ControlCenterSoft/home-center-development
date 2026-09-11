"""Canonical read-only index for module Home Service compatibility states."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .module_home_service_compatibility_state import (
    ModuleHomeServiceCompatibilityStateError,
    validate_module_home_service_compatibility_state,
)


INDEX_SCHEMA = "home-center.module-home-service-compatibility-index.v1"
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
ITEM_FIELDS = frozenset(
    {
        "state_id",
        "state_resource_version",
        "state_etag",
        "module_id",
        "module_version",
        "freshness",
        "effective_status",
        "observed_compatibility_status",
        "service_ids",
        "blocked_service_ids",
    }
)
INDEX_FIELDS = frozenset(
    {
        "schema",
        "index_id",
        "resource_version",
        "etag",
        "home_center_version",
        "module_count",
        "overall_status",
        "items",
        *AUTHORITY_FLAGS,
    }
)


class ModuleHomeServiceCompatibilityIndexError(ValueError):
    """Stable rejection code for malformed compatibility index evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceCompatibilityIndexItem:
    """Identity-preserving summary of one validated compatibility state."""

    state_id: str
    state_resource_version: str
    state_etag: str
    module_id: str
    module_version: str
    freshness: str
    effective_status: str
    observed_compatibility_status: str
    service_ids: tuple[str, ...]
    blocked_service_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "state_id": self.state_id,
            "state_resource_version": self.state_resource_version,
            "state_etag": self.state_etag,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "freshness": self.freshness,
            "effective_status": self.effective_status,
            "observed_compatibility_status": (
                self.observed_compatibility_status
            ),
            "service_ids": list(self.service_ids),
            "blocked_service_ids": list(self.blocked_service_ids),
        }


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceCompatibilityIndex:
    """Deterministic read-only projection for all module compatibility states."""

    index_id: str
    resource_version: str
    etag: str
    home_center_version: str
    module_count: int
    overall_status: str
    items: tuple[ModuleHomeServiceCompatibilityIndexItem, ...]
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
            "module_count": self.module_count,
            "overall_status": self.overall_status,
            "items": [item.to_dict() for item in self.items],
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
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        payload = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleHomeServiceCompatibilityIndexError(
                "compatibility_index_evidence_rejected"
            )
        try:
            payload = to_dict()
        except (TypeError, ValueError) as exc:
            raise ModuleHomeServiceCompatibilityIndexError(
                "compatibility_index_evidence_rejected"
            ) from exc
    if not isinstance(payload, dict):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    return payload


def _state_item(state: object) -> ModuleHomeServiceCompatibilityIndexItem:
    return ModuleHomeServiceCompatibilityIndexItem(
        state_id=state.state_id,
        state_resource_version=state.resource_version,
        state_etag=state.etag,
        module_id=state.module_id,
        module_version=state.module_version,
        freshness=state.freshness,
        effective_status=state.effective_status,
        observed_compatibility_status=state.observed_compatibility_status,
        service_ids=state.service_ids,
        blocked_service_ids=state.blocked_service_ids,
    )


def _overall_status(
    items: tuple[ModuleHomeServiceCompatibilityIndexItem, ...],
) -> str:
    if any(item.effective_status == "stale" for item in items):
        return "stale"
    if any(item.effective_status == "blocked" for item in items):
        return "blocked"
    return "compatible"


def _index_evidence(
    *,
    home_center_version: str,
    overall_status: str,
    items: tuple[ModuleHomeServiceCompatibilityIndexItem, ...],
) -> dict[str, object]:
    return {
        "schema": INDEX_SCHEMA,
        "home_center_version": home_center_version,
        "module_count": len(items),
        "overall_status": overall_status,
        "items": [item.to_dict() for item in items],
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }


def build_module_home_service_compatibility_index(
    states: Iterable[object],
    *,
    home_center_version: str,
) -> ModuleHomeServiceCompatibilityIndex:
    """Build a canonical index without granting module execution authority."""

    if not isinstance(home_center_version, str) or SEMVER.fullmatch(
        home_center_version
    ) is None:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_context_rejected"
        )
    try:
        candidates = list(states)
    except (TypeError, ValueError) as exc:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        ) from exc
    if len(candidates) > 4096:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_capacity_exceeded"
        )

    items: list[ModuleHomeServiceCompatibilityIndexItem] = []
    for candidate in candidates:
        try:
            state = validate_module_home_service_compatibility_state(candidate)
        except (
            ModuleHomeServiceCompatibilityStateError,
            TypeError,
            ValueError,
        ) as exc:
            raise ModuleHomeServiceCompatibilityIndexError(
                "compatibility_state_evidence_rejected"
            ) from exc
        if state.home_center_version != home_center_version:
            raise ModuleHomeServiceCompatibilityIndexError(
                "compatibility_index_context_mismatch"
            )
        items.append(_state_item(state))

    items.sort(key=lambda item: item.module_id)
    module_ids = [item.module_id for item in items]
    if len(module_ids) != len(set(module_ids)):
        raise ModuleHomeServiceCompatibilityIndexError(
            "duplicate_module_compatibility_state"
        )

    canonical_items = tuple(items)
    overall_status = _overall_status(canonical_items)
    evidence = _index_evidence(
        home_center_version=home_center_version,
        overall_status=overall_status,
        items=canonical_items,
    )
    resource_version = _canonical_sha256(evidence)
    return ModuleHomeServiceCompatibilityIndex(
        index_id="mhsci-" + resource_version[:24],
        resource_version=resource_version,
        etag=f'"mhsci-{resource_version}"',
        home_center_version=home_center_version,
        module_count=len(canonical_items),
        overall_status=overall_status,
        items=canonical_items,
    )


def _identifier(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or ID24.fullmatch(value[len(prefix) :]) is None
    ):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    return value


def _service_ids(
    value: object,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > 64
        or (not allow_empty and not value)
    ):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
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
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    return result


def _validate_item(value: object) -> ModuleHomeServiceCompatibilityIndexItem:
    payload = _mapping(value)
    if set(payload) != ITEM_FIELDS:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    state_id = _identifier(payload.get("state_id"), "mhscs-")
    resource_version = _digest(payload.get("state_resource_version"))
    if state_id != "mhscs-" + resource_version[:24]:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    state_etag = payload.get("state_etag")
    if state_etag != f'"mhscs-{resource_version}"':
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    module_id = payload.get("module_id")
    if not isinstance(module_id, str) or MODULE_ID.fullmatch(module_id) is None:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    module_version = payload.get("module_version")
    if not isinstance(module_version, str) or SEMVER.fullmatch(
        module_version
    ) is None:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    freshness = payload.get("freshness")
    if freshness not in {"current", "stale"}:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    observed = payload.get("observed_compatibility_status")
    if observed not in {"compatible", "blocked"}:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    effective = payload.get("effective_status")
    if effective != (observed if freshness == "current" else "stale"):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    service_ids = _service_ids(payload.get("service_ids"))
    blocked = _service_ids(
        payload.get("blocked_service_ids"),
        allow_empty=True,
    )
    if any(service_id not in service_ids for service_id in blocked):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    expected_observed = "blocked" if blocked else "compatible"
    if observed != expected_observed:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    return ModuleHomeServiceCompatibilityIndexItem(
        state_id=state_id,
        state_resource_version=resource_version,
        state_etag=state_etag,
        module_id=module_id,
        module_version=module_version,
        freshness=freshness,
        effective_status=effective,
        observed_compatibility_status=observed,
        service_ids=service_ids,
        blocked_service_ids=blocked,
    )


def validate_module_home_service_compatibility_index(
    value: object,
) -> ModuleHomeServiceCompatibilityIndex:
    """Validate a closed serialized index and its exact resource identity."""

    payload = _mapping(value)
    if (
        set(payload) != INDEX_FIELDS
        or payload.get("schema") != INDEX_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    index_id = _identifier(payload.get("index_id"), "mhsci-")
    resource_version = _digest(payload.get("resource_version"))
    if (
        index_id != "mhsci-" + resource_version[:24]
        or payload.get("etag") != f'"mhsci-{resource_version}"'
    ):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    home_center_version = payload.get("home_center_version")
    if not isinstance(home_center_version, str) or SEMVER.fullmatch(
        home_center_version
    ) is None:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    raw_items = payload.get("items")
    if not isinstance(raw_items, list) or len(raw_items) > 4096:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    items = tuple(_validate_item(item) for item in raw_items)
    module_ids = [item.module_id for item in items]
    if (
        module_ids != sorted(module_ids)
        or len(module_ids) != len(set(module_ids))
    ):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    module_count = payload.get("module_count")
    if (
        isinstance(module_count, bool)
        or not isinstance(module_count, int)
        or module_count != len(items)
    ):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    overall_status = payload.get("overall_status")
    if overall_status != _overall_status(items):
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    evidence = _index_evidence(
        home_center_version=home_center_version,
        overall_status=overall_status,
        items=items,
    )
    if _canonical_sha256(evidence) != resource_version:
        raise ModuleHomeServiceCompatibilityIndexError(
            "compatibility_index_evidence_rejected"
        )
    return ModuleHomeServiceCompatibilityIndex(
        index_id=index_id,
        resource_version=resource_version,
        etag=payload["etag"],
        home_center_version=home_center_version,
        module_count=module_count,
        overall_status=overall_status,
        items=items,
    )
