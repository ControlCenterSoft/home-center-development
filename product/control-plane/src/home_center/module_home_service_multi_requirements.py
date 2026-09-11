"""Canonical aggregate identity for multi-service module requirements."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from itertools import islice
from typing import Any, Iterable, Mapping

from .module_home_service_contract_requirements import (
    ModuleHomeServiceContractRequirementError,
    ModuleHomeServiceContractRequirementSet,
    build_module_home_service_contract_requirement_set,
    validate_module_home_service_contract_requirement_set,
)


MULTI_REQUIREMENT_SET_SCHEMA = (
    "home-center.module-home-service-contract-multi-requirement-set.v1"
)
ID24 = re.compile(r"^[0-9a-f]{24}$")
AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)
MULTI_REQUIREMENT_SET_FIELDS = frozenset(
    {
        "schema",
        "multi_requirement_set_id",
        "home_center_version",
        "module_id",
        "module_version",
        "service_requirement_sets",
        *AUTHORITY_FLAGS,
    }
)
SERVICE_REQUIREMENT_FIELDS = frozenset(
    {
        "service_id",
        "requirement_set_id",
        "required_service_contracts",
    }
)


class ModuleHomeServiceMultiRequirementError(ValueError):
    """Stable rejection code for invalid multi-service requirement evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class HomeServiceRequirementReference:
    """Canonical projection of one single-service requirement set."""

    service_id: str
    requirement_set_id: str
    required_service_contracts: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "requirement_set_id": self.requirement_set_id,
            "required_service_contracts": list(
                self.required_service_contracts
            ),
        }


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceMultiRequirementSet:
    """Exact non-authorizing identity for all service needs of one module."""

    multi_requirement_set_id: str
    home_center_version: str
    module_id: str
    module_version: str
    service_requirement_sets: tuple[HomeServiceRequirementReference, ...]
    schema: str = MULTI_REQUIREMENT_SET_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "multi_requirement_set_id": self.multi_requirement_set_id,
            "home_center_version": self.home_center_version,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "service_requirement_sets": [
                item.to_dict() for item in self.service_requirement_sets
            ],
            "admission_authorized": self.admission_authorized,
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": (
                self.external_publication_authorized
            ),
        }


def _reject(code: str = "multi_requirement_set_rejected") -> None:
    raise ModuleHomeServiceMultiRequirementError(code)


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
        raise ModuleHomeServiceMultiRequirementError(
            "multi_requirement_set_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _validated_requirement_set(
    value: object,
) -> ModuleHomeServiceContractRequirementSet:
    try:
        return validate_module_home_service_contract_requirement_set(value)
    except ModuleHomeServiceContractRequirementError as exc:
        raise ModuleHomeServiceMultiRequirementError(
            "service_requirement_set_rejected"
        ) from exc


def _requirement_sets(
    values: Iterable[object],
) -> tuple[ModuleHomeServiceContractRequirementSet, ...]:
    if isinstance(values, (str, bytes)):
        _reject("service_requirement_sets_rejected")
    try:
        iterator = iter(values)
        raw = tuple(islice(iterator, 65))
    except TypeError as exc:
        raise ModuleHomeServiceMultiRequirementError(
            "service_requirement_sets_rejected"
        ) from exc
    if not 1 <= len(raw) <= 64:
        _reject("service_requirement_sets_rejected")
    validated = tuple(_validated_requirement_set(item) for item in raw)
    service_ids = tuple(item.service_id for item in validated)
    if len(service_ids) != len(set(service_ids)):
        _reject("duplicate_service_requirement")
    return tuple(sorted(validated, key=lambda item: item.service_id))


def build_module_home_service_multi_requirement_set(
    requirement_sets: Iterable[object],
) -> ModuleHomeServiceMultiRequirementSet:
    """Build deterministic aggregate evidence from exact single-service sets."""

    items = _requirement_sets(requirement_sets)
    first = items[0]
    context = (
        first.home_center_version,
        first.module_id,
        first.module_version,
    )
    if any(
        (
            item.home_center_version,
            item.module_id,
            item.module_version,
        )
        != context
        for item in items[1:]
    ):
        _reject("requirement_context_mismatch")

    references = tuple(
        HomeServiceRequirementReference(
            service_id=item.service_id,
            requirement_set_id=item.requirement_set_id,
            required_service_contracts=item.required_service_contracts,
        )
        for item in items
    )
    evidence = {
        "schema": MULTI_REQUIREMENT_SET_SCHEMA,
        "home_center_version": first.home_center_version,
        "module_id": first.module_id,
        "module_version": first.module_version,
        "service_requirement_sets": [
            item.to_dict() for item in references
        ],
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    aggregate_id = "mhsmr-" + _canonical_sha256(evidence)[:24]
    return ModuleHomeServiceMultiRequirementSet(
        multi_requirement_set_id=aggregate_id,
        home_center_version=first.home_center_version,
        module_id=first.module_id,
        module_version=first.module_version,
        service_requirement_sets=references,
    )


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if not callable(to_dict):
        _reject()
    try:
        raw = to_dict()
    except (TypeError, ValueError) as exc:
        raise ModuleHomeServiceMultiRequirementError(
            "multi_requirement_set_rejected"
        ) from exc
    if not isinstance(raw, dict):
        _reject()
    return raw


def _serialized_requirement_sets(
    value: object,
    *,
    home_center_version: object,
    module_id: object,
    module_version: object,
) -> tuple[ModuleHomeServiceContractRequirementSet, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        _reject("service_requirement_sets_rejected")
    reconstructed: list[ModuleHomeServiceContractRequirementSet] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            _reject("service_requirement_set_rejected")
        payload = dict(entry)
        if set(payload) != SERVICE_REQUIREMENT_FIELDS:
            _reject("service_requirement_set_rejected")
        try:
            item = build_module_home_service_contract_requirement_set(
                home_center_version=home_center_version,
                module_id=module_id,
                module_version=module_version,
                service_id=payload.get("service_id"),
                required_service_contracts=payload.get(
                    "required_service_contracts", ()
                ),
            )
        except (ModuleHomeServiceContractRequirementError, TypeError) as exc:
            raise ModuleHomeServiceMultiRequirementError(
                "service_requirement_set_rejected"
            ) from exc
        if (
            payload.get("requirement_set_id") != item.requirement_set_id
            or payload.get("required_service_contracts")
            != list(item.required_service_contracts)
        ):
            _reject("service_requirement_set_rejected")
        reconstructed.append(item)
    service_ids = [item.service_id for item in reconstructed]
    if len(service_ids) != len(set(service_ids)):
        _reject("duplicate_service_requirement")
    if service_ids != sorted(service_ids):
        _reject("multi_requirement_set_rejected")
    return tuple(reconstructed)


def validate_module_home_service_multi_requirement_set(
    value: object,
) -> ModuleHomeServiceMultiRequirementSet:
    """Validate aggregate serialized evidence and exact nested identities."""

    payload = _mapping(value)
    if (
        set(payload) != MULTI_REQUIREMENT_SET_FIELDS
        or payload.get("schema") != MULTI_REQUIREMENT_SET_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        _reject()

    aggregate_id = payload.get("multi_requirement_set_id")
    if (
        not isinstance(aggregate_id, str)
        or not aggregate_id.startswith("mhsmr-")
        or ID24.fullmatch(aggregate_id[6:]) is None
    ):
        _reject()

    items = _serialized_requirement_sets(
        payload.get("service_requirement_sets"),
        home_center_version=payload.get("home_center_version"),
        module_id=payload.get("module_id"),
        module_version=payload.get("module_version"),
    )
    result = build_module_home_service_multi_requirement_set(items)
    if (
        result.multi_requirement_set_id != aggregate_id
        or result.to_dict() != payload
    ):
        _reject()
    return result
