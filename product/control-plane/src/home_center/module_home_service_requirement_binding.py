"""Bind canonical module service requirements to compatibility evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .module_home_service_contract_binding import (
    ModuleHomeServiceContractBindingError,
    bind_module_home_service_contracts,
)
from .module_home_service_contract_requirements import (
    ModuleHomeServiceContractRequirementError,
    validate_module_home_service_contract_requirement_set,
)


REQUIREMENT_BINDING_SCHEMA = (
    "home-center.module-home-service-contract-requirement-binding.v1"
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
SERVICE_CONTRACT = re.compile(
    r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$"
)
AUTHORITY_FLAGS = (
    "admission_authorized",
    "installation_authorized",
    "execution_authorized",
    "production_mutation_enabled",
    "external_publication_authorized",
)
REQUIREMENT_BINDING_FIELDS = frozenset(
    {
        "schema",
        "requirement_binding_id",
        "requirement_set_id",
        "home_service_contract_binding_id",
        "home_center_version",
        "module_id",
        "module_version",
        "service_id",
        "service_profile_sha256",
        "required_service_contracts",
        "compatibility_status",
        *AUTHORITY_FLAGS,
    }
)


class ModuleHomeServiceRequirementBindingError(ValueError):
    """Stable rejection code for requirement/compatibility binding failures."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceRequirementBinding:
    """Evidence binding one exact requirement set to one compatibility result."""

    requirement_binding_id: str
    requirement_set_id: str
    home_service_contract_binding_id: str
    home_center_version: str
    module_id: str
    module_version: str
    service_id: str
    service_profile_sha256: str
    required_service_contracts: tuple[str, ...]
    compatibility_status: str
    schema: str = REQUIREMENT_BINDING_SCHEMA
    admission_authorized: bool = False
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "requirement_binding_id": self.requirement_binding_id,
            "requirement_set_id": self.requirement_set_id,
            "home_service_contract_binding_id": self.home_service_contract_binding_id,
            "home_center_version": self.home_center_version,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "service_id": self.service_id,
            "service_profile_sha256": self.service_profile_sha256,
            "required_service_contracts": list(self.required_service_contracts),
            "compatibility_status": self.compatibility_status,
            "admission_authorized": self.admission_authorized,
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": self.external_publication_authorized,
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
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_evidence_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _payload(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        try:
            raw = dict(value)
        except (TypeError, ValueError, RuntimeError, RecursionError) as exc:
            raise ModuleHomeServiceRequirementBindingError(
                "requirement_binding_rejected"
            ) from exc
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise ModuleHomeServiceRequirementBindingError(
                "requirement_binding_rejected"
            )
        try:
            raw = to_dict()
        except (TypeError, ValueError, RuntimeError, RecursionError) as exc:
            raise ModuleHomeServiceRequirementBindingError(
                "requirement_binding_rejected"
            ) from exc
    if not isinstance(raw, dict):
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    return raw


def _identifier(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or ID24.fullmatch(value[len(prefix) :]) is None
    ):
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    return value


def _semver(value: object) -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    return value


def _module_id(value: object) -> str:
    if not isinstance(value, str) or MODULE_ID.fullmatch(value) is None:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    return value


def _service_id(value: object) -> str:
    if not isinstance(value, str) or SERVICE_ID.fullmatch(value) is None:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    return value


def _contracts(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    if any(
        not isinstance(item, str)
        or SERVICE_CONTRACT.fullmatch(item) is None
        for item in value
    ):
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    if len(value) != len(set(value)):
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    result = tuple(sorted(value))
    if list(result) != value:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )
    return result


def bind_module_home_service_requirement_set(
    requirement_set: object,
    module_binding: object,
    service_profile: object,
) -> ModuleHomeServiceRequirementBinding:
    """Bind exact requirement identity to exact Home Service compatibility."""

    try:
        requirements = validate_module_home_service_contract_requirement_set(
            requirement_set
        )
    except (
        ModuleHomeServiceContractRequirementError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_set_rejected"
        ) from exc

    try:
        compatibility = bind_module_home_service_contracts(
            module_binding,
            service_profile,
            requirements.required_service_contracts,
        )
    except (
        ModuleHomeServiceContractBindingError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceRequirementBindingError(
            "home_service_compatibility_rejected"
        ) from exc

    context = (
        (requirements.home_center_version, compatibility.home_center_version),
        (requirements.module_id, compatibility.module_id),
        (requirements.module_version, compatibility.module_version),
        (requirements.service_id, compatibility.service_id),
        (
            requirements.required_service_contracts,
            compatibility.required_service_contracts,
        ),
    )
    if any(expected != actual for expected, actual in context):
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_context_mismatch"
        )

    evidence = {
        "schema": REQUIREMENT_BINDING_SCHEMA,
        "requirement_set_id": requirements.requirement_set_id,
        "home_service_contract_binding_id": compatibility.binding_id,
        "home_center_version": requirements.home_center_version,
        "module_id": requirements.module_id,
        "module_version": requirements.module_version,
        "service_id": requirements.service_id,
        "service_profile_sha256": compatibility.service_profile_sha256,
        "required_service_contracts": list(requirements.required_service_contracts),
        "compatibility_status": compatibility.status,
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    requirement_binding_id = "mhsrb-" + _canonical_sha256(evidence)[:24]

    return ModuleHomeServiceRequirementBinding(
        requirement_binding_id=requirement_binding_id,
        requirement_set_id=requirements.requirement_set_id,
        home_service_contract_binding_id=compatibility.binding_id,
        home_center_version=requirements.home_center_version,
        module_id=requirements.module_id,
        module_version=requirements.module_version,
        service_id=requirements.service_id,
        service_profile_sha256=compatibility.service_profile_sha256,
        required_service_contracts=requirements.required_service_contracts,
        compatibility_status=compatibility.status,
    )


def validate_module_home_service_requirement_binding(
    value: object,
) -> ModuleHomeServiceRequirementBinding:
    """Validate serialized binding evidence and its deterministic identity."""

    payload = _payload(value)
    if (
        set(payload) != REQUIREMENT_BINDING_FIELDS
        or payload.get("schema") != REQUIREMENT_BINDING_SCHEMA
        or any(payload.get(flag) is not False for flag in AUTHORITY_FLAGS)
    ):
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )

    requirement_binding_id = _identifier(payload.get("requirement_binding_id"), "mhsrb-")
    requirement_set_id = _identifier(payload.get("requirement_set_id"), "mhscr-")
    home_service_contract_binding_id = _identifier(
        payload.get("home_service_contract_binding_id"), "mhscb-"
    )
    home_center_version = _semver(payload.get("home_center_version"))
    module_id = _module_id(payload.get("module_id"))
    module_version = _semver(payload.get("module_version"))
    service_id = _service_id(payload.get("service_id"))
    service_profile_sha256 = _digest(payload.get("service_profile_sha256"))
    required_service_contracts = _contracts(payload.get("required_service_contracts"))
    compatibility_status = payload.get("compatibility_status")
    if compatibility_status not in {"compatible", "blocked"}:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )

    evidence = dict(payload)
    evidence.pop("requirement_binding_id")
    expected_id = "mhsrb-" + _canonical_sha256(evidence)[:24]
    if requirement_binding_id != expected_id:
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_rejected"
        )

    return ModuleHomeServiceRequirementBinding(
        requirement_binding_id=requirement_binding_id,
        requirement_set_id=requirement_set_id,
        home_service_contract_binding_id=home_service_contract_binding_id,
        home_center_version=home_center_version,
        module_id=module_id,
        module_version=module_version,
        service_id=service_id,
        service_profile_sha256=service_profile_sha256,
        required_service_contracts=required_service_contracts,
        compatibility_status=compatibility_status,
    )
