"""Bind canonical module service requirements to compatibility evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

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
            "home_service_contract_binding_id": (
                self.home_service_contract_binding_id
            ),
            "home_center_version": self.home_center_version,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "service_id": self.service_id,
            "service_profile_sha256": self.service_profile_sha256,
            "required_service_contracts": list(
                self.required_service_contracts
            ),
            "compatibility_status": self.compatibility_status,
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
        raise ModuleHomeServiceRequirementBindingError(
            "requirement_binding_evidence_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


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
        (
            requirements.home_center_version,
            compatibility.home_center_version,
        ),
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
        "required_service_contracts": list(
            requirements.required_service_contracts
        ),
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
