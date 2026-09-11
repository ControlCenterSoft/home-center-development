"""Exact-state revalidation for module Home Service requirement bindings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .module_home_service_requirement_binding import (
    ModuleHomeServiceRequirementBinding,
    ModuleHomeServiceRequirementBindingError,
    bind_module_home_service_requirement_set,
)


REVALIDATION_SCHEMA = (
    "home-center.module-home-service-contract-requirement-binding-revalidation.v1"
)


class ModuleHomeServiceRequirementBindingRevalidationError(ValueError):
    """Stable rejection code for invalid requirement-binding revalidation."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceRequirementBindingRevalidation:
    """Evidence describing whether one exact requirement binding is current."""

    revalidation_id: str
    status: str
    original_requirement_binding_id: str
    fresh_requirement_binding_id: str
    original_requirement_set_id: str
    fresh_requirement_set_id: str
    original_home_service_contract_binding_id: str
    fresh_home_service_contract_binding_id: str
    original_home_center_version: str
    fresh_home_center_version: str
    original_module_id: str
    fresh_module_id: str
    original_module_version: str
    fresh_module_version: str
    original_service_id: str
    fresh_service_id: str
    original_service_profile_sha256: str
    fresh_service_profile_sha256: str
    original_required_service_contracts: tuple[str, ...]
    fresh_required_service_contracts: tuple[str, ...]
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
            "original_requirement_binding_id": (
                self.original_requirement_binding_id
            ),
            "fresh_requirement_binding_id": self.fresh_requirement_binding_id,
            "original_requirement_set_id": self.original_requirement_set_id,
            "fresh_requirement_set_id": self.fresh_requirement_set_id,
            "original_home_service_contract_binding_id": (
                self.original_home_service_contract_binding_id
            ),
            "fresh_home_service_contract_binding_id": (
                self.fresh_home_service_contract_binding_id
            ),
            "original_home_center_version": self.original_home_center_version,
            "fresh_home_center_version": self.fresh_home_center_version,
            "original_module_id": self.original_module_id,
            "fresh_module_id": self.fresh_module_id,
            "original_module_version": self.original_module_version,
            "fresh_module_version": self.fresh_module_version,
            "original_service_id": self.original_service_id,
            "fresh_service_id": self.fresh_service_id,
            "original_service_profile_sha256": (
                self.original_service_profile_sha256
            ),
            "fresh_service_profile_sha256": self.fresh_service_profile_sha256,
            "original_required_service_contracts": list(
                self.original_required_service_contracts
            ),
            "fresh_required_service_contracts": list(
                self.fresh_required_service_contracts
            ),
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
        raise ModuleHomeServiceRequirementBindingRevalidationError(
            "requirement_binding_revalidation_evidence_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _reconstruct_original(
    requirement_set: object,
    module_binding: object,
    service_profile: object,
    original_binding: ModuleHomeServiceRequirementBinding,
) -> ModuleHomeServiceRequirementBinding:
    if not isinstance(
        original_binding,
        ModuleHomeServiceRequirementBinding,
    ):
        raise ModuleHomeServiceRequirementBindingRevalidationError(
            "original_requirement_binding_rejected"
        )
    try:
        reconstructed = bind_module_home_service_requirement_set(
            requirement_set,
            module_binding,
            service_profile,
        )
        original_payload = original_binding.to_dict()
        reconstructed_payload = reconstructed.to_dict()
    except (
        ModuleHomeServiceRequirementBindingError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceRequirementBindingRevalidationError(
            "original_requirement_binding_rejected"
        ) from exc
    if original_payload != reconstructed_payload:
        raise ModuleHomeServiceRequirementBindingRevalidationError(
            "original_requirement_binding_rejected"
        )
    return reconstructed


def _fresh_binding(
    requirement_set: object,
    module_binding: object,
    service_profile: object,
) -> ModuleHomeServiceRequirementBinding:
    try:
        return bind_module_home_service_requirement_set(
            requirement_set,
            module_binding,
            service_profile,
        )
    except (
        ModuleHomeServiceRequirementBindingError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceRequirementBindingRevalidationError(
            "fresh_requirement_binding_rejected"
        ) from exc


def revalidate_module_home_service_requirement_binding(
    original_requirement_set: object,
    original_module_binding: object,
    original_service_profile: object,
    original_binding: ModuleHomeServiceRequirementBinding,
    *,
    fresh_requirement_set: object,
    fresh_module_binding: object,
    fresh_service_profile: object,
) -> ModuleHomeServiceRequirementBindingRevalidation:
    """Revalidate exact requirement/compatibility binding without side effects."""

    original = _reconstruct_original(
        original_requirement_set,
        original_module_binding,
        original_service_profile,
        original_binding,
    )
    fresh = _fresh_binding(
        fresh_requirement_set,
        fresh_module_binding,
        fresh_service_profile,
    )

    drift: set[str] = set()
    comparisons = (
        (
            "requirement_set_changed",
            original.requirement_set_id,
            fresh.requirement_set_id,
        ),
        (
            "home_service_contract_binding_changed",
            original.home_service_contract_binding_id,
            fresh.home_service_contract_binding_id,
        ),
        (
            "home_center_version_changed",
            original.home_center_version,
            fresh.home_center_version,
        ),
        (
            "module_identity_changed",
            original.module_id,
            fresh.module_id,
        ),
        (
            "module_version_changed",
            original.module_version,
            fresh.module_version,
        ),
        (
            "home_service_identity_changed",
            original.service_id,
            fresh.service_id,
        ),
        (
            "home_service_profile_changed",
            original.service_profile_sha256,
            fresh.service_profile_sha256,
        ),
        (
            "required_service_contracts_changed",
            original.required_service_contracts,
            fresh.required_service_contracts,
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

    if not drift and (
        original.requirement_binding_id != fresh.requirement_binding_id
    ):
        drift.add("requirement_binding_evidence_changed")

    drift_reasons = tuple(sorted(drift))
    status = "current" if not drift_reasons else "stale"
    evidence = {
        "schema": REVALIDATION_SCHEMA,
        "status": status,
        "original_requirement_binding_id": original.requirement_binding_id,
        "fresh_requirement_binding_id": fresh.requirement_binding_id,
        "original_requirement_set_id": original.requirement_set_id,
        "fresh_requirement_set_id": fresh.requirement_set_id,
        "original_home_service_contract_binding_id": (
            original.home_service_contract_binding_id
        ),
        "fresh_home_service_contract_binding_id": (
            fresh.home_service_contract_binding_id
        ),
        "original_home_center_version": original.home_center_version,
        "fresh_home_center_version": fresh.home_center_version,
        "original_module_id": original.module_id,
        "fresh_module_id": fresh.module_id,
        "original_module_version": original.module_version,
        "fresh_module_version": fresh.module_version,
        "original_service_id": original.service_id,
        "fresh_service_id": fresh.service_id,
        "original_service_profile_sha256": original.service_profile_sha256,
        "fresh_service_profile_sha256": fresh.service_profile_sha256,
        "original_required_service_contracts": list(
            original.required_service_contracts
        ),
        "fresh_required_service_contracts": list(
            fresh.required_service_contracts
        ),
        "original_compatibility_status": original.compatibility_status,
        "fresh_compatibility_status": fresh.compatibility_status,
        "drift_reasons": list(drift_reasons),
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    revalidation_id = "mhsrbr-" + _canonical_sha256(evidence)[:24]

    return ModuleHomeServiceRequirementBindingRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_requirement_binding_id=original.requirement_binding_id,
        fresh_requirement_binding_id=fresh.requirement_binding_id,
        original_requirement_set_id=original.requirement_set_id,
        fresh_requirement_set_id=fresh.requirement_set_id,
        original_home_service_contract_binding_id=(
            original.home_service_contract_binding_id
        ),
        fresh_home_service_contract_binding_id=(
            fresh.home_service_contract_binding_id
        ),
        original_home_center_version=original.home_center_version,
        fresh_home_center_version=fresh.home_center_version,
        original_module_id=original.module_id,
        fresh_module_id=fresh.module_id,
        original_module_version=original.module_version,
        fresh_module_version=fresh.module_version,
        original_service_id=original.service_id,
        fresh_service_id=fresh.service_id,
        original_service_profile_sha256=original.service_profile_sha256,
        fresh_service_profile_sha256=fresh.service_profile_sha256,
        original_required_service_contracts=(
            original.required_service_contracts
        ),
        fresh_required_service_contracts=fresh.required_service_contracts,
        original_compatibility_status=original.compatibility_status,
        fresh_compatibility_status=fresh.compatibility_status,
        drift_reasons=drift_reasons,
    )
