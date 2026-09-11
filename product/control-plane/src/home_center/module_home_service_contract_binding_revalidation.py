"""Exact-state revalidation for module/Home Service contract bindings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable

from .module_home_service_contract_binding import (
    ModuleHomeServiceContractBinding,
    ModuleHomeServiceContractBindingError,
    bind_module_home_service_contracts,
)

REVALIDATION_SCHEMA = (
    "home-center.module-home-service-contract-binding-revalidation.v1"
)


class ModuleHomeServiceContractBindingRevalidationError(ValueError):
    """Stable rejection code for invalid Home Service binding revalidation."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleHomeServiceContractBindingRevalidation:
    """Evidence describing whether one exact module/service binding is current."""

    revalidation_id: str
    status: str
    original_binding_id: str
    fresh_binding_id: str
    original_module_contract_admission_binding_id: str
    fresh_module_contract_admission_binding_id: str
    original_home_center_version: str
    fresh_home_center_version: str
    original_module_id: str
    fresh_module_id: str
    original_module_version: str
    fresh_module_version: str
    original_service_profile_sha256: str
    fresh_service_profile_sha256: str
    original_service_id: str
    fresh_service_id: str
    original_service_kind: str
    fresh_service_kind: str
    original_required_service_contracts: tuple[str, ...]
    fresh_required_service_contracts: tuple[str, ...]
    original_provided_service_contracts: tuple[str, ...]
    fresh_provided_service_contracts: tuple[str, ...]
    original_unsupported_service_contracts: tuple[str, ...]
    fresh_unsupported_service_contracts: tuple[str, ...]
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
            "original_binding_id": self.original_binding_id,
            "fresh_binding_id": self.fresh_binding_id,
            "original_module_contract_admission_binding_id": (
                self.original_module_contract_admission_binding_id
            ),
            "fresh_module_contract_admission_binding_id": (
                self.fresh_module_contract_admission_binding_id
            ),
            "original_home_center_version": self.original_home_center_version,
            "fresh_home_center_version": self.fresh_home_center_version,
            "original_module_id": self.original_module_id,
            "fresh_module_id": self.fresh_module_id,
            "original_module_version": self.original_module_version,
            "fresh_module_version": self.fresh_module_version,
            "original_service_profile_sha256": self.original_service_profile_sha256,
            "fresh_service_profile_sha256": self.fresh_service_profile_sha256,
            "original_service_id": self.original_service_id,
            "fresh_service_id": self.fresh_service_id,
            "original_service_kind": self.original_service_kind,
            "fresh_service_kind": self.fresh_service_kind,
            "original_required_service_contracts": list(
                self.original_required_service_contracts
            ),
            "fresh_required_service_contracts": list(
                self.fresh_required_service_contracts
            ),
            "original_provided_service_contracts": list(
                self.original_provided_service_contracts
            ),
            "fresh_provided_service_contracts": list(
                self.fresh_provided_service_contracts
            ),
            "original_unsupported_service_contracts": list(
                self.original_unsupported_service_contracts
            ),
            "fresh_unsupported_service_contracts": list(
                self.fresh_unsupported_service_contracts
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
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ModuleHomeServiceContractBindingRevalidationError(
            "binding_revalidation_evidence_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _reconstruct_original(
    module_binding: object,
    service_profile: object,
    required_service_contracts: Iterable[str],
    original_binding: ModuleHomeServiceContractBinding,
) -> ModuleHomeServiceContractBinding:
    if not isinstance(original_binding, ModuleHomeServiceContractBinding):
        raise ModuleHomeServiceContractBindingRevalidationError(
            "original_home_service_binding_rejected"
        )
    try:
        reconstructed = bind_module_home_service_contracts(
            module_binding,
            service_profile,
            required_service_contracts,
        )
        original_payload = original_binding.to_dict()
        reconstructed_payload = reconstructed.to_dict()
    except (
        ModuleHomeServiceContractBindingError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceContractBindingRevalidationError(
            "original_home_service_binding_rejected"
        ) from exc
    if original_payload != reconstructed_payload:
        raise ModuleHomeServiceContractBindingRevalidationError(
            "original_home_service_binding_rejected"
        )
    return reconstructed


def _fresh_binding(
    module_binding: object,
    service_profile: object,
    required_service_contracts: Iterable[str],
) -> ModuleHomeServiceContractBinding:
    try:
        return bind_module_home_service_contracts(
            module_binding,
            service_profile,
            required_service_contracts,
        )
    except (
        ModuleHomeServiceContractBindingError,
        TypeError,
        ValueError,
    ) as exc:
        raise ModuleHomeServiceContractBindingRevalidationError(
            "fresh_home_service_binding_rejected"
        ) from exc


def revalidate_module_home_service_contract_binding(
    original_module_binding: object,
    original_service_profile: object,
    original_required_service_contracts: Iterable[str],
    original_binding: ModuleHomeServiceContractBinding,
    *,
    fresh_module_binding: object,
    fresh_service_profile: object,
    fresh_required_service_contracts: Iterable[str],
) -> ModuleHomeServiceContractBindingRevalidation:
    """Revalidate one exact module/Home Service binding without side effects."""

    original = _reconstruct_original(
        original_module_binding,
        original_service_profile,
        original_required_service_contracts,
        original_binding,
    )
    fresh = _fresh_binding(
        fresh_module_binding,
        fresh_service_profile,
        fresh_required_service_contracts,
    )

    drift: set[str] = set()
    comparisons = (
        (
            "module_contract_admission_binding_changed",
            original.module_contract_admission_binding_id,
            fresh.module_contract_admission_binding_id,
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
            "home_service_profile_changed",
            original.service_profile_sha256,
            fresh.service_profile_sha256,
        ),
        (
            "home_service_identity_changed",
            (original.service_id, original.service_kind),
            (fresh.service_id, fresh.service_kind),
        ),
        (
            "required_service_contracts_changed",
            original.required_service_contracts,
            fresh.required_service_contracts,
        ),
        (
            "provided_service_contracts_changed",
            original.provided_service_contracts,
            fresh.provided_service_contracts,
        ),
        (
            "unsupported_service_contracts_changed",
            original.unsupported_service_contracts,
            fresh.unsupported_service_contracts,
        ),
        (
            "compatibility_status_changed",
            original.status,
            fresh.status,
        ),
    )
    for reason, old, new in comparisons:
        if old != new:
            drift.add(reason)

    if not drift and original.binding_id != fresh.binding_id:
        drift.add("home_service_binding_evidence_changed")

    drift_reasons = tuple(sorted(drift))
    status = "current" if not drift_reasons else "stale"
    evidence = {
        "schema": REVALIDATION_SCHEMA,
        "status": status,
        "original_binding_id": original.binding_id,
        "fresh_binding_id": fresh.binding_id,
        "original_module_contract_admission_binding_id": (
            original.module_contract_admission_binding_id
        ),
        "fresh_module_contract_admission_binding_id": (
            fresh.module_contract_admission_binding_id
        ),
        "original_home_center_version": original.home_center_version,
        "fresh_home_center_version": fresh.home_center_version,
        "original_module_id": original.module_id,
        "fresh_module_id": fresh.module_id,
        "original_module_version": original.module_version,
        "fresh_module_version": fresh.module_version,
        "original_service_profile_sha256": original.service_profile_sha256,
        "fresh_service_profile_sha256": fresh.service_profile_sha256,
        "original_service_id": original.service_id,
        "fresh_service_id": fresh.service_id,
        "original_service_kind": original.service_kind,
        "fresh_service_kind": fresh.service_kind,
        "original_required_service_contracts": list(
            original.required_service_contracts
        ),
        "fresh_required_service_contracts": list(
            fresh.required_service_contracts
        ),
        "original_provided_service_contracts": list(
            original.provided_service_contracts
        ),
        "fresh_provided_service_contracts": list(
            fresh.provided_service_contracts
        ),
        "original_unsupported_service_contracts": list(
            original.unsupported_service_contracts
        ),
        "fresh_unsupported_service_contracts": list(
            fresh.unsupported_service_contracts
        ),
        "original_compatibility_status": original.status,
        "fresh_compatibility_status": fresh.status,
        "drift_reasons": list(drift_reasons),
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    revalidation_id = "mhscbr-" + _canonical_sha256(evidence)[:24]

    return ModuleHomeServiceContractBindingRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_binding_id=original.binding_id,
        fresh_binding_id=fresh.binding_id,
        original_module_contract_admission_binding_id=(
            original.module_contract_admission_binding_id
        ),
        fresh_module_contract_admission_binding_id=(
            fresh.module_contract_admission_binding_id
        ),
        original_home_center_version=original.home_center_version,
        fresh_home_center_version=fresh.home_center_version,
        original_module_id=original.module_id,
        fresh_module_id=fresh.module_id,
        original_module_version=original.module_version,
        fresh_module_version=fresh.module_version,
        original_service_profile_sha256=original.service_profile_sha256,
        fresh_service_profile_sha256=fresh.service_profile_sha256,
        original_service_id=original.service_id,
        fresh_service_id=fresh.service_id,
        original_service_kind=original.service_kind,
        fresh_service_kind=fresh.service_kind,
        original_required_service_contracts=original.required_service_contracts,
        fresh_required_service_contracts=fresh.required_service_contracts,
        original_provided_service_contracts=original.provided_service_contracts,
        fresh_provided_service_contracts=fresh.provided_service_contracts,
        original_unsupported_service_contracts=(
            original.unsupported_service_contracts
        ),
        fresh_unsupported_service_contracts=(
            fresh.unsupported_service_contracts
        ),
        original_compatibility_status=original.status,
        fresh_compatibility_status=fresh.status,
        drift_reasons=drift_reasons,
    )
