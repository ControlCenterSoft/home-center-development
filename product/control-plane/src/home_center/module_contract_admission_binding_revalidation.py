"""Exact-state revalidation for module contract admission bindings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .module_contract_admission_binding import (
    ModuleContractAdmissionBinding,
    ModuleContractAdmissionBindingError,
    bind_module_contract_admission,
)

REVALIDATION_SCHEMA = (
    "home-center.module-contract-admission-binding-revalidation.v1"
)


class ModuleContractAdmissionBindingRevalidationError(ValueError):
    """Stable rejection code for invalid contract-binding revalidation evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleContractAdmissionBindingRevalidation:
    """Deterministic evidence describing whether an exact binding is current."""

    revalidation_id: str
    status: str
    original_binding_id: str
    fresh_binding_id: str
    original_profile_id: str
    fresh_profile_id: str
    original_negotiation_decision_id: str
    fresh_negotiation_decision_id: str
    original_admission_decision_id: str
    fresh_admission_decision_id: str
    original_home_center_version: str
    fresh_home_center_version: str
    original_module_manifest_schema: str
    fresh_module_manifest_schema: str
    original_module_admission_schema: str
    fresh_module_admission_schema: str
    original_module_id: str
    fresh_module_id: str
    original_module_version: str
    fresh_module_version: str
    original_manifest_binding_sha256: str
    fresh_manifest_binding_sha256: str
    original_artifact_sha256: str
    fresh_artifact_sha256: str
    original_admission_status: str
    fresh_admission_status: str
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
            "original_profile_id": self.original_profile_id,
            "fresh_profile_id": self.fresh_profile_id,
            "original_negotiation_decision_id": (
                self.original_negotiation_decision_id
            ),
            "fresh_negotiation_decision_id": self.fresh_negotiation_decision_id,
            "original_admission_decision_id": self.original_admission_decision_id,
            "fresh_admission_decision_id": self.fresh_admission_decision_id,
            "original_home_center_version": self.original_home_center_version,
            "fresh_home_center_version": self.fresh_home_center_version,
            "original_module_manifest_schema": self.original_module_manifest_schema,
            "fresh_module_manifest_schema": self.fresh_module_manifest_schema,
            "original_module_admission_schema": (
                self.original_module_admission_schema
            ),
            "fresh_module_admission_schema": self.fresh_module_admission_schema,
            "original_module_id": self.original_module_id,
            "fresh_module_id": self.fresh_module_id,
            "original_module_version": self.original_module_version,
            "fresh_module_version": self.fresh_module_version,
            "original_manifest_binding_sha256": (
                self.original_manifest_binding_sha256
            ),
            "fresh_manifest_binding_sha256": self.fresh_manifest_binding_sha256,
            "original_artifact_sha256": self.original_artifact_sha256,
            "fresh_artifact_sha256": self.fresh_artifact_sha256,
            "original_admission_status": self.original_admission_status,
            "fresh_admission_status": self.fresh_admission_status,
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
        raise ModuleContractAdmissionBindingRevalidationError(
            "binding_revalidation_evidence_rejected"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _reconstruct_original(
    profile: object,
    negotiation: object,
    admission: object,
    original: ModuleContractAdmissionBinding,
) -> ModuleContractAdmissionBinding:
    if not isinstance(original, ModuleContractAdmissionBinding):
        raise ModuleContractAdmissionBindingRevalidationError(
            "original_contract_admission_binding_rejected"
        )
    try:
        reconstructed = bind_module_contract_admission(
            profile,
            negotiation,
            admission,
        )
        original_payload = original.to_dict()
        reconstructed_payload = reconstructed.to_dict()
    except (ModuleContractAdmissionBindingError, TypeError, ValueError) as exc:
        raise ModuleContractAdmissionBindingRevalidationError(
            "original_contract_admission_binding_rejected"
        ) from exc
    if original_payload != reconstructed_payload:
        raise ModuleContractAdmissionBindingRevalidationError(
            "original_contract_admission_binding_rejected"
        )
    return reconstructed


def _fresh_binding(
    profile: object,
    negotiation: object,
    admission: object,
) -> ModuleContractAdmissionBinding:
    try:
        return bind_module_contract_admission(
            profile,
            negotiation,
            admission,
        )
    except (ModuleContractAdmissionBindingError, TypeError, ValueError) as exc:
        raise ModuleContractAdmissionBindingRevalidationError(
            "fresh_contract_admission_binding_rejected"
        ) from exc


def revalidate_module_contract_admission_binding(
    original_profile: object,
    original_negotiation: object,
    original_admission: object,
    original_binding: ModuleContractAdmissionBinding,
    *,
    fresh_profile: object,
    fresh_negotiation: object,
    fresh_admission: object,
) -> ModuleContractAdmissionBindingRevalidation:
    """Revalidate one exact contract/admission binding without side effects."""

    original = _reconstruct_original(
        original_profile,
        original_negotiation,
        original_admission,
        original_binding,
    )
    fresh = _fresh_binding(
        fresh_profile,
        fresh_negotiation,
        fresh_admission,
    )

    drift: set[str] = set()
    comparisons = (
        (
            "contract_profile_changed",
            original.profile_id,
            fresh.profile_id,
        ),
        (
            "contract_negotiation_changed",
            original.negotiation_decision_id,
            fresh.negotiation_decision_id,
        ),
        (
            "module_admission_changed",
            original.admission_decision_id,
            fresh.admission_decision_id,
        ),
        (
            "home_center_version_changed",
            original.home_center_version,
            fresh.home_center_version,
        ),
        (
            "module_manifest_contract_changed",
            original.module_manifest_schema,
            fresh.module_manifest_schema,
        ),
        (
            "module_admission_contract_changed",
            original.module_admission_schema,
            fresh.module_admission_schema,
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
            "manifest_binding_changed",
            original.manifest_binding_sha256,
            fresh.manifest_binding_sha256,
        ),
        (
            "artifact_changed",
            original.artifact_sha256,
            fresh.artifact_sha256,
        ),
        (
            "admission_status_changed",
            original.admission_status,
            fresh.admission_status,
        ),
    )
    for reason, old, new in comparisons:
        if old != new:
            drift.add(reason)

    if not drift and original.binding_id != fresh.binding_id:
        drift.add("contract_admission_binding_evidence_changed")

    drift_reasons = tuple(sorted(drift))
    status = "current" if not drift_reasons else "stale"
    evidence = {
        "schema": REVALIDATION_SCHEMA,
        "status": status,
        "original_binding_id": original.binding_id,
        "fresh_binding_id": fresh.binding_id,
        "original_profile_id": original.profile_id,
        "fresh_profile_id": fresh.profile_id,
        "original_negotiation_decision_id": original.negotiation_decision_id,
        "fresh_negotiation_decision_id": fresh.negotiation_decision_id,
        "original_admission_decision_id": original.admission_decision_id,
        "fresh_admission_decision_id": fresh.admission_decision_id,
        "original_home_center_version": original.home_center_version,
        "fresh_home_center_version": fresh.home_center_version,
        "original_module_manifest_schema": original.module_manifest_schema,
        "fresh_module_manifest_schema": fresh.module_manifest_schema,
        "original_module_admission_schema": original.module_admission_schema,
        "fresh_module_admission_schema": fresh.module_admission_schema,
        "original_module_id": original.module_id,
        "fresh_module_id": fresh.module_id,
        "original_module_version": original.module_version,
        "fresh_module_version": fresh.module_version,
        "original_manifest_binding_sha256": original.manifest_binding_sha256,
        "fresh_manifest_binding_sha256": fresh.manifest_binding_sha256,
        "original_artifact_sha256": original.artifact_sha256,
        "fresh_artifact_sha256": fresh.artifact_sha256,
        "original_admission_status": original.admission_status,
        "fresh_admission_status": fresh.admission_status,
        "drift_reasons": list(drift_reasons),
        "admission_authorized": False,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    revalidation_id = "mcabr-" + _canonical_sha256(evidence)[:24]

    return ModuleContractAdmissionBindingRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_binding_id=original.binding_id,
        fresh_binding_id=fresh.binding_id,
        original_profile_id=original.profile_id,
        fresh_profile_id=fresh.profile_id,
        original_negotiation_decision_id=original.negotiation_decision_id,
        fresh_negotiation_decision_id=fresh.negotiation_decision_id,
        original_admission_decision_id=original.admission_decision_id,
        fresh_admission_decision_id=fresh.admission_decision_id,
        original_home_center_version=original.home_center_version,
        fresh_home_center_version=fresh.home_center_version,
        original_module_manifest_schema=original.module_manifest_schema,
        fresh_module_manifest_schema=fresh.module_manifest_schema,
        original_module_admission_schema=original.module_admission_schema,
        fresh_module_admission_schema=fresh.module_admission_schema,
        original_module_id=original.module_id,
        fresh_module_id=fresh.module_id,
        original_module_version=original.module_version,
        fresh_module_version=fresh.module_version,
        original_manifest_binding_sha256=original.manifest_binding_sha256,
        fresh_manifest_binding_sha256=fresh.manifest_binding_sha256,
        original_artifact_sha256=original.artifact_sha256,
        fresh_artifact_sha256=fresh.artifact_sha256,
        original_admission_status=original.admission_status,
        fresh_admission_status=fresh.admission_status,
        drift_reasons=drift_reasons,
    )
