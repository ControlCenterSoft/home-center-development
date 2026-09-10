"""Exact-state revalidation for Home Center module compatibility admission."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Mapping

from .module_admission import (
    ModuleAdmissionDecision,
    ModuleAdmissionError,
    evaluate_module_compatibility,
)
from .module_artifact import VerifiedModuleArtifact


class ModuleAdmissionRevalidationError(ValueError):
    """Stable rejection code for invalid admission revalidation evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleAdmissionRevalidation:
    """Deterministic exact-state revalidation with no execution authority."""

    revalidation_id: str
    status: str
    original_decision_id: str
    fresh_decision_id: str
    module_id: str
    module_version: str
    manifest_binding_sha256: str
    provenance_statement_sha256: str
    artifact_sha256: str
    original_home_center_version: str
    fresh_home_center_version: str
    original_architecture: str
    fresh_architecture: str
    original_operating_system: str
    fresh_operating_system: str
    original_available_capabilities: tuple[str, ...]
    fresh_available_capabilities: tuple[str, ...]
    original_installed_modules: tuple[tuple[str, str], ...]
    fresh_installed_modules: tuple[tuple[str, str], ...]
    original_compatibility_status: str
    fresh_compatibility_status: str
    original_reasons: tuple[str, ...]
    fresh_reasons: tuple[str, ...]
    drift_reasons: tuple[str, ...]
    schema: str = "home-center.module-admission-revalidation.v1"
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    @property
    def current(self) -> bool:
        return self.status == "current"

    def to_dict(self) -> dict[str, object]:
        def modules(values: tuple[tuple[str, str], ...]) -> list[dict[str, str]]:
            return [
                {"id": module_id, "version": version}
                for module_id, version in values
            ]

        return {
            "schema": self.schema,
            "revalidation_id": self.revalidation_id,
            "status": self.status,
            "original_decision_id": self.original_decision_id,
            "fresh_decision_id": self.fresh_decision_id,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "manifest_binding_sha256": self.manifest_binding_sha256,
            "provenance_statement_sha256": self.provenance_statement_sha256,
            "artifact_sha256": self.artifact_sha256,
            "original_home_center_version": self.original_home_center_version,
            "fresh_home_center_version": self.fresh_home_center_version,
            "original_architecture": self.original_architecture,
            "fresh_architecture": self.fresh_architecture,
            "original_operating_system": self.original_operating_system,
            "fresh_operating_system": self.fresh_operating_system,
            "original_available_capabilities": list(
                self.original_available_capabilities
            ),
            "fresh_available_capabilities": list(self.fresh_available_capabilities),
            "original_installed_modules": modules(self.original_installed_modules),
            "fresh_installed_modules": modules(self.fresh_installed_modules),
            "original_compatibility_status": self.original_compatibility_status,
            "fresh_compatibility_status": self.fresh_compatibility_status,
            "original_reasons": list(self.original_reasons),
            "fresh_reasons": list(self.fresh_reasons),
            "drift_reasons": list(self.drift_reasons),
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": self.external_publication_authorized,
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
        raise ModuleAdmissionRevalidationError(
            "revalidation_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _reconstruct_original_decision(
    manifest: dict[str, object],
    verified: VerifiedModuleArtifact,
    original: ModuleAdmissionDecision,
) -> ModuleAdmissionDecision:
    if not isinstance(original, ModuleAdmissionDecision):
        raise ModuleAdmissionRevalidationError(
            "original_decision_evidence_rejected"
        )
    try:
        reconstructed = evaluate_module_compatibility(
            manifest,
            verified,
            home_center_version=original.home_center_version,
            architecture=original.architecture,
            operating_system=original.operating_system,
            available_capabilities=original.available_capabilities,
            installed_modules=dict(original.installed_modules),
        )
        original_payload = original.to_dict()
        reconstructed_payload = reconstructed.to_dict()
    except (ModuleAdmissionError, TypeError, ValueError) as exc:
        raise ModuleAdmissionRevalidationError(
            "original_decision_evidence_rejected"
        ) from exc

    if original_payload != reconstructed_payload:
        raise ModuleAdmissionRevalidationError(
            "original_decision_evidence_rejected"
        )
    return reconstructed


def revalidate_module_compatibility_decision(
    manifest: dict[str, object],
    verified: VerifiedModuleArtifact,
    original: ModuleAdmissionDecision,
    *,
    home_center_version: str,
    architecture: str,
    operating_system: str,
    available_capabilities: Iterable[str],
    installed_modules: Mapping[str, str],
) -> ModuleAdmissionRevalidation:
    """Revalidate one exact admission decision against a fresh runtime snapshot."""

    trusted_original = _reconstruct_original_decision(manifest, verified, original)
    try:
        fresh = evaluate_module_compatibility(
            manifest,
            verified,
            home_center_version=home_center_version,
            architecture=architecture,
            operating_system=operating_system,
            available_capabilities=available_capabilities,
            installed_modules=installed_modules,
        )
    except ModuleAdmissionError as exc:
        raise ModuleAdmissionRevalidationError(
            "fresh_runtime_evidence_rejected"
        ) from exc

    drift: list[str] = []
    if trusted_original.home_center_version != fresh.home_center_version:
        drift.append("home_center_version_changed")
    if trusted_original.architecture != fresh.architecture:
        drift.append("architecture_changed")
    if trusted_original.operating_system != fresh.operating_system:
        drift.append("operating_system_changed")
    if (
        trusted_original.available_capabilities
        != fresh.available_capabilities
    ):
        drift.append("capability_set_changed")
    if trusted_original.installed_modules != fresh.installed_modules:
        drift.append("installed_module_set_changed")
    if trusted_original.status != fresh.status:
        drift.append("compatibility_status_changed")
    if trusted_original.reasons != fresh.reasons:
        drift.append("compatibility_reasons_changed")
    if not drift and trusted_original.decision_id != fresh.decision_id:
        drift.append("decision_evidence_changed")

    drift_reasons = tuple(sorted(drift))
    status = "current" if not drift_reasons else "stale"
    evidence = {
        "schema": "home-center.module-admission-revalidation.v1",
        "status": status,
        "original_decision_id": trusted_original.decision_id,
        "fresh_decision_id": fresh.decision_id,
        "module_id": fresh.module_id,
        "module_version": fresh.module_version,
        "manifest_binding_sha256": fresh.manifest_binding_sha256,
        "provenance_statement_sha256": fresh.provenance_statement_sha256,
        "artifact_sha256": fresh.artifact_sha256,
        "original_home_center_version": trusted_original.home_center_version,
        "fresh_home_center_version": fresh.home_center_version,
        "original_architecture": trusted_original.architecture,
        "fresh_architecture": fresh.architecture,
        "original_operating_system": trusted_original.operating_system,
        "fresh_operating_system": fresh.operating_system,
        "original_available_capabilities": trusted_original.available_capabilities,
        "fresh_available_capabilities": fresh.available_capabilities,
        "original_installed_modules": [
            {"id": module_id, "version": version}
            for module_id, version in trusted_original.installed_modules
        ],
        "fresh_installed_modules": [
            {"id": module_id, "version": version}
            for module_id, version in fresh.installed_modules
        ],
        "original_compatibility_status": trusted_original.status,
        "fresh_compatibility_status": fresh.status,
        "original_reasons": trusted_original.reasons,
        "fresh_reasons": fresh.reasons,
        "drift_reasons": drift_reasons,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    revalidation_id = "madr-" + _canonical_sha256(evidence)[:24]
    return ModuleAdmissionRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_decision_id=trusted_original.decision_id,
        fresh_decision_id=fresh.decision_id,
        module_id=fresh.module_id,
        module_version=fresh.module_version,
        manifest_binding_sha256=fresh.manifest_binding_sha256,
        provenance_statement_sha256=fresh.provenance_statement_sha256,
        artifact_sha256=fresh.artifact_sha256,
        original_home_center_version=trusted_original.home_center_version,
        fresh_home_center_version=fresh.home_center_version,
        original_architecture=trusted_original.architecture,
        fresh_architecture=fresh.architecture,
        original_operating_system=trusted_original.operating_system,
        fresh_operating_system=fresh.operating_system,
        original_available_capabilities=trusted_original.available_capabilities,
        fresh_available_capabilities=fresh.available_capabilities,
        original_installed_modules=trusted_original.installed_modules,
        fresh_installed_modules=fresh.installed_modules,
        original_compatibility_status=trusted_original.status,
        fresh_compatibility_status=fresh.status,
        original_reasons=trusted_original.reasons,
        fresh_reasons=fresh.reasons,
        drift_reasons=drift_reasons,
    )
