"""Batch exact-state revalidation for Home Center module admission bindings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Sequence

from .module_admission import ModuleAdmissionDecision
from .module_admission_revalidation import (
    ModuleAdmissionRevalidationError,
    revalidate_module_compatibility_decision,
)
from .module_artifact import VerifiedModuleArtifact
from .module_compatibility_snapshot import (
    ModuleAdmissionSnapshotBinding,
    ModuleCompatibilitySnapshot,
    ModuleCompatibilitySnapshotError,
    bind_module_admission_decisions_to_snapshot,
    build_module_compatibility_snapshot,
)


MAX_ADMISSION_SET_MEMBERS = 256


class ModuleAdmissionSetRevalidationError(ValueError):
    """Stable rejection code for malformed or mismatched admission-set evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleAdmissionSetMember:
    """Trusted inputs needed to reconstruct and revalidate one admission decision."""

    manifest: dict[str, object]
    verified: VerifiedModuleArtifact
    decision: ModuleAdmissionDecision


@dataclass(frozen=True, slots=True)
class ModuleAdmissionSetRevalidation:
    """Atomic evidence that one bound admission set is current or stale."""

    revalidation_id: str
    status: str
    original_binding_id: str
    original_snapshot_id: str
    fresh_snapshot_id: str
    snapshot_drift_reasons: tuple[str, ...]
    members: tuple[
        tuple[str, str, str, str, str, str, tuple[str, ...]], ...
    ]
    stale_module_ids: tuple[str, ...]
    schema: str = "home-center.module-admission-set-revalidation.v1"
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
            "original_snapshot_id": self.original_snapshot_id,
            "fresh_snapshot_id": self.fresh_snapshot_id,
            "snapshot_drift_reasons": list(self.snapshot_drift_reasons),
            "members": [
                {
                    "module_id": module_id,
                    "module_version": module_version,
                    "original_decision_id": original_decision_id,
                    "fresh_decision_id": fresh_decision_id,
                    "status": status,
                    "fresh_compatibility_status": fresh_compatibility_status,
                    "drift_reasons": list(drift_reasons),
                }
                for (
                    module_id,
                    module_version,
                    original_decision_id,
                    fresh_decision_id,
                    status,
                    fresh_compatibility_status,
                    drift_reasons,
                ) in self.members
            ],
            "stale_module_ids": list(self.stale_module_ids),
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
        raise ModuleAdmissionSetRevalidationError(
            "admission_set_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _reconstruct_snapshot(
    snapshot: ModuleCompatibilitySnapshot,
    *,
    code: str,
) -> ModuleCompatibilitySnapshot:
    if not isinstance(snapshot, ModuleCompatibilitySnapshot):
        raise ModuleAdmissionSetRevalidationError(code)
    try:
        reconstructed = build_module_compatibility_snapshot(
            home_center_version=snapshot.home_center_version,
            architecture=snapshot.architecture,
            operating_system=snapshot.operating_system,
            available_capabilities=snapshot.available_capabilities,
            installed_modules=dict(snapshot.installed_modules),
        )
        supplied_payload = snapshot.to_dict()
        reconstructed_payload = reconstructed.to_dict()
    except (ModuleCompatibilitySnapshotError, TypeError, ValueError) as exc:
        raise ModuleAdmissionSetRevalidationError(code) from exc
    if supplied_payload != reconstructed_payload:
        raise ModuleAdmissionSetRevalidationError(code)
    return reconstructed


def _snapshot_drift(
    original: ModuleCompatibilitySnapshot,
    fresh: ModuleCompatibilitySnapshot,
) -> tuple[str, ...]:
    drift: list[str] = []
    if original.home_center_version != fresh.home_center_version:
        drift.append("home_center_version_changed")
    if original.architecture != fresh.architecture:
        drift.append("architecture_changed")
    if original.operating_system != fresh.operating_system:
        drift.append("operating_system_changed")
    if original.available_capabilities != fresh.available_capabilities:
        drift.append("capability_set_changed")
    if original.installed_modules != fresh.installed_modules:
        drift.append("installed_module_set_changed")
    if not drift and original.snapshot_id != fresh.snapshot_id:
        drift.append("snapshot_evidence_changed")
    return tuple(sorted(drift))


def revalidate_module_admission_set(
    original_snapshot: ModuleCompatibilitySnapshot,
    original_binding: ModuleAdmissionSnapshotBinding,
    members: Sequence[ModuleAdmissionSetMember],
    fresh_snapshot: ModuleCompatibilitySnapshot,
) -> ModuleAdmissionSetRevalidation:
    """Revalidate a complete bound admission set against one fresh runtime snapshot."""

    trusted_original_snapshot = _reconstruct_snapshot(
        original_snapshot,
        code="original_snapshot_evidence_rejected",
    )
    trusted_fresh_snapshot = _reconstruct_snapshot(
        fresh_snapshot,
        code="fresh_snapshot_evidence_rejected",
    )
    if not isinstance(original_binding, ModuleAdmissionSnapshotBinding):
        raise ModuleAdmissionSetRevalidationError(
            "original_binding_evidence_rejected"
        )
    if (
        isinstance(members, (str, bytes))
        or not isinstance(members, Sequence)
        or not 1 <= len(members) <= MAX_ADMISSION_SET_MEMBERS
    ):
        raise ModuleAdmissionSetRevalidationError("admission_set_members_rejected")

    decisions: list[ModuleAdmissionDecision] = []
    normalized_members: list[ModuleAdmissionSetMember] = []
    for member in members:
        if not isinstance(member, ModuleAdmissionSetMember):
            raise ModuleAdmissionSetRevalidationError(
                "admission_set_member_rejected"
            )
        decisions.append(member.decision)
        normalized_members.append(member)

    try:
        reconstructed_binding = bind_module_admission_decisions_to_snapshot(
            trusted_original_snapshot,
            decisions,
        )
        supplied_binding_payload = original_binding.to_dict()
        reconstructed_binding_payload = reconstructed_binding.to_dict()
    except (ModuleCompatibilitySnapshotError, TypeError, ValueError) as exc:
        raise ModuleAdmissionSetRevalidationError(
            "original_binding_evidence_rejected"
        ) from exc
    if supplied_binding_payload != reconstructed_binding_payload:
        raise ModuleAdmissionSetRevalidationError(
            "original_binding_evidence_rejected"
        )

    results: list[tuple[str, str, str, str, str, str, tuple[str, ...]]] = []
    stale_module_ids: list[str] = []
    for member in sorted(
        normalized_members,
        key=lambda item: (item.decision.module_id, item.decision.decision_id),
    ):
        try:
            result = revalidate_module_compatibility_decision(
                member.manifest,
                member.verified,
                member.decision,
                home_center_version=trusted_fresh_snapshot.home_center_version,
                architecture=trusted_fresh_snapshot.architecture,
                operating_system=trusted_fresh_snapshot.operating_system,
                available_capabilities=trusted_fresh_snapshot.available_capabilities,
                installed_modules=dict(trusted_fresh_snapshot.installed_modules),
            )
        except (ModuleAdmissionRevalidationError, TypeError, ValueError) as exc:
            raise ModuleAdmissionSetRevalidationError(
                "admission_set_member_revalidation_rejected"
            ) from exc
        if result.module_id != member.decision.module_id:
            raise ModuleAdmissionSetRevalidationError(
                "admission_set_member_revalidation_rejected"
            )
        results.append(
            (
                result.module_id,
                result.module_version,
                result.original_decision_id,
                result.fresh_decision_id,
                result.status,
                result.fresh_compatibility_status,
                result.drift_reasons,
            )
        )
        if result.status != "current":
            stale_module_ids.append(result.module_id)

    snapshot_drift_reasons = _snapshot_drift(
        trusted_original_snapshot,
        trusted_fresh_snapshot,
    )
    stale_modules = tuple(sorted(stale_module_ids))
    status = (
        "current"
        if not snapshot_drift_reasons and not stale_modules
        else "stale"
    )
    normalized_results = tuple(results)
    evidence = {
        "schema": "home-center.module-admission-set-revalidation.v1",
        "status": status,
        "original_binding_id": reconstructed_binding.binding_id,
        "original_snapshot_id": trusted_original_snapshot.snapshot_id,
        "fresh_snapshot_id": trusted_fresh_snapshot.snapshot_id,
        "snapshot_drift_reasons": snapshot_drift_reasons,
        "members": [
            {
                "module_id": module_id,
                "module_version": module_version,
                "original_decision_id": original_decision_id,
                "fresh_decision_id": fresh_decision_id,
                "status": member_status,
                "fresh_compatibility_status": fresh_compatibility_status,
                "drift_reasons": drift_reasons,
            }
            for (
                module_id,
                module_version,
                original_decision_id,
                fresh_decision_id,
                member_status,
                fresh_compatibility_status,
                drift_reasons,
            ) in normalized_results
        ],
        "stale_module_ids": stale_modules,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    revalidation_id = "masr-" + _canonical_sha256(evidence)[:24]
    return ModuleAdmissionSetRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_binding_id=reconstructed_binding.binding_id,
        original_snapshot_id=trusted_original_snapshot.snapshot_id,
        fresh_snapshot_id=trusted_fresh_snapshot.snapshot_id,
        snapshot_drift_reasons=snapshot_drift_reasons,
        members=normalized_results,
        stale_module_ids=stale_modules,
    )
