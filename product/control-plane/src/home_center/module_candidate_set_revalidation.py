"""Exact-state revalidation for Home Center module candidate-set compatibility."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

from .module_artifact import VerifiedModuleArtifact
from .module_candidate_set import (
    ModuleCandidateSetDecision,
    ModuleCandidateSetError,
    evaluate_module_candidate_set,
)
from .module_compatibility_snapshot import ModuleCompatibilitySnapshot

CandidateInput = tuple[dict[str, Any], VerifiedModuleArtifact]


class ModuleCandidateSetRevalidationError(ValueError):
    """Stable rejection code for invalid candidate-set revalidation evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleCandidateSetRevalidation:
    """Deterministic revalidation evidence with no installation authority."""

    revalidation_id: str
    status: str
    original_candidate_set_id: str
    fresh_candidate_set_id: str
    original_snapshot_id: str
    fresh_snapshot_id: str
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
    original_planned_modules: tuple[tuple[str, str], ...]
    fresh_planned_modules: tuple[tuple[str, str], ...]
    original_candidates: tuple[
        tuple[str, str, str, str, str, str, tuple[str, ...]], ...
    ]
    fresh_candidates: tuple[
        tuple[str, str, str, str, str, str, tuple[str, ...]], ...
    ]
    original_blocked_modules: tuple[str, ...]
    fresh_blocked_modules: tuple[str, ...]
    stale_modules: tuple[str, ...]
    drift_reasons: tuple[str, ...]
    schema: str = "home-center.module-candidate-set-revalidation.v1"
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

        def candidates(
            values: tuple[
                tuple[str, str, str, str, str, str, tuple[str, ...]], ...
            ],
        ) -> list[dict[str, object]]:
            return [
                {
                    "module_id": module_id,
                    "module_version": module_version,
                    "decision_id": decision_id,
                    "status": status,
                    "manifest_binding_sha256": manifest_binding_sha256,
                    "artifact_sha256": artifact_sha256,
                    "reasons": list(reasons),
                }
                for (
                    module_id,
                    module_version,
                    decision_id,
                    status,
                    manifest_binding_sha256,
                    artifact_sha256,
                    reasons,
                ) in values
            ]

        return {
            "schema": self.schema,
            "revalidation_id": self.revalidation_id,
            "status": self.status,
            "original_candidate_set_id": self.original_candidate_set_id,
            "fresh_candidate_set_id": self.fresh_candidate_set_id,
            "original_snapshot_id": self.original_snapshot_id,
            "fresh_snapshot_id": self.fresh_snapshot_id,
            "original_home_center_version": self.original_home_center_version,
            "fresh_home_center_version": self.fresh_home_center_version,
            "original_architecture": self.original_architecture,
            "fresh_architecture": self.fresh_architecture,
            "original_operating_system": self.original_operating_system,
            "fresh_operating_system": self.fresh_operating_system,
            "original_available_capabilities": list(
                self.original_available_capabilities
            ),
            "fresh_available_capabilities": list(
                self.fresh_available_capabilities
            ),
            "original_installed_modules": modules(self.original_installed_modules),
            "fresh_installed_modules": modules(self.fresh_installed_modules),
            "original_planned_modules": modules(self.original_planned_modules),
            "fresh_planned_modules": modules(self.fresh_planned_modules),
            "original_candidates": candidates(self.original_candidates),
            "fresh_candidates": candidates(self.fresh_candidates),
            "original_blocked_modules": list(self.original_blocked_modules),
            "fresh_blocked_modules": list(self.fresh_blocked_modules),
            "stale_modules": list(self.stale_modules),
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
        raise ModuleCandidateSetRevalidationError(
            "candidate_set_revalidation_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _reconstruct_original(
    snapshot: ModuleCompatibilitySnapshot,
    candidates: Sequence[CandidateInput],
    original: ModuleCandidateSetDecision,
) -> ModuleCandidateSetDecision:
    if not isinstance(original, ModuleCandidateSetDecision):
        raise ModuleCandidateSetRevalidationError(
            "original_candidate_set_evidence_rejected"
        )
    try:
        reconstructed = evaluate_module_candidate_set(snapshot, candidates)
        original_payload = original.to_dict()
        reconstructed_payload = reconstructed.to_dict()
    except (ModuleCandidateSetError, TypeError, ValueError) as exc:
        raise ModuleCandidateSetRevalidationError(
            "original_candidate_set_evidence_rejected"
        ) from exc
    if original_payload != reconstructed_payload:
        raise ModuleCandidateSetRevalidationError(
            "original_candidate_set_evidence_rejected"
        )
    return reconstructed


def _fresh_candidate_set(
    snapshot: ModuleCompatibilitySnapshot,
    candidates: Sequence[CandidateInput],
) -> ModuleCandidateSetDecision:
    try:
        return evaluate_module_candidate_set(snapshot, candidates)
    except (ModuleCandidateSetError, TypeError, ValueError) as exc:
        raise ModuleCandidateSetRevalidationError(
            "fresh_candidate_set_evidence_rejected"
        ) from exc


def revalidate_module_candidate_set(
    original_snapshot: ModuleCompatibilitySnapshot,
    original_candidates: Sequence[CandidateInput],
    original: ModuleCandidateSetDecision,
    *,
    fresh_snapshot: ModuleCompatibilitySnapshot,
    fresh_candidates: Sequence[CandidateInput] | None = None,
) -> ModuleCandidateSetRevalidation:
    """Revalidate one exact candidate set against fresh runtime/candidate evidence.

    The original candidate-set decision is reconstructed before use. The fresh
    decision is then independently evaluated against a canonical fresh runtime
    snapshot. A changed runtime state or candidate composition makes the old
    exact-state evidence stale even when the resulting compatibility status
    remains compatible.
    """

    trusted_original = _reconstruct_original(
        original_snapshot,
        original_candidates,
        original,
    )
    current_candidates = (
        original_candidates if fresh_candidates is None else fresh_candidates
    )
    fresh = _fresh_candidate_set(fresh_snapshot, current_candidates)

    drift: set[str] = set()
    stale_modules: set[str] = set()

    if trusted_original.snapshot_id != fresh.snapshot_id:
        drift.add("snapshot_changed")
    if trusted_original.home_center_version != fresh.home_center_version:
        drift.add("home_center_version_changed")
    if trusted_original.architecture != fresh.architecture:
        drift.add("architecture_changed")
    if trusted_original.operating_system != fresh.operating_system:
        drift.add("operating_system_changed")
    if (
        trusted_original.available_capabilities
        != fresh.available_capabilities
    ):
        drift.add("capability_set_changed")
    if trusted_original.installed_modules != fresh.installed_modules:
        drift.add("installed_module_set_changed")
    if trusted_original.planned_modules != fresh.planned_modules:
        drift.add("planned_module_set_changed")
    if trusted_original.blocked_modules != fresh.blocked_modules:
        drift.add("blocked_module_set_changed")
    if trusted_original.status != fresh.status:
        drift.add("set_compatibility_status_changed")

    original_by_module = {
        candidate[0]: candidate for candidate in trusted_original.candidates
    }
    fresh_by_module = {candidate[0]: candidate for candidate in fresh.candidates}
    original_ids = set(original_by_module)
    fresh_ids = set(fresh_by_module)

    if original_ids != fresh_ids:
        drift.add("candidate_membership_changed")
        stale_modules.update(original_ids.symmetric_difference(fresh_ids))

    for module_id in sorted(original_ids.intersection(fresh_ids)):
        original_candidate = original_by_module[module_id]
        fresh_candidate = fresh_by_module[module_id]

        if original_candidate[1] != fresh_candidate[1]:
            drift.add("candidate_version_changed")
        if (
            original_candidate[4] != fresh_candidate[4]
            or original_candidate[5] != fresh_candidate[5]
        ):
            drift.add("candidate_artifact_evidence_changed")
        if (
            original_candidate[3] != fresh_candidate[3]
            or original_candidate[6] != fresh_candidate[6]
        ):
            drift.add("candidate_compatibility_changed")
        if original_candidate[2] != fresh_candidate[2]:
            drift.add("candidate_decision_evidence_changed")
        if original_candidate != fresh_candidate:
            stale_modules.add(module_id)

    if not drift and trusted_original.candidate_set_id != fresh.candidate_set_id:
        drift.add("candidate_set_evidence_changed")
        stale_modules.update(original_ids.union(fresh_ids))

    drift_reasons = tuple(sorted(drift))
    stale_module_ids = tuple(sorted(stale_modules))
    status = "current" if not drift_reasons else "stale"

    evidence = {
        "schema": "home-center.module-candidate-set-revalidation.v1",
        "status": status,
        "original_candidate_set_id": trusted_original.candidate_set_id,
        "fresh_candidate_set_id": fresh.candidate_set_id,
        "original_snapshot_id": trusted_original.snapshot_id,
        "fresh_snapshot_id": fresh.snapshot_id,
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
        "original_planned_modules": [
            {"id": module_id, "version": version}
            for module_id, version in trusted_original.planned_modules
        ],
        "fresh_planned_modules": [
            {"id": module_id, "version": version}
            for module_id, version in fresh.planned_modules
        ],
        "original_candidates": trusted_original.to_dict()["candidates"],
        "fresh_candidates": fresh.to_dict()["candidates"],
        "original_blocked_modules": trusted_original.blocked_modules,
        "fresh_blocked_modules": fresh.blocked_modules,
        "stale_modules": stale_module_ids,
        "drift_reasons": drift_reasons,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    revalidation_id = "mcsr-" + _canonical_sha256(evidence)[:24]

    return ModuleCandidateSetRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_candidate_set_id=trusted_original.candidate_set_id,
        fresh_candidate_set_id=fresh.candidate_set_id,
        original_snapshot_id=trusted_original.snapshot_id,
        fresh_snapshot_id=fresh.snapshot_id,
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
        original_planned_modules=trusted_original.planned_modules,
        fresh_planned_modules=fresh.planned_modules,
        original_candidates=trusted_original.candidates,
        fresh_candidates=fresh.candidates,
        original_blocked_modules=trusted_original.blocked_modules,
        fresh_blocked_modules=fresh.blocked_modules,
        stale_modules=stale_module_ids,
        drift_reasons=drift_reasons,
    )
