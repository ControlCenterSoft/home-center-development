"""Cross-candidate compatibility evidence for Home Center module admission."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

from .module_admission import (
    ModuleAdmissionDecision,
    ModuleAdmissionError,
    evaluate_module_compatibility,
    validate_module_admission,
)
from .module_artifact import VerifiedModuleArtifact
from .module_compatibility_snapshot import (
    ModuleCompatibilitySnapshot,
    ModuleCompatibilitySnapshotError,
    build_module_compatibility_snapshot,
)

MAX_CANDIDATE_MODULES = 128


class ModuleCandidateSetError(ValueError):
    """Stable rejection code for malformed or inconsistent candidate sets."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleCandidateSetDecision:
    """Deterministic compatibility evidence for one planned module candidate set."""

    candidate_set_id: str
    status: str
    snapshot_id: str
    home_center_version: str
    architecture: str
    operating_system: str
    available_capabilities: tuple[str, ...]
    installed_modules: tuple[tuple[str, str], ...]
    planned_modules: tuple[tuple[str, str], ...]
    candidates: tuple[
        tuple[str, str, str, str, str, str, tuple[str, ...]], ...
    ]
    blocked_modules: tuple[str, ...]
    schema: str = "home-center.module-candidate-set-decision.v1"
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    @property
    def compatible(self) -> bool:
        return self.status == "compatible"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "candidate_set_id": self.candidate_set_id,
            "status": self.status,
            "snapshot_id": self.snapshot_id,
            "home_center_version": self.home_center_version,
            "architecture": self.architecture,
            "operating_system": self.operating_system,
            "available_capabilities": list(self.available_capabilities),
            "installed_modules": [
                {"id": module_id, "version": version}
                for module_id, version in self.installed_modules
            ],
            "planned_modules": [
                {"id": module_id, "version": version}
                for module_id, version in self.planned_modules
            ],
            "candidates": [
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
                ) in self.candidates
            ],
            "blocked_modules": list(self.blocked_modules),
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
        raise ModuleCandidateSetError("candidate_set_evidence_rejected") from exc
    return hashlib.sha256(payload).hexdigest()


def _trusted_snapshot(
    snapshot: ModuleCompatibilitySnapshot,
) -> ModuleCompatibilitySnapshot:
    if not isinstance(snapshot, ModuleCompatibilitySnapshot):
        raise ModuleCandidateSetError("compatibility_snapshot_rejected")
    try:
        rebuilt = build_module_compatibility_snapshot(
            home_center_version=snapshot.home_center_version,
            architecture=snapshot.architecture,
            operating_system=snapshot.operating_system,
            available_capabilities=snapshot.available_capabilities,
            installed_modules=dict(snapshot.installed_modules),
        )
    except (TypeError, ValueError, ModuleCompatibilitySnapshotError) as exc:
        raise ModuleCandidateSetError("compatibility_snapshot_rejected") from exc
    if snapshot.to_dict() != rebuilt.to_dict():
        raise ModuleCandidateSetError("compatibility_snapshot_rejected")
    return rebuilt


def _candidate_input(
    item: object,
) -> tuple[dict[str, Any], VerifiedModuleArtifact]:
    if not isinstance(item, tuple) or len(item) != 2:
        raise ModuleCandidateSetError("candidate_rejected")
    manifest, verified = item
    if not isinstance(manifest, dict) or not isinstance(
        verified, VerifiedModuleArtifact
    ):
        raise ModuleCandidateSetError("candidate_rejected")
    return manifest, verified


def evaluate_module_candidate_set(
    snapshot: ModuleCompatibilitySnapshot,
    candidates: Sequence[tuple[dict[str, Any], VerifiedModuleArtifact]],
) -> ModuleCandidateSetDecision:
    """Evaluate candidates together against one exact runtime snapshot.

    Candidate module versions are overlaid onto the snapshot's installed-module
    map only for compatibility analysis. The result is evidence only and grants
    no installation, execution, mutation or publication authority.
    """

    trusted_snapshot = _trusted_snapshot(snapshot)
    if isinstance(candidates, (str, bytes)) or not isinstance(candidates, Sequence):
        raise ModuleCandidateSetError("candidates_rejected")
    if not 1 <= len(candidates) <= MAX_CANDIDATE_MODULES:
        raise ModuleCandidateSetError("candidates_rejected")

    normalized_inputs: list[
        tuple[str, str, dict[str, Any], VerifiedModuleArtifact]
    ] = []
    module_ids: set[str] = set()
    for raw_candidate in candidates:
        manifest, verified = _candidate_input(raw_candidate)
        try:
            admitted = validate_module_admission(manifest)
        except (ModuleAdmissionError, ValueError, TypeError) as exc:
            raise ModuleCandidateSetError("candidate_manifest_rejected") from exc
        module_id = admitted.identity.module_id
        module_version = admitted.identity.version
        if module_id in module_ids:
            raise ModuleCandidateSetError("candidate_module_duplicate")
        module_ids.add(module_id)
        normalized_inputs.append(
            (module_id, module_version, manifest, verified)
        )

    normalized_inputs.sort(key=lambda item: (item[0], item[1]))

    planned_map = dict(trusted_snapshot.installed_modules)
    for module_id, module_version, _, _ in normalized_inputs:
        planned_map[module_id] = module_version
    planned_modules = tuple(sorted(planned_map.items()))

    decisions: list[ModuleAdmissionDecision] = []
    for _, _, manifest, verified in normalized_inputs:
        try:
            decision = evaluate_module_compatibility(
                manifest,
                verified,
                home_center_version=trusted_snapshot.home_center_version,
                architecture=trusted_snapshot.architecture,
                operating_system=trusted_snapshot.operating_system,
                available_capabilities=trusted_snapshot.available_capabilities,
                installed_modules=planned_map,
            )
        except (ModuleAdmissionError, ValueError, TypeError) as exc:
            raise ModuleCandidateSetError("candidate_evidence_rejected") from exc
        decisions.append(decision)

    candidate_refs = tuple(
        (
            decision.module_id,
            decision.module_version,
            decision.decision_id,
            decision.status,
            decision.manifest_binding_sha256,
            decision.artifact_sha256,
            decision.reasons,
        )
        for decision in decisions
    )
    blocked_modules = tuple(
        decision.module_id for decision in decisions if not decision.compatible
    )
    status = "compatible" if not blocked_modules else "blocked"

    evidence = {
        "schema": "home-center.module-candidate-set-decision.v1",
        "status": status,
        "snapshot_id": trusted_snapshot.snapshot_id,
        "home_center_version": trusted_snapshot.home_center_version,
        "architecture": trusted_snapshot.architecture,
        "operating_system": trusted_snapshot.operating_system,
        "available_capabilities": trusted_snapshot.available_capabilities,
        "installed_modules": [
            {"id": module_id, "version": version}
            for module_id, version in trusted_snapshot.installed_modules
        ],
        "planned_modules": [
            {"id": module_id, "version": version}
            for module_id, version in planned_modules
        ],
        "candidates": [
            {
                "module_id": module_id,
                "module_version": module_version,
                "decision_id": decision_id,
                "status": candidate_status,
                "manifest_binding_sha256": binding,
                "artifact_sha256": artifact_sha256,
                "reasons": list(reasons),
            }
            for (
                module_id,
                module_version,
                decision_id,
                candidate_status,
                binding,
                artifact_sha256,
                reasons,
            ) in candidate_refs
        ],
        "blocked_modules": blocked_modules,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    candidate_set_id = "mcsd-" + _canonical_sha256(evidence)[:24]
    return ModuleCandidateSetDecision(
        candidate_set_id=candidate_set_id,
        status=status,
        snapshot_id=trusted_snapshot.snapshot_id,
        home_center_version=trusted_snapshot.home_center_version,
        architecture=trusted_snapshot.architecture,
        operating_system=trusted_snapshot.operating_system,
        available_capabilities=trusted_snapshot.available_capabilities,
        installed_modules=trusted_snapshot.installed_modules,
        planned_modules=planned_modules,
        candidates=candidate_refs,
        blocked_modules=blocked_modules,
    )
