"""Exact-state revalidation for policy-bound Home Center module candidate sets."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

from .module_artifact import VerifiedModuleArtifact
from .module_compatibility_policy import (
    ModuleCompatibilityPolicyError,
    ModuleCompatibilityPolicySnapshot,
    ModulePolicyCandidateSetDecision,
    evaluate_module_candidate_set_under_policy,
)
from .module_compatibility_snapshot import ModuleCompatibilitySnapshot

CandidateInput = tuple[dict[str, Any], VerifiedModuleArtifact]


class ModulePolicyCandidateSetRevalidationError(ValueError):
    """Stable rejection code for invalid policy-bound revalidation evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModulePolicyCandidateSetRevalidation:
    """Deterministic policy-bound revalidation evidence without authority."""

    revalidation_id: str
    status: str
    original_decision_id: str
    fresh_decision_id: str
    original_policy_id: str
    fresh_policy_id: str
    original_policy_version: str
    fresh_policy_version: str
    original_candidate_set_id: str
    fresh_candidate_set_id: str
    original_snapshot_id: str
    fresh_snapshot_id: str
    original_status: str
    fresh_status: str
    original_base_status: str
    fresh_base_status: str
    original_base_blocked_modules: tuple[str, ...]
    fresh_base_blocked_modules: tuple[str, ...]
    original_policy_blocked_modules: tuple[str, ...]
    fresh_policy_blocked_modules: tuple[str, ...]
    original_blocked_modules: tuple[str, ...]
    fresh_blocked_modules: tuple[str, ...]
    original_missing_required_runtime_capabilities: tuple[str, ...]
    fresh_missing_required_runtime_capabilities: tuple[str, ...]
    original_policy_reasons: tuple[str, ...]
    fresh_policy_reasons: tuple[str, ...]
    original_modules: tuple[tuple[str, str, tuple[str, ...]], ...]
    fresh_modules: tuple[tuple[str, str, tuple[str, ...]], ...]
    stale_modules: tuple[str, ...]
    drift_reasons: tuple[str, ...]
    schema: str = "home-center.module-policy-candidate-set-revalidation.v1"
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    @property
    def current(self) -> bool:
        return self.status == "current"

    def to_dict(self) -> dict[str, object]:
        def module_results(
            values: tuple[tuple[str, str, tuple[str, ...]], ...],
        ) -> list[dict[str, object]]:
            return [
                {
                    "module_id": module_id,
                    "publisher": publisher,
                    "policy_reasons": list(reasons),
                }
                for module_id, publisher, reasons in values
            ]

        return {
            "schema": self.schema,
            "revalidation_id": self.revalidation_id,
            "status": self.status,
            "original_decision_id": self.original_decision_id,
            "fresh_decision_id": self.fresh_decision_id,
            "original_policy_id": self.original_policy_id,
            "fresh_policy_id": self.fresh_policy_id,
            "original_policy_version": self.original_policy_version,
            "fresh_policy_version": self.fresh_policy_version,
            "original_candidate_set_id": self.original_candidate_set_id,
            "fresh_candidate_set_id": self.fresh_candidate_set_id,
            "original_snapshot_id": self.original_snapshot_id,
            "fresh_snapshot_id": self.fresh_snapshot_id,
            "original_status": self.original_status,
            "fresh_status": self.fresh_status,
            "original_base_status": self.original_base_status,
            "fresh_base_status": self.fresh_base_status,
            "original_base_blocked_modules": list(
                self.original_base_blocked_modules
            ),
            "fresh_base_blocked_modules": list(
                self.fresh_base_blocked_modules
            ),
            "original_policy_blocked_modules": list(
                self.original_policy_blocked_modules
            ),
            "fresh_policy_blocked_modules": list(
                self.fresh_policy_blocked_modules
            ),
            "original_blocked_modules": list(self.original_blocked_modules),
            "fresh_blocked_modules": list(self.fresh_blocked_modules),
            "original_missing_required_runtime_capabilities": list(
                self.original_missing_required_runtime_capabilities
            ),
            "fresh_missing_required_runtime_capabilities": list(
                self.fresh_missing_required_runtime_capabilities
            ),
            "original_policy_reasons": list(self.original_policy_reasons),
            "fresh_policy_reasons": list(self.fresh_policy_reasons),
            "original_modules": module_results(self.original_modules),
            "fresh_modules": module_results(self.fresh_modules),
            "stale_modules": list(self.stale_modules),
            "drift_reasons": list(self.drift_reasons),
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": (
                self.external_publication_authorized
            ),
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
        raise ModulePolicyCandidateSetRevalidationError(
            "policy_candidate_set_revalidation_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _reconstruct_original(
    policy: ModuleCompatibilityPolicySnapshot,
    snapshot: ModuleCompatibilitySnapshot,
    candidates: Sequence[CandidateInput],
    original: ModulePolicyCandidateSetDecision,
) -> ModulePolicyCandidateSetDecision:
    if not isinstance(original, ModulePolicyCandidateSetDecision):
        raise ModulePolicyCandidateSetRevalidationError(
            "original_policy_candidate_set_evidence_rejected"
        )
    try:
        reconstructed = evaluate_module_candidate_set_under_policy(
            policy,
            snapshot,
            candidates,
        )
        original_payload = original.to_dict()
        reconstructed_payload = reconstructed.to_dict()
    except (ModuleCompatibilityPolicyError, TypeError, ValueError) as exc:
        raise ModulePolicyCandidateSetRevalidationError(
            "original_policy_candidate_set_evidence_rejected"
        ) from exc
    if original_payload != reconstructed_payload:
        raise ModulePolicyCandidateSetRevalidationError(
            "original_policy_candidate_set_evidence_rejected"
        )
    return reconstructed


def _fresh_decision(
    policy: ModuleCompatibilityPolicySnapshot,
    snapshot: ModuleCompatibilitySnapshot,
    candidates: Sequence[CandidateInput],
) -> ModulePolicyCandidateSetDecision:
    try:
        return evaluate_module_candidate_set_under_policy(
            policy,
            snapshot,
            candidates,
        )
    except (ModuleCompatibilityPolicyError, TypeError, ValueError) as exc:
        raise ModulePolicyCandidateSetRevalidationError(
            "fresh_policy_candidate_set_evidence_rejected"
        ) from exc


def revalidate_module_candidate_set_under_policy(
    original_policy: ModuleCompatibilityPolicySnapshot,
    original_snapshot: ModuleCompatibilitySnapshot,
    original_candidates: Sequence[CandidateInput],
    original: ModulePolicyCandidateSetDecision,
    *,
    fresh_snapshot: ModuleCompatibilitySnapshot,
    fresh_policy: ModuleCompatibilityPolicySnapshot | None = None,
    fresh_candidates: Sequence[CandidateInput] | None = None,
) -> ModulePolicyCandidateSetRevalidation:
    """Revalidate exact policy/runtime/candidate evidence without side effects."""

    trusted_original = _reconstruct_original(
        original_policy,
        original_snapshot,
        original_candidates,
        original,
    )
    selected_policy = (
        original_policy if fresh_policy is None else fresh_policy
    )
    selected_candidates = (
        original_candidates if fresh_candidates is None else fresh_candidates
    )
    fresh = _fresh_decision(
        selected_policy,
        fresh_snapshot,
        selected_candidates,
    )

    drift: set[str] = set()
    stale_modules: set[str] = set()

    original_module_map = {
        module_id: (publisher, reasons)
        for module_id, publisher, reasons in trusted_original.modules
    }
    fresh_module_map = {
        module_id: (publisher, reasons)
        for module_id, publisher, reasons in fresh.modules
    }
    original_module_ids = set(original_module_map)
    fresh_module_ids = set(fresh_module_map)
    all_module_ids = original_module_ids.union(fresh_module_ids)

    if trusted_original.policy_id != fresh.policy_id:
        drift.add("compatibility_policy_changed")
        stale_modules.update(all_module_ids)
    if trusted_original.policy_version != fresh.policy_version:
        drift.add("policy_version_changed")
    if trusted_original.snapshot_id != fresh.snapshot_id:
        drift.add("runtime_snapshot_changed")
        stale_modules.update(all_module_ids)
    if trusted_original.candidate_set_id != fresh.candidate_set_id:
        drift.add("candidate_set_changed")
        stale_modules.update(all_module_ids)
    if original_module_ids != fresh_module_ids:
        drift.add("candidate_membership_changed")
        stale_modules.update(original_module_ids.symmetric_difference(fresh_module_ids))
    if trusted_original.status != fresh.status:
        drift.add("aggregate_status_changed")
    if trusted_original.base_status != fresh.base_status:
        drift.add("base_compatibility_changed")
    if (
        trusted_original.base_blocked_modules
        != fresh.base_blocked_modules
    ):
        drift.add("base_blocked_module_set_changed")
    if (
        trusted_original.policy_blocked_modules
        != fresh.policy_blocked_modules
    ):
        drift.add("policy_blocked_module_set_changed")
    if trusted_original.blocked_modules != fresh.blocked_modules:
        drift.add("blocked_module_set_changed")
    if (
        trusted_original.missing_required_runtime_capabilities
        != fresh.missing_required_runtime_capabilities
    ):
        drift.add("policy_runtime_requirement_outcome_changed")
    if trusted_original.policy_reasons != fresh.policy_reasons:
        drift.add("policy_reason_set_changed")

    for module_id in sorted(original_module_ids.intersection(fresh_module_ids)):
        if original_module_map[module_id] != fresh_module_map[module_id]:
            drift.add("module_policy_outcome_changed")
            stale_modules.add(module_id)

    if not drift and trusted_original.decision_id != fresh.decision_id:
        drift.add("policy_candidate_set_evidence_changed")
        stale_modules.update(all_module_ids)

    drift_reasons = tuple(sorted(drift))
    stale_module_ids = tuple(sorted(stale_modules))
    status = "current" if not drift_reasons else "stale"

    evidence = {
        "schema": "home-center.module-policy-candidate-set-revalidation.v1",
        "status": status,
        "original_decision_id": trusted_original.decision_id,
        "fresh_decision_id": fresh.decision_id,
        "original_policy_id": trusted_original.policy_id,
        "fresh_policy_id": fresh.policy_id,
        "original_policy_version": trusted_original.policy_version,
        "fresh_policy_version": fresh.policy_version,
        "original_candidate_set_id": trusted_original.candidate_set_id,
        "fresh_candidate_set_id": fresh.candidate_set_id,
        "original_snapshot_id": trusted_original.snapshot_id,
        "fresh_snapshot_id": fresh.snapshot_id,
        "original_status": trusted_original.status,
        "fresh_status": fresh.status,
        "original_base_status": trusted_original.base_status,
        "fresh_base_status": fresh.base_status,
        "original_base_blocked_modules": list(
            trusted_original.base_blocked_modules
        ),
        "fresh_base_blocked_modules": list(fresh.base_blocked_modules),
        "original_policy_blocked_modules": list(
            trusted_original.policy_blocked_modules
        ),
        "fresh_policy_blocked_modules": list(
            fresh.policy_blocked_modules
        ),
        "original_blocked_modules": list(trusted_original.blocked_modules),
        "fresh_blocked_modules": list(fresh.blocked_modules),
        "original_missing_required_runtime_capabilities": list(
            trusted_original.missing_required_runtime_capabilities
        ),
        "fresh_missing_required_runtime_capabilities": list(
            fresh.missing_required_runtime_capabilities
        ),
        "original_policy_reasons": list(trusted_original.policy_reasons),
        "fresh_policy_reasons": list(fresh.policy_reasons),
        "original_modules": trusted_original.to_dict()["modules"],
        "fresh_modules": fresh.to_dict()["modules"],
        "stale_modules": list(stale_module_ids),
        "drift_reasons": list(drift_reasons),
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    revalidation_id = "mpcsr-" + _canonical_sha256(evidence)[:24]

    return ModulePolicyCandidateSetRevalidation(
        revalidation_id=revalidation_id,
        status=status,
        original_decision_id=trusted_original.decision_id,
        fresh_decision_id=fresh.decision_id,
        original_policy_id=trusted_original.policy_id,
        fresh_policy_id=fresh.policy_id,
        original_policy_version=trusted_original.policy_version,
        fresh_policy_version=fresh.policy_version,
        original_candidate_set_id=trusted_original.candidate_set_id,
        fresh_candidate_set_id=fresh.candidate_set_id,
        original_snapshot_id=trusted_original.snapshot_id,
        fresh_snapshot_id=fresh.snapshot_id,
        original_status=trusted_original.status,
        fresh_status=fresh.status,
        original_base_status=trusted_original.base_status,
        fresh_base_status=fresh.base_status,
        original_base_blocked_modules=trusted_original.base_blocked_modules,
        fresh_base_blocked_modules=fresh.base_blocked_modules,
        original_policy_blocked_modules=(
            trusted_original.policy_blocked_modules
        ),
        fresh_policy_blocked_modules=fresh.policy_blocked_modules,
        original_blocked_modules=trusted_original.blocked_modules,
        fresh_blocked_modules=fresh.blocked_modules,
        original_missing_required_runtime_capabilities=(
            trusted_original.missing_required_runtime_capabilities
        ),
        fresh_missing_required_runtime_capabilities=(
            fresh.missing_required_runtime_capabilities
        ),
        original_policy_reasons=trusted_original.policy_reasons,
        fresh_policy_reasons=fresh.policy_reasons,
        original_modules=trusted_original.modules,
        fresh_modules=fresh.modules,
        stale_modules=stale_module_ids,
        drift_reasons=drift_reasons,
    )
