"""Versioned compatibility-policy evidence for Home Center module admission."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .module_artifact import VerifiedModuleArtifact
from .module_candidate_set import (
    ModuleCandidateSetError,
    evaluate_module_candidate_set,
)
from .module_compatibility_snapshot import ModuleCompatibilitySnapshot
from .module_manifest import MODULE_ID, SEMVER, SYMBOLIC_ID


MAX_POLICY_MODULE_IDS = 256
MAX_POLICY_PUBLISHERS = 256
MAX_POLICY_CAPABILITIES = 256
MAX_POLICY_CANDIDATES = 128


class ModuleCompatibilityPolicyError(ValueError):
    """Stable rejection code for malformed or mismatched compatibility policy."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleCompatibilityPolicySnapshot:
    """Canonical identity for one module-compatibility policy."""

    policy_id: str
    policy_version: str
    blocked_module_ids: tuple[str, ...]
    restrict_publishers: bool
    allowed_publishers: tuple[str, ...]
    required_runtime_capabilities: tuple[str, ...]
    max_candidate_modules: int
    schema: str = "home-center.module-compatibility-policy-snapshot.v1"
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "blocked_module_ids": list(self.blocked_module_ids),
            "restrict_publishers": self.restrict_publishers,
            "allowed_publishers": list(self.allowed_publishers),
            "required_runtime_capabilities": list(
                self.required_runtime_capabilities
            ),
            "max_candidate_modules": self.max_candidate_modules,
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": (
                self.external_publication_authorized
            ),
        }


@dataclass(frozen=True, slots=True)
class ModulePolicyCandidateSetDecision:
    """Policy-bound candidate-set evidence with no execution authority."""

    decision_id: str
    status: str
    policy_id: str
    policy_version: str
    candidate_set_id: str
    snapshot_id: str
    base_status: str
    candidate_count: int
    missing_required_runtime_capabilities: tuple[str, ...]
    base_blocked_modules: tuple[str, ...]
    policy_blocked_modules: tuple[str, ...]
    blocked_modules: tuple[str, ...]
    policy_reasons: tuple[str, ...]
    modules: tuple[tuple[str, str, tuple[str, ...]], ...]
    schema: str = "home-center.module-policy-candidate-set-decision.v1"
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
            "decision_id": self.decision_id,
            "status": self.status,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "candidate_set_id": self.candidate_set_id,
            "snapshot_id": self.snapshot_id,
            "base_status": self.base_status,
            "candidate_count": self.candidate_count,
            "missing_required_runtime_capabilities": list(
                self.missing_required_runtime_capabilities
            ),
            "base_blocked_modules": list(self.base_blocked_modules),
            "policy_blocked_modules": list(self.policy_blocked_modules),
            "blocked_modules": list(self.blocked_modules),
            "policy_reasons": list(self.policy_reasons),
            "modules": [
                {
                    "module_id": module_id,
                    "publisher": publisher,
                    "policy_reasons": list(reasons),
                }
                for module_id, publisher, reasons in self.modules
            ],
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
        raise ModuleCompatibilityPolicyError(
            "compatibility_policy_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _semver(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or SEMVER.fullmatch(value) is None
    ):
        raise ModuleCompatibilityPolicyError(code)
    return value


def _module_id(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or MODULE_ID.fullmatch(value) is None
    ):
        raise ModuleCompatibilityPolicyError(code)
    return value


def _symbolic(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or SYMBOLIC_ID.fullmatch(value) is None
    ):
        raise ModuleCompatibilityPolicyError(code)
    return value


def _normalize_unique(
    values: Iterable[str],
    *,
    maximum: int,
    validator: str,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ModuleCompatibilityPolicyError(f"{validator}_set_rejected")
    normalized: list[str] = []
    for raw_value in values:
        if validator == "module":
            value = _module_id(raw_value, "policy_module_id_rejected")
        elif validator == "publisher":
            value = _module_id(raw_value, "policy_publisher_rejected")
        elif validator == "capability":
            value = _symbolic(raw_value, "policy_capability_rejected")
        else:
            raise ModuleCompatibilityPolicyError(
                "compatibility_policy_validator_rejected"
            )
        normalized.append(value)
        if len(normalized) > maximum:
            raise ModuleCompatibilityPolicyError(
                f"{validator}_set_rejected"
            )
    if len(normalized) != len(set(normalized)):
        raise ModuleCompatibilityPolicyError(f"{validator}_duplicate")
    return tuple(sorted(normalized))


def _policy_evidence(
    *,
    policy_version: str,
    blocked_module_ids: tuple[str, ...],
    restrict_publishers: bool,
    allowed_publishers: tuple[str, ...],
    required_runtime_capabilities: tuple[str, ...],
    max_candidate_modules: int,
) -> dict[str, object]:
    return {
        "schema": "home-center.module-compatibility-policy-snapshot.v1",
        "policy_version": policy_version,
        "blocked_module_ids": list(blocked_module_ids),
        "restrict_publishers": restrict_publishers,
        "allowed_publishers": list(allowed_publishers),
        "required_runtime_capabilities": list(
            required_runtime_capabilities
        ),
        "max_candidate_modules": max_candidate_modules,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }


def build_module_compatibility_policy_snapshot(
    *,
    policy_version: str,
    blocked_module_ids: Iterable[str] = (),
    restrict_publishers: bool = False,
    allowed_publishers: Iterable[str] = (),
    required_runtime_capabilities: Iterable[str] = (),
    max_candidate_modules: int = MAX_POLICY_CANDIDATES,
) -> ModuleCompatibilityPolicySnapshot:
    """Build deterministic compatibility policy evidence without side effects."""

    version = _semver(policy_version, "policy_version_rejected")
    blocked = _normalize_unique(
        blocked_module_ids,
        maximum=MAX_POLICY_MODULE_IDS,
        validator="module",
    )
    if not isinstance(restrict_publishers, bool):
        raise ModuleCompatibilityPolicyError(
            "restrict_publishers_rejected"
        )
    publishers = _normalize_unique(
        allowed_publishers,
        maximum=MAX_POLICY_PUBLISHERS,
        validator="publisher",
    )
    if restrict_publishers and not publishers:
        raise ModuleCompatibilityPolicyError(
            "allowed_publishers_required"
        )
    if not restrict_publishers and publishers:
        raise ModuleCompatibilityPolicyError(
            "allowed_publishers_not_permitted"
        )
    capabilities = _normalize_unique(
        required_runtime_capabilities,
        maximum=MAX_POLICY_CAPABILITIES,
        validator="capability",
    )
    if (
        isinstance(max_candidate_modules, bool)
        or not isinstance(max_candidate_modules, int)
        or not 1 <= max_candidate_modules <= MAX_POLICY_CANDIDATES
    ):
        raise ModuleCompatibilityPolicyError(
            "max_candidate_modules_rejected"
        )

    evidence = _policy_evidence(
        policy_version=version,
        blocked_module_ids=blocked,
        restrict_publishers=restrict_publishers,
        allowed_publishers=publishers,
        required_runtime_capabilities=capabilities,
        max_candidate_modules=max_candidate_modules,
    )
    policy_id = "mcp-" + _canonical_sha256(evidence)[:24]
    return ModuleCompatibilityPolicySnapshot(
        policy_id=policy_id,
        policy_version=version,
        blocked_module_ids=blocked,
        restrict_publishers=restrict_publishers,
        allowed_publishers=publishers,
        required_runtime_capabilities=capabilities,
        max_candidate_modules=max_candidate_modules,
    )


def _trusted_policy(
    policy: ModuleCompatibilityPolicySnapshot,
) -> ModuleCompatibilityPolicySnapshot:
    if not isinstance(policy, ModuleCompatibilityPolicySnapshot):
        raise ModuleCompatibilityPolicyError(
            "compatibility_policy_rejected"
        )
    try:
        rebuilt = build_module_compatibility_policy_snapshot(
            policy_version=policy.policy_version,
            blocked_module_ids=policy.blocked_module_ids,
            restrict_publishers=policy.restrict_publishers,
            allowed_publishers=policy.allowed_publishers,
            required_runtime_capabilities=(
                policy.required_runtime_capabilities
            ),
            max_candidate_modules=policy.max_candidate_modules,
        )
    except (TypeError, ValueError) as exc:
        raise ModuleCompatibilityPolicyError(
            "compatibility_policy_rejected"
        ) from exc
    if policy.to_dict() != rebuilt.to_dict():
        raise ModuleCompatibilityPolicyError(
            "compatibility_policy_rejected"
        )
    return rebuilt


def _candidate_publishers(
    candidates: Sequence[tuple[dict[str, Any], VerifiedModuleArtifact]],
) -> Mapping[str, str]:
    publishers: dict[str, str] = {}
    for raw_candidate in candidates:
        if not isinstance(raw_candidate, tuple) or len(raw_candidate) != 2:
            raise ModuleCompatibilityPolicyError(
                "candidate_policy_evidence_rejected"
            )
        manifest, _ = raw_candidate
        if not isinstance(manifest, dict):
            raise ModuleCompatibilityPolicyError(
                "candidate_policy_evidence_rejected"
            )
        module = manifest.get("module")
        if not isinstance(module, dict):
            raise ModuleCompatibilityPolicyError(
                "candidate_policy_evidence_rejected"
            )
        module_id = _module_id(
            module.get("id"),
            "candidate_module_id_rejected",
        )
        publisher = _module_id(
            module.get("publisher"),
            "candidate_publisher_rejected",
        )
        if module_id in publishers:
            raise ModuleCompatibilityPolicyError(
                "candidate_module_duplicate"
            )
        publishers[module_id] = publisher
    return publishers


def evaluate_module_candidate_set_under_policy(
    policy: ModuleCompatibilityPolicySnapshot,
    snapshot: ModuleCompatibilitySnapshot,
    candidates: Sequence[tuple[dict[str, Any], VerifiedModuleArtifact]],
) -> ModulePolicyCandidateSetDecision:
    """Bind one exact candidate-set decision to one exact compatibility policy."""

    trusted_policy = _trusted_policy(policy)
    try:
        base = evaluate_module_candidate_set(snapshot, candidates)
    except (ModuleCandidateSetError, TypeError, ValueError) as exc:
        raise ModuleCompatibilityPolicyError(
            "candidate_set_rejected"
        ) from exc

    publishers = _candidate_publishers(candidates)
    candidate_ids = tuple(item[0] for item in base.candidates)
    if set(publishers) != set(candidate_ids):
        raise ModuleCompatibilityPolicyError(
            "candidate_policy_evidence_rejected"
        )

    missing_required = tuple(
        sorted(
            set(trusted_policy.required_runtime_capabilities)
            - set(base.available_capabilities)
        )
    )

    global_reasons: set[str] = set()
    if len(candidate_ids) > trusted_policy.max_candidate_modules:
        global_reasons.add("candidate_limit_exceeded")
    if missing_required:
        global_reasons.add("runtime_capability_required")

    blocked_by_policy: set[str] = set()
    module_results: list[tuple[str, str, tuple[str, ...]]] = []
    for module_id in candidate_ids:
        reasons = set(global_reasons)
        publisher = publishers[module_id]
        if module_id in trusted_policy.blocked_module_ids:
            reasons.add("module_blocked_by_policy")
        if (
            trusted_policy.restrict_publishers
            and publisher not in trusted_policy.allowed_publishers
        ):
            reasons.add("publisher_not_allowed")
        normalized_reasons = tuple(sorted(reasons))
        if normalized_reasons:
            blocked_by_policy.add(module_id)
        module_results.append(
            (module_id, publisher, normalized_reasons)
        )

    policy_blocked_modules = tuple(sorted(blocked_by_policy))
    blocked_modules = tuple(
        sorted(set(base.blocked_modules).union(policy_blocked_modules))
    )
    policy_reasons = tuple(
        sorted(
            {
                reason
                for _, _, reasons in module_results
                for reason in reasons
            }
        )
    )
    status = "compatible" if not blocked_modules else "blocked"
    normalized_modules = tuple(sorted(module_results))

    evidence = {
        "schema": "home-center.module-policy-candidate-set-decision.v1",
        "status": status,
        "policy_id": trusted_policy.policy_id,
        "policy_version": trusted_policy.policy_version,
        "candidate_set_id": base.candidate_set_id,
        "snapshot_id": base.snapshot_id,
        "base_status": base.status,
        "candidate_count": len(candidate_ids),
        "missing_required_runtime_capabilities": list(
            missing_required
        ),
        "base_blocked_modules": list(base.blocked_modules),
        "policy_blocked_modules": list(policy_blocked_modules),
        "blocked_modules": list(blocked_modules),
        "policy_reasons": list(policy_reasons),
        "modules": [
            {
                "module_id": module_id,
                "publisher": publisher,
                "policy_reasons": list(reasons),
            }
            for module_id, publisher, reasons in normalized_modules
        ],
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    decision_id = "mpcs-" + _canonical_sha256(evidence)[:24]
    return ModulePolicyCandidateSetDecision(
        decision_id=decision_id,
        status=status,
        policy_id=trusted_policy.policy_id,
        policy_version=trusted_policy.policy_version,
        candidate_set_id=base.candidate_set_id,
        snapshot_id=base.snapshot_id,
        base_status=base.status,
        candidate_count=len(candidate_ids),
        missing_required_runtime_capabilities=missing_required,
        base_blocked_modules=base.blocked_modules,
        policy_blocked_modules=policy_blocked_modules,
        blocked_modules=blocked_modules,
        policy_reasons=policy_reasons,
        modules=normalized_modules,
    )
