"""Fail-closed qualification evidence for a concrete Home Center policy backend.

This module evaluates evidence produced by a bounded real-backend qualification run.
It never invokes a backend during qualification, never grants mutation authority by
itself, and never converts backend command acceptance into verified enforcement.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re

SCHEMA = "home-center.policy-backend-qualification.v1"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")


class PolicyBackendQualificationError(ValueError):
    """Reject malformed qualification evidence before evaluating semantics."""


@dataclass(frozen=True, slots=True)
class PolicyBackendQualificationEvidence:
    version: str
    revision: str
    candidate_artifact_sha256: str
    backend_id: str
    adapter_id: str
    adapter_version: str
    adapter_artifact_sha256: str
    execution_transcript_sha256: str
    environment_evidence_sha256: str
    real_backend_exercised: bool
    real_target_exercised: bool
    plan_contract_validated: bool
    confirmation_contract_validated: bool
    exact_desired_state_bound: bool
    secret_values_absent_from_evidence: bool
    single_invocation_proven: bool
    ambiguous_outcome_fail_closed: bool
    automatic_retry_disabled: bool
    reconciliation_required_after_mutation: bool
    post_condition_readback_exercised: bool
    verified_state_transition_separate: bool
    restart_recovery_exercised: bool
    recovery_path_exercised: bool
    infrastructure_scope_bounded: bool
    external_publication_forbidden: bool


@dataclass(frozen=True, slots=True)
class PolicyBackendQualificationDecision:
    version: str
    revision: str
    candidate_artifact_sha256: str
    backend_id: str
    adapter_id: str
    adapter_version: str
    adapter_artifact_sha256: str
    evidence_sha256: str
    qualified: bool
    blockers: tuple[str, ...]
    schema: str = SCHEMA
    backend_mutation_authorized: bool = False
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "backend_id": self.backend_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "adapter_artifact_sha256": self.adapter_artifact_sha256,
            "evidence_sha256": self.evidence_sha256,
            "qualified": self.qualified,
            "blockers": list(self.blockers),
            "backend_mutation_authorized": False,
            "release_authorized": False,
            "external_publication_authorized": False,
        }


def _validate_identity(evidence: PolicyBackendQualificationEvidence) -> None:
    if not isinstance(evidence, PolicyBackendQualificationEvidence):
        raise PolicyBackendQualificationError("policy_backend_qualification_evidence_invalid")
    if _SEMVER.fullmatch(evidence.version) is None:
        raise PolicyBackendQualificationError("policy_backend_qualification_version_invalid")
    if _REVISION.fullmatch(evidence.revision) is None:
        raise PolicyBackendQualificationError("policy_backend_qualification_revision_invalid")
    if _IDENTIFIER.fullmatch(evidence.backend_id) is None:
        raise PolicyBackendQualificationError("policy_backend_qualification_backend_id_invalid")
    if _IDENTIFIER.fullmatch(evidence.adapter_id) is None:
        raise PolicyBackendQualificationError("policy_backend_qualification_adapter_id_invalid")
    if evidence.adapter_id != evidence.backend_id:
        raise PolicyBackendQualificationError("policy_backend_qualification_identity_mismatch")
    if _SEMVER.fullmatch(evidence.adapter_version) is None:
        raise PolicyBackendQualificationError("policy_backend_qualification_adapter_version_invalid")
    digest_fields = (
        evidence.candidate_artifact_sha256,
        evidence.adapter_artifact_sha256,
        evidence.execution_transcript_sha256,
        evidence.environment_evidence_sha256,
    )
    if any(_SHA256.fullmatch(value) is None for value in digest_fields):
        raise PolicyBackendQualificationError("policy_backend_qualification_digest_invalid")


def _evidence_digest(evidence: PolicyBackendQualificationEvidence) -> str:
    payload = json.dumps(
        asdict(evidence),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def evaluate_policy_backend_qualification(
    evidence: PolicyBackendQualificationEvidence,
) -> PolicyBackendQualificationDecision:
    """Evaluate exact-bound real-backend evidence without granting authority."""

    _validate_identity(evidence)
    blockers: list[str] = []
    checks = (
        ("real_backend", evidence.real_backend_exercised),
        ("real_target", evidence.real_target_exercised),
        ("plan_contract", evidence.plan_contract_validated),
        ("confirmation_contract", evidence.confirmation_contract_validated),
        ("exact_desired_state", evidence.exact_desired_state_bound),
        ("secret_values_absent", evidence.secret_values_absent_from_evidence),
        ("single_invocation", evidence.single_invocation_proven),
        ("ambiguous_outcome_fail_closed", evidence.ambiguous_outcome_fail_closed),
        ("automatic_retry_disabled", evidence.automatic_retry_disabled),
        ("reconciliation_required", evidence.reconciliation_required_after_mutation),
        ("post_condition_readback", evidence.post_condition_readback_exercised),
        ("verified_transition_separate", evidence.verified_state_transition_separate),
        ("restart_recovery", evidence.restart_recovery_exercised),
        ("recovery_path", evidence.recovery_path_exercised),
        ("infrastructure_scope_bounded", evidence.infrastructure_scope_bounded),
        ("external_publication_forbidden", evidence.external_publication_forbidden),
    )
    for blocker, passed in checks:
        if passed is not True:
            blockers.append(blocker)

    return PolicyBackendQualificationDecision(
        version=evidence.version,
        revision=evidence.revision,
        candidate_artifact_sha256=evidence.candidate_artifact_sha256,
        backend_id=evidence.backend_id,
        adapter_id=evidence.adapter_id,
        adapter_version=evidence.adapter_version,
        adapter_artifact_sha256=evidence.adapter_artifact_sha256,
        evidence_sha256=_evidence_digest(evidence),
        qualified=not blockers,
        blockers=tuple(blockers),
    )


def registration_metadata_from_policy_backend_qualification(
    decision: PolicyBackendQualificationDecision,
    *,
    expected_version: str,
    expected_revision: str,
    expected_candidate_artifact_sha256: str,
    expected_backend_id: str,
    expected_adapter_version: str,
    expected_adapter_artifact_sha256: str,
) -> dict[str, str]:
    """Build registration metadata only from one exact qualified decision."""

    if not isinstance(decision, PolicyBackendQualificationDecision):
        raise PolicyBackendQualificationError("policy_backend_qualification_decision_invalid")
    if (
        decision.schema != SCHEMA
        or decision.qualified is not True
        or decision.blockers
        or decision.backend_mutation_authorized is not False
        or decision.release_authorized is not False
        or decision.external_publication_authorized is not False
        or _SHA256.fullmatch(decision.evidence_sha256) is None
    ):
        raise PolicyBackendQualificationError("policy_backend_qualification_decision_invalid")

    if (
        _SEMVER.fullmatch(expected_version) is None
        or _REVISION.fullmatch(expected_revision) is None
        or _SHA256.fullmatch(expected_candidate_artifact_sha256) is None
        or _IDENTIFIER.fullmatch(expected_backend_id) is None
        or _SEMVER.fullmatch(expected_adapter_version) is None
        or _SHA256.fullmatch(expected_adapter_artifact_sha256) is None
    ):
        raise PolicyBackendQualificationError("policy_backend_qualification_expected_identity_invalid")

    expected = (
        expected_version,
        expected_revision,
        expected_candidate_artifact_sha256,
        expected_backend_id,
        expected_backend_id,
        expected_adapter_version,
        expected_adapter_artifact_sha256,
    )
    actual = (
        decision.version,
        decision.revision,
        decision.candidate_artifact_sha256,
        decision.backend_id,
        decision.adapter_id,
        decision.adapter_version,
        decision.adapter_artifact_sha256,
    )
    if actual != expected:
        raise PolicyBackendQualificationError("policy_backend_qualification_candidate_mismatch")

    return {
        "adapter_id": decision.adapter_id,
        "adapter_version": decision.adapter_version,
        "adapter_artifact_sha256": decision.adapter_artifact_sha256,
        "qualification_evidence_sha256": decision.evidence_sha256,
    }


class QualificationBoundPolicyMutationAdapter:
    """Adapter wrapper whose qualification flag can only follow exact evidence.

    Production integration can register this wrapper with the existing enforcement
    runtime instead of trusting a concrete adapter's self-declared qualification
    flag. The wrapper delegates only ``apply_policy`` and exposes the exact metadata
    bound by the qualification decision.
    """

    policy_mutation_capable = True
    policy_backend_qualified = True
    qualification_binding_schema = SCHEMA

    def __init__(
        self,
        adapter: object,
        decision: PolicyBackendQualificationDecision,
        *,
        expected_version: str,
        expected_revision: str,
        expected_candidate_artifact_sha256: str,
        expected_backend_id: str,
        expected_adapter_version: str,
        expected_adapter_artifact_sha256: str,
    ) -> None:
        metadata = registration_metadata_from_policy_backend_qualification(
            decision,
            expected_version=expected_version,
            expected_revision=expected_revision,
            expected_candidate_artifact_sha256=expected_candidate_artifact_sha256,
            expected_backend_id=expected_backend_id,
            expected_adapter_version=expected_adapter_version,
            expected_adapter_artifact_sha256=expected_adapter_artifact_sha256,
        )
        if (
            getattr(adapter, "policy_mutation_capable", None) is not True
            or getattr(adapter, "adapter_id", None) != metadata["adapter_id"]
            or getattr(adapter, "adapter_version", None) != metadata["adapter_version"]
            or getattr(adapter, "adapter_artifact_sha256", None)
            != metadata["adapter_artifact_sha256"]
            or not callable(getattr(adapter, "apply_policy", None))
        ):
            raise PolicyBackendQualificationError("policy_backend_adapter_binding_invalid")
        self._adapter = adapter
        self.adapter_id = metadata["adapter_id"]
        self.adapter_version = metadata["adapter_version"]
        self.adapter_artifact_sha256 = metadata["adapter_artifact_sha256"]
        self.qualification_evidence_sha256 = metadata["qualification_evidence_sha256"]

    def apply_policy(self, request: dict[str, object]) -> object:
        return self._adapter.apply_policy(request)  # type: ignore[attr-defined]
