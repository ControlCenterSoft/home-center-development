"""Fail-closed qualification evidence for a concrete 0.57 enrollment provider adapter.

This module does not invoke a provider. It evaluates evidence produced by a bounded
real-provider qualification run and only marks the adapter qualified when every
release-critical safety property is proven for the exact Home Center candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

SCHEMA = "home-center.provider-adapter-qualification.v1"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")


class ProviderAdapterQualificationError(ValueError):
    """Reject malformed qualification evidence before evaluating it."""


@dataclass(frozen=True, slots=True)
class ProviderAdapterQualificationEvidence:
    version: str
    revision: str
    adapter_id: str
    adapter_version: str
    candidate_artifact_sha256: str
    adapter_artifact_sha256: str
    execution_transcript_sha256: str
    environment_evidence_sha256: str
    real_provider_exercised: bool
    real_target_exercised: bool
    start_contract_validated: bool
    cancel_contract_validated: bool
    secret_reference_only: bool
    secret_values_absent_from_evidence: bool
    retry_safe_only_when_proven: bool
    ambiguous_outcome_fail_closed: bool
    post_condition_separate: bool
    managed_state_change_forbidden: bool


@dataclass(frozen=True, slots=True)
class ProviderAdapterQualificationDecision:
    version: str
    revision: str
    adapter_id: str
    adapter_version: str
    candidate_artifact_sha256: str
    evidence_sha256: str
    qualified: bool
    blockers: tuple[str, ...]
    schema: str = SCHEMA
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "evidence_sha256": self.evidence_sha256,
            "qualified": self.qualified,
            "blockers": list(self.blockers),
            "release_authorized": False,
            "external_publication_authorized": False,
        }


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _validate_identity(evidence: ProviderAdapterQualificationEvidence) -> None:
    if _SEMVER.fullmatch(evidence.version) is None:
        raise ProviderAdapterQualificationError("provider_qualification_version_invalid")
    if _REVISION.fullmatch(evidence.revision) is None:
        raise ProviderAdapterQualificationError("provider_qualification_revision_invalid")
    if _PROVIDER_ID.fullmatch(evidence.adapter_id) is None:
        raise ProviderAdapterQualificationError("provider_qualification_adapter_id_invalid")
    if _SEMVER.fullmatch(evidence.adapter_version) is None:
        raise ProviderAdapterQualificationError("provider_qualification_adapter_version_invalid")


def evaluate_provider_adapter_qualification(
    evidence: ProviderAdapterQualificationEvidence,
) -> ProviderAdapterQualificationDecision:
    """Evaluate exact-bound provider qualification evidence without granting authority."""

    if not isinstance(evidence, ProviderAdapterQualificationEvidence):
        raise ProviderAdapterQualificationError("provider_qualification_evidence_invalid")
    _validate_identity(evidence)

    blockers: list[str] = []
    digest_fields = (
        ("candidate_artifact_digest", evidence.candidate_artifact_sha256),
        ("adapter_artifact_digest", evidence.adapter_artifact_sha256),
        ("execution_transcript_digest", evidence.execution_transcript_sha256),
        ("environment_evidence_digest", evidence.environment_evidence_sha256),
    )
    for blocker, value in digest_fields:
        if not _valid_sha256(value):
            blockers.append(blocker)

    checks = (
        ("real_provider", evidence.real_provider_exercised),
        ("real_target", evidence.real_target_exercised),
        ("start_contract", evidence.start_contract_validated),
        ("cancel_contract", evidence.cancel_contract_validated),
        ("secret_reference_only", evidence.secret_reference_only),
        ("secret_values_absent", evidence.secret_values_absent_from_evidence),
        ("retry_semantics", evidence.retry_safe_only_when_proven),
        ("ambiguous_outcome_fail_closed", evidence.ambiguous_outcome_fail_closed),
        ("post_condition_separate", evidence.post_condition_separate),
        ("managed_state_change_forbidden", evidence.managed_state_change_forbidden),
    )
    for blocker, passed in checks:
        if passed is not True:
            blockers.append(blocker)

    # Bind the decision to the exact Home Center candidate, immutable provider
    # artifact and exact observed run. The digest carries no provider secrets
    # or endpoint material.
    if blockers:
        evidence_sha256 = "0" * 64
    else:
        import hashlib
        import json

        canonical = {
            "version": evidence.version,
            "revision": evidence.revision,
            "adapter_id": evidence.adapter_id,
            "adapter_version": evidence.adapter_version,
            "candidate_artifact_sha256": evidence.candidate_artifact_sha256,
            "adapter_artifact_sha256": evidence.adapter_artifact_sha256,
            "execution_transcript_sha256": evidence.execution_transcript_sha256,
            "environment_evidence_sha256": evidence.environment_evidence_sha256,
        }
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        evidence_sha256 = hashlib.sha256(payload).hexdigest()

    return ProviderAdapterQualificationDecision(
        version=evidence.version,
        revision=evidence.revision,
        adapter_id=evidence.adapter_id,
        adapter_version=evidence.adapter_version,
        candidate_artifact_sha256=evidence.candidate_artifact_sha256,
        evidence_sha256=evidence_sha256,
        qualified=not blockers,
        blockers=tuple(blockers),
    )
