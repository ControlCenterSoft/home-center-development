"""Fail-closed release-promotion evidence gate for Home Center.

This module evaluates bounded evidence for Release Candidate / Public Stable
readiness. It never performs publication, deployment, provider execution or
any other production mutation, and a positive decision does not itself grant
release or external-publication authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

SCHEMA = "home-center.release-promotion-decision.v1"
CANDIDATE = "candidate"
STABLE = "stable"
APPROVED = "approved"

_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")


class ReleasePromotionError(ValueError):
    """Reject malformed release-promotion inputs before evaluation."""


@dataclass(frozen=True, slots=True)
class ReleaseBinding:
    version: str
    revision: str

    def matches(self, version: str, revision: str) -> bool:
        return self.version == version and self.revision == revision


@dataclass(frozen=True, slots=True)
class QualificationEvidence:
    binding: ReleaseBinding
    ci_passed: bool
    exact_source_identity: bool
    reproducible_artifact: bool


@dataclass(frozen=True, slots=True)
class SecurityEvidence:
    binding: ReleaseBinding
    codeql_passed: bool
    privacy_boundary_passed: bool
    infrastructure_neutrality_passed: bool


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    binding: ReleaseBinding
    upgrade_qualified: bool
    rollback_qualified: bool
    user_state_preserved: bool
    real_target_accepted: bool
    multi_node_ha_restart_qualified: bool


@dataclass(frozen=True, slots=True)
class RealEnvironmentEvidence:
    binding: ReleaseBinding
    candidate_artifact_sha256: str
    evidence_sha256: str
    qualified: bool


@dataclass(frozen=True, slots=True)
class ProviderAdapterEvidence:
    binding: ReleaseBinding
    adapter_id: str
    adapter_version: str
    evidence_sha256: str
    qualified: bool


@dataclass(frozen=True, slots=True)
class ArtifactEvidence:
    binding: ReleaseBinding
    candidate_artifact_sha256: str
    qualification_manifest: bool
    provenance_v2: bool
    source_artifact_sha256: str = ""
    deployment_artifact_sha256: str = ""
    checksum_sidecar: bool = False
    sha256sums: bool = False
    acceptance_manifest: bool = False
    release_manifest: bool = False
    spdx_sbom: bool = False


@dataclass(frozen=True, slots=True)
class CommercialEvidence:
    binding: ReleaseBinding
    disposition: str
    evidence_sha256: str
    dependencies_reviewed: bool
    redistribution_reviewed: bool
    notices_prepared: bool
    source_obligations_resolved: bool
    sbom_reviewed: bool
    legal_terms_dispositioned: bool
    release_claims_reviewed: bool


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    target_channel: str
    version: str
    revision: str
    ready: bool
    blockers: tuple[str, ...]
    schema: str = SCHEMA
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "target_channel": self.target_channel,
            "version": self.version,
            "revision": self.revision,
            "ready": self.ready,
            "blockers": list(self.blockers),
            "release_authorized": self.release_authorized,
            "external_publication_authorized": self.external_publication_authorized,
        }


def _valid_sha256(value: str) -> bool:
    return bool(_SHA256.fullmatch(value))


def _validate_identity(version: str, revision: str) -> None:
    if not _SEMVER.fullmatch(version):
        raise ReleasePromotionError("release_version_invalid")
    if not _REVISION.fullmatch(revision):
        raise ReleasePromotionError("release_revision_invalid")


def _provider_identity_valid(evidence: ProviderAdapterEvidence) -> bool:
    return bool(
        _PROVIDER_ID.fullmatch(evidence.adapter_id)
        and _SEMVER.fullmatch(evidence.adapter_version)
        and _valid_sha256(evidence.evidence_sha256)
    )


def _real_environment_identity_valid(evidence: RealEnvironmentEvidence) -> bool:
    return bool(
        _valid_sha256(evidence.candidate_artifact_sha256)
        and _valid_sha256(evidence.evidence_sha256)
    )


def evaluate_release_promotion(
    *,
    target_channel: str,
    version: str,
    revision: str,
    qualification: QualificationEvidence,
    security: SecurityEvidence,
    recovery: RecoveryEvidence,
    real_environment: RealEnvironmentEvidence,
    provider: ProviderAdapterEvidence,
    artifacts: ArtifactEvidence,
    commercial: CommercialEvidence,
) -> PromotionDecision:
    """Evaluate exact-bound RC/Stable evidence without creating authority."""

    if target_channel not in {CANDIDATE, STABLE}:
        raise ReleasePromotionError("target_channel_invalid")
    _validate_identity(version, revision)

    blockers: list[str] = []

    if not qualification.binding.matches(version, revision):
        blockers.append("qualification_binding")
    if not qualification.ci_passed:
        blockers.append("ci")
    if not qualification.exact_source_identity:
        blockers.append("source_identity")
    if not qualification.reproducible_artifact:
        blockers.append("reproducible_artifact")

    if not security.binding.matches(version, revision):
        blockers.append("security_binding")
    if not security.codeql_passed:
        blockers.append("codeql")
    if not security.privacy_boundary_passed:
        blockers.append("privacy_boundary")
    if not security.infrastructure_neutrality_passed:
        blockers.append("infrastructure_neutrality")

    if not recovery.binding.matches(version, revision):
        blockers.append("recovery_binding")
    if not recovery.upgrade_qualified:
        blockers.append("upgrade")
    if not recovery.rollback_qualified:
        blockers.append("rollback")
    if not recovery.user_state_preserved:
        blockers.append("user_state_preservation")
    if not recovery.real_target_accepted:
        blockers.append("real_target_acceptance")
    if not recovery.multi_node_ha_restart_qualified:
        blockers.append("multi_node_ha_restart")

    if not real_environment.binding.matches(version, revision):
        blockers.append("real_environment_binding")
    if not _real_environment_identity_valid(real_environment):
        blockers.append("real_environment_evidence")
    if (
        _valid_sha256(real_environment.candidate_artifact_sha256)
        and _valid_sha256(artifacts.candidate_artifact_sha256)
        and real_environment.candidate_artifact_sha256 != artifacts.candidate_artifact_sha256
    ):
        blockers.append("real_environment_artifact_binding")
    if not real_environment.qualified:
        blockers.append("real_environment_qualification")

    if not provider.binding.matches(version, revision):
        blockers.append("provider_binding")
    if not _provider_identity_valid(provider):
        blockers.append("provider_evidence")
    if not provider.qualified:
        blockers.append("provider_adapter_qualification")

    if not artifacts.binding.matches(version, revision):
        blockers.append("artifact_binding")
    if not _valid_sha256(artifacts.candidate_artifact_sha256):
        blockers.append("candidate_artifact_digest")
    if not artifacts.qualification_manifest:
        blockers.append("qualification_manifest")
    if not artifacts.provenance_v2:
        blockers.append("provenance_v2")

    if target_channel == STABLE:
        if not _valid_sha256(artifacts.source_artifact_sha256):
            blockers.append("source_artifact_digest")
        if not _valid_sha256(artifacts.deployment_artifact_sha256):
            blockers.append("deployment_artifact_digest")
        if not artifacts.checksum_sidecar:
            blockers.append("checksum_sidecar")
        if not artifacts.sha256sums:
            blockers.append("sha256sums")
        if not artifacts.acceptance_manifest:
            blockers.append("acceptance_manifest")
        if not artifacts.release_manifest:
            blockers.append("release_manifest")
        if not artifacts.spdx_sbom:
            blockers.append("spdx_sbom")

    if not commercial.binding.matches(version, revision):
        blockers.append("commercial_binding")
    if commercial.disposition != APPROVED:
        blockers.append("commercial_disposition")
    if not _valid_sha256(commercial.evidence_sha256):
        blockers.append("commercial_evidence")
    if not commercial.dependencies_reviewed:
        blockers.append("dependencies_reviewed")
    if not commercial.redistribution_reviewed:
        blockers.append("redistribution_reviewed")
    if not commercial.notices_prepared:
        blockers.append("notices_prepared")
    if not commercial.source_obligations_resolved:
        blockers.append("source_obligations_resolved")
    if not commercial.sbom_reviewed:
        blockers.append("sbom_reviewed")
    if not commercial.legal_terms_dispositioned:
        blockers.append("legal_terms_dispositioned")
    if not commercial.release_claims_reviewed:
        blockers.append("release_claims_reviewed")

    return PromotionDecision(
        target_channel=target_channel,
        version=version,
        revision=revision,
        ready=not blockers,
        blockers=tuple(blockers),
    )
