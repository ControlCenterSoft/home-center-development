"""Bounded Public Stable profile evaluation for Home Center 0.57.

The full release-promotion evaluator remains intentionally strict for profiles
that claim real provider execution, multi-node HA or commercial launch.  This
module defines the narrower technical Stable profile permitted by HC-RM-1.2:
a qualified single-node core may be released while unqualified optional
capabilities remain fail-closed and explicitly unsupported.

A positive decision never grants provider execution, HA, commercial or
external-publication authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from .release_promotion_gate import (
    APPROVED,
    ArtifactEvidence,
    CommercialEvidence,
    ProviderAdapterEvidence,
    QualificationEvidence,
    RealEnvironmentEvidence,
    RecoveryEvidence,
    ReleaseBinding,
    ReleasePromotionError,
    SecurityEvidence,
    _provider_identity_valid,
    _real_environment_identity_valid,
    _valid_sha256,
    _validate_identity,
)

SCHEMA = "home-center.bounded-stable-profile-decision.v1"
CORE_SINGLE_NODE = "core-single-node"


@dataclass(frozen=True, slots=True)
class StableProfileClaims:
    """Optional claims that must be backed by their own exact-bound evidence."""

    provider_execution: bool = False
    multi_node_ha: bool = False
    commercial_launch: bool = False


@dataclass(frozen=True, slots=True)
class BoundedStableDecision:
    version: str
    revision: str
    profile: str
    ready: bool
    blockers: tuple[str, ...]
    provider_execution_supported: bool
    multi_node_ha_supported: bool
    commercial_launch_cleared: bool
    schema: str = SCHEMA
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "profile": self.profile,
            "ready": self.ready,
            "blockers": list(self.blockers),
            "provider_execution_supported": self.provider_execution_supported,
            "multi_node_ha_supported": self.multi_node_ha_supported,
            "commercial_launch_cleared": self.commercial_launch_cleared,
            "release_authorized": self.release_authorized,
            "external_publication_authorized": self.external_publication_authorized,
        }


def _commercial_complete(
    *,
    version: str,
    revision: str,
    evidence: CommercialEvidence | None,
    blockers: list[str],
) -> bool:
    if evidence is None:
        blockers.append("commercial_evidence_missing")
        return False
    complete = True
    if not evidence.binding.matches(version, revision):
        blockers.append("commercial_binding")
        complete = False
    if evidence.disposition != APPROVED:
        blockers.append("commercial_disposition")
        complete = False
    if not _valid_sha256(evidence.evidence_sha256):
        blockers.append("commercial_evidence")
        complete = False
    fields = (
        ("dependencies_reviewed", evidence.dependencies_reviewed),
        ("redistribution_reviewed", evidence.redistribution_reviewed),
        ("notices_prepared", evidence.notices_prepared),
        ("source_obligations_resolved", evidence.source_obligations_resolved),
        ("sbom_reviewed", evidence.sbom_reviewed),
        ("legal_terms_dispositioned", evidence.legal_terms_dispositioned),
        ("release_claims_reviewed", evidence.release_claims_reviewed),
    )
    for name, passed in fields:
        if not passed:
            blockers.append(name)
            complete = False
    return complete


def evaluate_bounded_stable_profile(
    *,
    version: str,
    revision: str,
    qualification: QualificationEvidence,
    security: SecurityEvidence,
    recovery: RecoveryEvidence,
    artifacts: ArtifactEvidence,
    claims: StableProfileClaims = StableProfileClaims(),
    real_environment: RealEnvironmentEvidence | None = None,
    provider: ProviderAdapterEvidence | None = None,
    commercial: CommercialEvidence | None = None,
) -> BoundedStableDecision:
    """Evaluate a technical Public Stable profile without inventing optional claims.

    Core Stable always requires exact-bound CI/source/artifact/security evidence,
    supported upgrade and rollback, user-state preservation, and the complete
    public Stable artifact set.  Real provider execution, multi-node HA and
    commercial launch are evaluated only when the release explicitly claims
    those capabilities.  When not claimed they stay unsupported/fail-closed.
    """

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

    if not artifacts.binding.matches(version, revision):
        blockers.append("artifact_binding")
    if not _valid_sha256(artifacts.candidate_artifact_sha256):
        blockers.append("candidate_artifact_digest")
    if not artifacts.qualification_manifest:
        blockers.append("qualification_manifest")
    if not artifacts.provenance_v2:
        blockers.append("provenance_v2")
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

    provider_supported = False
    if claims.provider_execution:
        if provider is None:
            blockers.append("provider_evidence_missing")
        else:
            provider_supported = True
            if not provider.binding.matches(version, revision):
                blockers.append("provider_binding")
                provider_supported = False
            if not _provider_identity_valid(provider):
                blockers.append("provider_evidence")
                provider_supported = False
            if (
                _valid_sha256(provider.candidate_artifact_sha256)
                and _valid_sha256(artifacts.candidate_artifact_sha256)
                and provider.candidate_artifact_sha256 != artifacts.candidate_artifact_sha256
            ):
                blockers.append("provider_candidate_artifact_binding")
                provider_supported = False
            if not provider.qualified:
                blockers.append("provider_adapter_qualification")
                provider_supported = False

    ha_supported = False
    if claims.multi_node_ha:
        ha_supported = True
        if not recovery.real_target_accepted:
            blockers.append("real_target_acceptance")
            ha_supported = False
        if not recovery.multi_node_ha_restart_qualified:
            blockers.append("multi_node_ha_restart")
            ha_supported = False
        if real_environment is None:
            blockers.append("real_environment_evidence_missing")
            ha_supported = False
        else:
            if not real_environment.binding.matches(version, revision):
                blockers.append("real_environment_binding")
                ha_supported = False
            if not _real_environment_identity_valid(real_environment):
                blockers.append("real_environment_evidence")
                ha_supported = False
            if (
                _valid_sha256(real_environment.candidate_artifact_sha256)
                and _valid_sha256(artifacts.candidate_artifact_sha256)
                and real_environment.candidate_artifact_sha256 != artifacts.candidate_artifact_sha256
            ):
                blockers.append("real_environment_artifact_binding")
                ha_supported = False
            if not real_environment.qualified:
                blockers.append("real_environment_qualification")
                ha_supported = False

    commercial_cleared = False
    if claims.commercial_launch:
        commercial_cleared = _commercial_complete(
            version=version,
            revision=revision,
            evidence=commercial,
            blockers=blockers,
        )

    return BoundedStableDecision(
        version=version,
        revision=revision,
        profile=CORE_SINGLE_NODE,
        ready=not blockers,
        blockers=tuple(blockers),
        provider_execution_supported=provider_supported,
        multi_node_ha_supported=ha_supported,
        commercial_launch_cleared=commercial_cleared,
    )
