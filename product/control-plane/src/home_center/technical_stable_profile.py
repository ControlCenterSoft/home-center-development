"""Technical Public Stable profile for a single-node Home Center release.

The full RC/Stable promotion gate remains authoritative for releases that claim
multi-node HA, concrete provider execution, or commercial-launch clearance.
This narrower profile implements the canonical roadmap rule that those optional
claims may remain disabled/unclaimed instead of blocking an otherwise qualified
single-node technical Stable release.

This evaluator never grants publication authority. It only states whether the
exact release identity has the technical evidence required for the bounded
single-node-core profile.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from .release_promotion_gate import (
    ArtifactEvidence,
    QualificationEvidence,
    RecoveryEvidence,
    ReleaseBinding,
    SecurityEvidence,
)

SCHEMA = "home-center.technical-stable-profile-decision.v1"
SINGLE_NODE_CORE = "single-node-core"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class TechnicalStableProfileError(ValueError):
    """Reject malformed technical Stable profile inputs."""


@dataclass(frozen=True, slots=True)
class TargetNodeEvidence:
    binding: ReleaseBinding
    candidate_artifact_sha256: str
    evidence_sha256: str
    qualified: bool


@dataclass(frozen=True, slots=True)
class TechnicalStableProfileDecision:
    version: str
    revision: str
    release_profile: str
    ready: bool
    blockers: tuple[str, ...]
    target_node_qualified: bool
    ha_supported: bool = False
    provider_execution_supported: bool = False
    commercial_launch_cleared: bool = False
    schema: str = SCHEMA
    release_authorized: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": self.version,
            "revision": self.revision,
            "release_profile": self.release_profile,
            "ready": self.ready,
            "blockers": list(self.blockers),
            "target_node_qualified": self.target_node_qualified,
            "ha_supported": False,
            "provider_execution_supported": False,
            "commercial_launch_cleared": False,
            "release_authorized": False,
            "external_publication_authorized": False,
        }


def _valid_sha256(value: str) -> bool:
    return bool(_SHA256.fullmatch(value))


def _validate_identity(version: str, revision: str) -> None:
    if _SEMVER.fullmatch(version) is None:
        raise TechnicalStableProfileError("release_version_invalid")
    if _REVISION.fullmatch(revision) is None:
        raise TechnicalStableProfileError("release_revision_invalid")


def evaluate_single_node_technical_stable(
    *,
    version: str,
    revision: str,
    qualification: QualificationEvidence,
    security: SecurityEvidence,
    recovery: RecoveryEvidence,
    target_node: TargetNodeEvidence,
    artifacts: ArtifactEvidence,
) -> TechnicalStableProfileDecision:
    """Evaluate the bounded single-node technical Stable profile fail-closed."""

    _validate_identity(version, revision)
    blockers: list[str] = []

    if not qualification.binding.matches(version, revision): blockers.append("qualification_binding")
    if not qualification.ci_passed: blockers.append("ci")
    if not qualification.exact_source_identity: blockers.append("source_identity")
    if not qualification.reproducible_artifact: blockers.append("reproducible_artifact")
    if not security.binding.matches(version, revision): blockers.append("security_binding")
    if not security.codeql_passed: blockers.append("codeql")
    if not security.privacy_boundary_passed: blockers.append("privacy_boundary")
    if not security.infrastructure_neutrality_passed: blockers.append("infrastructure_neutrality")
    if not recovery.binding.matches(version, revision): blockers.append("recovery_binding")
    if not recovery.upgrade_qualified: blockers.append("upgrade")
    if not recovery.rollback_qualified: blockers.append("rollback")
    if not recovery.user_state_preserved: blockers.append("user_state_preservation")

    if not target_node.binding.matches(version, revision): blockers.append("target_node_binding")
    if not _valid_sha256(target_node.candidate_artifact_sha256) or not _valid_sha256(target_node.evidence_sha256): blockers.append("target_node_evidence")
    if (_valid_sha256(target_node.candidate_artifact_sha256) and _valid_sha256(artifacts.candidate_artifact_sha256) and target_node.candidate_artifact_sha256 != artifacts.candidate_artifact_sha256): blockers.append("target_node_candidate_artifact_binding")
    if not target_node.qualified: blockers.append("target_node_qualification")

    if not artifacts.binding.matches(version, revision): blockers.append("artifact_binding")
    if not _valid_sha256(artifacts.candidate_artifact_sha256): blockers.append("candidate_artifact_digest")
    if not artifacts.qualification_manifest: blockers.append("qualification_manifest")
    if not artifacts.provenance_v2: blockers.append("provenance_v2")
    if not _valid_sha256(artifacts.source_artifact_sha256): blockers.append("source_artifact_digest")
    if not _valid_sha256(artifacts.deployment_artifact_sha256): blockers.append("deployment_artifact_digest")
    if not artifacts.checksum_sidecar: blockers.append("checksum_sidecar")
    if not artifacts.sha256sums: blockers.append("sha256sums")
    if not artifacts.acceptance_manifest: blockers.append("acceptance_manifest")
    if not artifacts.release_manifest: blockers.append("release_manifest")
    if not artifacts.spdx_sbom: blockers.append("spdx_sbom")

    return TechnicalStableProfileDecision(
        version=version,
        revision=revision,
        release_profile=SINGLE_NODE_CORE,
        ready=not blockers,
        blockers=tuple(blockers),
        target_node_qualified=target_node.qualified,
    )
