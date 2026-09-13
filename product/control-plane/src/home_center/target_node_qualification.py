"""Fail-closed qualification of a Home Center release on one real target node.

This evidence boundary is intentionally narrower than the existing multi-node
real-environment qualification. It exists for a single-node Stable profile:
Home Center single-node operation may be qualified independently while HA stays
explicitly unsupported/unclaimed. A positive decision never grants release,
deployment, provider-execution or external-publication authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

SCHEMA = "home-center.target-node-qualification.v1"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NODE_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")


class TargetNodeQualificationError(ValueError):
    """Reject malformed target-node evidence before evaluating it."""


@dataclass(frozen=True, slots=True)
class TargetNodeQualificationEvidence:
    version: str
    revision: str
    candidate_artifact_sha256: str
    target_node_id: str
    target_environment_sha256: str
    target_execution_transcript_sha256: str
    install_or_upgrade_exercised: bool
    health_ready: bool
    user_state_preserved: bool
    rollback_exercised: bool


@dataclass(frozen=True, slots=True)
class TargetNodeQualificationDecision:
    version: str
    revision: str
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
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "evidence_sha256": self.evidence_sha256,
            "qualified": self.qualified,
            "blockers": list(self.blockers),
            "release_authorized": False,
            "external_publication_authorized": False,
        }


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _validate_identity(evidence: TargetNodeQualificationEvidence) -> None:
    if not isinstance(evidence, TargetNodeQualificationEvidence):
        raise TargetNodeQualificationError("target_node_evidence_invalid")
    if _SEMVER.fullmatch(evidence.version) is None:
        raise TargetNodeQualificationError("target_node_version_invalid")
    if _REVISION.fullmatch(evidence.revision) is None:
        raise TargetNodeQualificationError("target_node_revision_invalid")
    if _NODE_ID.fullmatch(evidence.target_node_id) is None:
        raise TargetNodeQualificationError("target_node_id_invalid")


def evaluate_target_node_qualification(
    evidence: TargetNodeQualificationEvidence,
) -> TargetNodeQualificationDecision:
    """Evaluate exact-bound target-node evidence without granting authority."""

    _validate_identity(evidence)
    blockers: list[str] = []
    for blocker, value in (
        ("candidate_artifact_digest", evidence.candidate_artifact_sha256),
        ("target_environment_digest", evidence.target_environment_sha256),
        ("target_execution_transcript_digest", evidence.target_execution_transcript_sha256),
    ):
        if not _valid_sha256(value):
            blockers.append(blocker)

    for blocker, passed in (
        ("target_install_or_upgrade", evidence.install_or_upgrade_exercised),
        ("target_health_ready", evidence.health_ready),
        ("target_user_state_preservation", evidence.user_state_preserved),
        ("target_rollback", evidence.rollback_exercised),
    ):
        if passed is not True:
            blockers.append(blocker)

    if blockers:
        evidence_sha256 = "0" * 64
    else:
        canonical = {
            "version": evidence.version,
            "revision": evidence.revision,
            "candidate_artifact_sha256": evidence.candidate_artifact_sha256,
            "target_node_id": evidence.target_node_id,
            "target_environment_sha256": evidence.target_environment_sha256,
            "target_execution_transcript_sha256": evidence.target_execution_transcript_sha256,
            "install_or_upgrade_exercised": True,
            "health_ready": True,
            "user_state_preserved": True,
            "rollback_exercised": True,
        }
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        evidence_sha256 = hashlib.sha256(payload).hexdigest()

    return TargetNodeQualificationDecision(
        version=evidence.version,
        revision=evidence.revision,
        candidate_artifact_sha256=evidence.candidate_artifact_sha256,
        evidence_sha256=evidence_sha256,
        qualified=not blockers,
        blockers=tuple(blockers),
    )
