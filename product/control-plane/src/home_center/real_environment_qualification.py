"""Fail-closed qualification of Home Center 0.57 real-environment release evidence.

This module never deploys or mutates a target. It evaluates evidence produced by
bounded real target-node and multi-node HA/restart acceptance runs and emits a
content-addressed qualification decision for the exact candidate revision.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

SCHEMA = "home-center.real-environment-qualification.v1"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NODE_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")


class RealEnvironmentQualificationError(ValueError):
    """Reject malformed real-environment evidence before evaluating it."""


@dataclass(frozen=True, slots=True)
class RealEnvironmentQualificationEvidence:
    version: str
    revision: str
    candidate_artifact_sha256: str
    target_node_id: str
    target_environment_sha256: str
    target_execution_transcript_sha256: str
    target_install_or_upgrade_exercised: bool
    target_health_ready: bool
    target_user_state_preserved: bool
    target_rollback_exercised: bool
    ha_node_ids: tuple[str, ...]
    ha_environment_sha256: str
    ha_execution_transcript_sha256: str
    real_multi_node_contour_exercised: bool
    replication_healthy: bool
    peer_continuity_verified: bool
    restart_exercised: bool
    post_restart_health_ready: bool
    ha_rollback_exercised: bool


@dataclass(frozen=True, slots=True)
class RealEnvironmentQualificationDecision:
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


def _validate_identity(evidence: RealEnvironmentQualificationEvidence) -> None:
    if not isinstance(evidence, RealEnvironmentQualificationEvidence):
        raise RealEnvironmentQualificationError("real_environment_evidence_invalid")
    if _SEMVER.fullmatch(evidence.version) is None:
        raise RealEnvironmentQualificationError("real_environment_version_invalid")
    if _REVISION.fullmatch(evidence.revision) is None:
        raise RealEnvironmentQualificationError("real_environment_revision_invalid")
    if _NODE_ID.fullmatch(evidence.target_node_id) is None:
        raise RealEnvironmentQualificationError("real_environment_target_node_id_invalid")
    if len(evidence.ha_node_ids) < 2:
        raise RealEnvironmentQualificationError("real_environment_ha_node_count_invalid")
    if len(set(evidence.ha_node_ids)) != len(evidence.ha_node_ids):
        raise RealEnvironmentQualificationError("real_environment_ha_node_ids_not_unique")
    if any(_NODE_ID.fullmatch(node_id) is None for node_id in evidence.ha_node_ids):
        raise RealEnvironmentQualificationError("real_environment_ha_node_id_invalid")


def evaluate_real_environment_qualification(
    evidence: RealEnvironmentQualificationEvidence,
) -> RealEnvironmentQualificationDecision:
    """Evaluate exact-bound real target/HA evidence without granting authority."""

    _validate_identity(evidence)

    blockers: list[str] = []
    digests = (
        ("candidate_artifact_digest", evidence.candidate_artifact_sha256),
        ("target_environment_digest", evidence.target_environment_sha256),
        ("target_execution_transcript_digest", evidence.target_execution_transcript_sha256),
        ("ha_environment_digest", evidence.ha_environment_sha256),
        ("ha_execution_transcript_digest", evidence.ha_execution_transcript_sha256),
    )
    for blocker, value in digests:
        if not _valid_sha256(value):
            blockers.append(blocker)

    checks = (
        ("target_install_or_upgrade", evidence.target_install_or_upgrade_exercised),
        ("target_health_ready", evidence.target_health_ready),
        ("target_user_state_preservation", evidence.target_user_state_preserved),
        ("target_rollback", evidence.target_rollback_exercised),
        ("real_multi_node_contour", evidence.real_multi_node_contour_exercised),
        ("replication_health", evidence.replication_healthy),
        ("peer_continuity", evidence.peer_continuity_verified),
        ("restart", evidence.restart_exercised),
        ("post_restart_health", evidence.post_restart_health_ready),
        ("ha_rollback", evidence.ha_rollback_exercised),
    )
    for blocker, passed in checks:
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
            "ha_node_ids": list(evidence.ha_node_ids),
            "ha_environment_sha256": evidence.ha_environment_sha256,
            "ha_execution_transcript_sha256": evidence.ha_execution_transcript_sha256,
        }
        payload = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        evidence_sha256 = hashlib.sha256(payload).hexdigest()

    return RealEnvironmentQualificationDecision(
        version=evidence.version,
        revision=evidence.revision,
        candidate_artifact_sha256=evidence.candidate_artifact_sha256,
        evidence_sha256=evidence_sha256,
        qualified=not blockers,
        blockers=tuple(blockers),
    )
