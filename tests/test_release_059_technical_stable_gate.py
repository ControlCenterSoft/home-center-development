from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.release_promotion_gate import (
    ArtifactEvidence,
    QualificationEvidence,
    RecoveryEvidence,
    ReleaseBinding,
    SecurityEvidence,
)
from home_center.target_node_qualification import (
    TargetNodeQualificationEvidence,
    evaluate_target_node_qualification,
)
from home_center.technical_stable_profile import (
    TargetNodeEvidence,
    TechnicalStableProfileError,
    evaluate_single_node_technical_stable,
)

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.59.0"
REVISION = "c" * 40
DIGEST = "a" * 64
OTHER = "b" * 64


def _binding(revision: str = REVISION) -> ReleaseBinding:
    return ReleaseBinding(VERSION, revision)


def _qualification(revision: str = REVISION) -> QualificationEvidence:
    return QualificationEvidence(_binding(revision), True, True, True)


def _security(revision: str = REVISION) -> SecurityEvidence:
    return SecurityEvidence(_binding(revision), True, True, True)


def _recovery(revision: str = REVISION) -> RecoveryEvidence:
    return RecoveryEvidence(_binding(revision), True, True, True, False, False)


def _artifacts(revision: str = REVISION, complete: bool = True) -> ArtifactEvidence:
    return ArtifactEvidence(
        binding=_binding(revision),
        candidate_artifact_sha256=DIGEST,
        qualification_manifest=True,
        provenance_v2=True,
        source_artifact_sha256=DIGEST if complete else "",
        deployment_artifact_sha256=DIGEST if complete else "",
        checksum_sidecar=complete,
        sha256sums=complete,
        acceptance_manifest=complete,
        release_manifest=complete,
        spdx_sbom=complete,
    )


def _target(artifact: str = DIGEST, evidence: str = DIGEST, qualified: bool = True) -> TargetNodeEvidence:
    return TargetNodeEvidence(_binding(), artifact, evidence, qualified)


def test_target_node_decision_is_content_addressed_and_never_authorizes_release() -> None:
    decision = evaluate_target_node_qualification(
        TargetNodeQualificationEvidence(
            version=VERSION,
            revision=REVISION,
            candidate_artifact_sha256=DIGEST,
            target_node_id="target-node-a",
            target_environment_sha256=OTHER,
            target_execution_transcript_sha256="d" * 64,
            install_or_upgrade_exercised=True,
            health_ready=True,
            user_state_preserved=True,
            rollback_exercised=True,
        )
    )
    assert decision.qualified is True
    assert decision.blockers == ()
    assert decision.evidence_sha256 != "0" * 64
    assert decision.release_authorized is False
    assert decision.external_publication_authorized is False
    schema = json.loads((ROOT / "contracts/releases/target-node-qualification.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(decision.to_dict())


def test_target_node_missing_health_or_rollback_fails_closed() -> None:
    decision = evaluate_target_node_qualification(
        TargetNodeQualificationEvidence(
            version=VERSION,
            revision=REVISION,
            candidate_artifact_sha256=DIGEST,
            target_node_id="target-node-a",
            target_environment_sha256=OTHER,
            target_execution_transcript_sha256="d" * 64,
            install_or_upgrade_exercised=True,
            health_ready=False,
            user_state_preserved=True,
            rollback_exercised=False,
        )
    )
    assert decision.qualified is False
    assert decision.blockers == ("target_health_ready", "target_rollback")
    assert decision.evidence_sha256 == "0" * 64


def test_single_node_technical_stable_does_not_require_optional_ha_provider_or_commercial_claims() -> None:
    decision = evaluate_single_node_technical_stable(
        version=VERSION,
        revision=REVISION,
        qualification=_qualification(),
        security=_security(),
        recovery=_recovery(),
        target_node=_target(),
        artifacts=_artifacts(),
    )
    assert decision.ready is True
    assert decision.blockers == ()
    assert decision.target_node_qualified is True
    assert decision.ha_supported is False
    assert decision.provider_execution_supported is False
    assert decision.commercial_launch_cleared is False
    assert decision.release_authorized is False
    assert decision.external_publication_authorized is False
    schema = json.loads((ROOT / "contracts/releases/technical-stable-profile-decision.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(decision.to_dict())


def test_target_node_and_stable_artifact_set_remain_hard_gates() -> None:
    decision = evaluate_single_node_technical_stable(
        version=VERSION,
        revision=REVISION,
        qualification=_qualification(),
        security=_security(),
        recovery=_recovery(),
        target_node=_target(evidence="", qualified=False),
        artifacts=_artifacts(complete=False),
    )
    assert decision.ready is False
    assert decision.blockers == (
        "target_node_evidence",
        "target_node_qualification",
        "source_artifact_digest",
        "deployment_artifact_digest",
        "checksum_sidecar",
        "sha256sums",
        "acceptance_manifest",
        "release_manifest",
        "spdx_sbom",
    )


def test_target_node_evidence_cannot_be_reused_for_another_candidate_artifact() -> None:
    decision = evaluate_single_node_technical_stable(
        version=VERSION,
        revision=REVISION,
        qualification=_qualification(),
        security=_security(),
        recovery=_recovery(),
        target_node=_target(artifact=OTHER),
        artifacts=_artifacts(),
    )
    assert decision.blockers == ("target_node_candidate_artifact_binding",)


def test_invalid_release_identity_is_rejected() -> None:
    with pytest.raises(TechnicalStableProfileError, match="release_revision_invalid"):
        evaluate_single_node_technical_stable(
            version=VERSION,
            revision="latest",
            qualification=_qualification(),
            security=_security(),
            recovery=_recovery(),
            target_node=_target(),
            artifacts=_artifacts(),
        )
