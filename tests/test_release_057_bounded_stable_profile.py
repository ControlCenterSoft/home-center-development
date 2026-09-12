from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from home_center.bounded_stable_profile import (
    StableProfileClaims,
    evaluate_bounded_stable_profile,
)
from home_center.release_promotion_gate import (
    ArtifactEvidence,
    QualificationEvidence,
    RecoveryEvidence,
    ReleaseBinding,
    SecurityEvidence,
)

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.57.0"
REVISION = "c" * 40
DIGEST = "a" * 64


def _binding() -> ReleaseBinding:
    return ReleaseBinding(version=VERSION, revision=REVISION)


def _qualification() -> QualificationEvidence:
    return QualificationEvidence(
        binding=_binding(),
        ci_passed=True,
        exact_source_identity=True,
        reproducible_artifact=True,
    )


def _security() -> SecurityEvidence:
    return SecurityEvidence(
        binding=_binding(),
        codeql_passed=True,
        privacy_boundary_passed=True,
        infrastructure_neutrality_passed=True,
    )


def _recovery() -> RecoveryEvidence:
    return RecoveryEvidence(
        binding=_binding(),
        upgrade_qualified=True,
        rollback_qualified=True,
        user_state_preserved=True,
        real_target_accepted=False,
        multi_node_ha_restart_qualified=False,
    )


def _artifacts() -> ArtifactEvidence:
    return ArtifactEvidence(
        binding=_binding(),
        candidate_artifact_sha256=DIGEST,
        qualification_manifest=True,
        provenance_v2=True,
        source_artifact_sha256=DIGEST,
        deployment_artifact_sha256=DIGEST,
        checksum_sidecar=True,
        sha256sums=True,
        acceptance_manifest=True,
        release_manifest=True,
        spdx_sbom=True,
    )


def _decision(*, claims: StableProfileClaims = StableProfileClaims()):
    return evaluate_bounded_stable_profile(
        version=VERSION,
        revision=REVISION,
        qualification=_qualification(),
        security=_security(),
        recovery=_recovery(),
        artifacts=_artifacts(),
        claims=claims,
    )


def test_core_single_node_stable_does_not_invent_optional_capability_claims() -> None:
    decision = _decision()
    assert decision.ready is True
    assert decision.blockers == ()
    assert decision.profile == "core-single-node"
    assert decision.provider_execution_supported is False
    assert decision.multi_node_ha_supported is False
    assert decision.commercial_launch_cleared is False
    assert decision.release_authorized is False
    assert decision.external_publication_authorized is False


def test_provider_execution_claim_requires_exact_qualified_provider_evidence() -> None:
    decision = _decision(claims=StableProfileClaims(provider_execution=True))
    assert decision.ready is False
    assert decision.blockers == ("provider_evidence_missing",)
    assert decision.provider_execution_supported is False


def test_multi_node_ha_claim_requires_real_target_and_ha_evidence() -> None:
    decision = _decision(claims=StableProfileClaims(multi_node_ha=True))
    assert decision.ready is False
    assert decision.blockers == (
        "real_target_acceptance",
        "multi_node_ha_restart",
        "real_environment_evidence_missing",
    )
    assert decision.multi_node_ha_supported is False


def test_commercial_launch_claim_requires_separate_commercial_evidence() -> None:
    decision = _decision(claims=StableProfileClaims(commercial_launch=True))
    assert decision.ready is False
    assert decision.blockers == ("commercial_evidence_missing",)
    assert decision.commercial_launch_cleared is False


def test_core_stable_keeps_security_upgrade_rollback_and_user_state_fail_closed() -> None:
    recovery = RecoveryEvidence(
        binding=_binding(),
        upgrade_qualified=False,
        rollback_qualified=False,
        user_state_preserved=False,
        real_target_accepted=False,
        multi_node_ha_restart_qualified=False,
    )
    decision = evaluate_bounded_stable_profile(
        version=VERSION,
        revision=REVISION,
        qualification=_qualification(),
        security=_security(),
        recovery=recovery,
        artifacts=_artifacts(),
    )
    assert decision.ready is False
    assert decision.blockers == ("upgrade", "rollback", "user_state_preservation")


def test_core_stable_requires_complete_public_artifact_set() -> None:
    artifacts = ArtifactEvidence(
        binding=_binding(),
        candidate_artifact_sha256=DIGEST,
        qualification_manifest=True,
        provenance_v2=True,
    )
    decision = evaluate_bounded_stable_profile(
        version=VERSION,
        revision=REVISION,
        qualification=_qualification(),
        security=_security(),
        recovery=_recovery(),
        artifacts=artifacts,
    )
    assert decision.ready is False
    assert decision.blockers == (
        "source_artifact_digest",
        "deployment_artifact_digest",
        "checksum_sidecar",
        "sha256sums",
        "acceptance_manifest",
        "release_manifest",
        "spdx_sbom",
    )


def test_bounded_stable_decision_matches_closed_public_schema() -> None:
    schema = json.loads(
        (ROOT / "contracts/releases/bounded-stable-profile-decision.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(_decision().to_dict())
