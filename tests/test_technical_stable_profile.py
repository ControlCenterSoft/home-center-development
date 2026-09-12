from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "product/control-plane/src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from home_center.release_promotion_gate import (  # noqa: E402
    ArtifactEvidence,
    QualificationEvidence,
    RecoveryEvidence,
    ReleaseBinding,
    SecurityEvidence,
)
from home_center.technical_stable_profile import (  # noqa: E402
    TargetNodeEvidence,
    TechnicalStableProfileError,
    evaluate_single_node_technical_stable,
)

VERSION = "0.57.0"
REVISION = "c" * 40
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


def _binding(revision: str = REVISION) -> ReleaseBinding:
    return ReleaseBinding(version=VERSION, revision=revision)


def _qualification(revision: str = REVISION) -> QualificationEvidence:
    return QualificationEvidence(
        binding=_binding(revision),
        ci_passed=True,
        exact_source_identity=True,
        reproducible_artifact=True,
    )


def _security(revision: str = REVISION) -> SecurityEvidence:
    return SecurityEvidence(
        binding=_binding(revision),
        codeql_passed=True,
        privacy_boundary_passed=True,
        infrastructure_neutrality_passed=True,
    )


def _recovery(revision: str = REVISION) -> RecoveryEvidence:
    return RecoveryEvidence(
        binding=_binding(revision),
        upgrade_qualified=True,
        rollback_qualified=True,
        user_state_preserved=True,
        real_target_accepted=False,
        multi_node_ha_restart_qualified=False,
    )


def _target(
    revision: str = REVISION,
    *,
    artifact_sha256: str = DIGEST,
    evidence_sha256: str = DIGEST,
    qualified: bool = True,
) -> TargetNodeEvidence:
    return TargetNodeEvidence(
        binding=_binding(revision),
        candidate_artifact_sha256=artifact_sha256,
        evidence_sha256=evidence_sha256,
        qualified=qualified,
    )


def _artifacts(revision: str = REVISION, *, complete: bool = True) -> ArtifactEvidence:
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


def _decision():
    return evaluate_single_node_technical_stable(
        version=VERSION,
        revision=REVISION,
        qualification=_qualification(),
        security=_security(),
        recovery=_recovery(),
        target_node=_target(),
        artifacts=_artifacts(),
    )


class TechnicalStableProfileTests(unittest.TestCase):
    def test_single_node_stable_can_be_ready_without_ha_provider_or_commercial_claims(self) -> None:
        decision = _decision()
        self.assertTrue(decision.ready)
        self.assertEqual(decision.blockers, ())
        self.assertTrue(decision.target_node_qualified)
        self.assertFalse(decision.ha_supported)
        self.assertFalse(decision.provider_execution_supported)
        self.assertFalse(decision.commercial_launch_cleared)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_target_node_is_still_a_hard_technical_gate(self) -> None:
        decision = evaluate_single_node_technical_stable(
            version=VERSION,
            revision=REVISION,
            qualification=_qualification(),
            security=_security(),
            recovery=_recovery(),
            target_node=_target(evidence_sha256="", qualified=False),
            artifacts=_artifacts(),
        )
        self.assertEqual(
            decision.blockers,
            ("target_node_evidence", "target_node_qualification"),
        )

    def test_target_node_evidence_must_bind_exact_candidate_artifact(self) -> None:
        decision = evaluate_single_node_technical_stable(
            version=VERSION,
            revision=REVISION,
            qualification=_qualification(),
            security=_security(),
            recovery=_recovery(),
            target_node=_target(artifact_sha256=OTHER_DIGEST),
            artifacts=_artifacts(),
        )
        self.assertEqual(decision.blockers, ("target_node_candidate_artifact_binding",))

    def test_stable_artifact_set_remains_mandatory(self) -> None:
        decision = evaluate_single_node_technical_stable(
            version=VERSION,
            revision=REVISION,
            qualification=_qualification(),
            security=_security(),
            recovery=_recovery(),
            target_node=_target(),
            artifacts=_artifacts(complete=False),
        )
        self.assertEqual(
            decision.blockers,
            (
                "source_artifact_digest",
                "deployment_artifact_digest",
                "checksum_sidecar",
                "sha256sums",
                "acceptance_manifest",
                "release_manifest",
                "spdx_sbom",
            ),
        )

    def test_cross_revision_evidence_is_rejected(self) -> None:
        other = "d" * 40
        decision = evaluate_single_node_technical_stable(
            version=VERSION,
            revision=REVISION,
            qualification=_qualification(other),
            security=_security(other),
            recovery=_recovery(other),
            target_node=_target(other),
            artifacts=_artifacts(other),
        )
        self.assertEqual(
            decision.blockers,
            (
                "qualification_binding",
                "security_binding",
                "recovery_binding",
                "target_node_binding",
                "artifact_binding",
            ),
        )

    def test_invalid_release_identity_is_rejected_before_evaluation(self) -> None:
        with self.assertRaisesRegex(TechnicalStableProfileError, "release_revision_invalid"):
            evaluate_single_node_technical_stable(
                version=VERSION,
                revision="latest",
                qualification=_qualification(),
                security=_security(),
                recovery=_recovery(),
                target_node=_target(),
                artifacts=_artifacts(),
            )

    def test_serialized_decision_matches_closed_schema(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/releases/technical-stable-profile-decision.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(_decision().to_dict())


if __name__ == "__main__":
    unittest.main()
