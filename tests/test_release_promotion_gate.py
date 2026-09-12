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
    APPROVED,
    CANDIDATE,
    STABLE,
    ArtifactEvidence,
    CommercialEvidence,
    ProviderAdapterEvidence,
    QualificationEvidence,
    RecoveryEvidence,
    ReleaseBinding,
    ReleasePromotionError,
    SecurityEvidence,
    evaluate_release_promotion,
)

VERSION = "0.57.0"
REVISION = "c" * 40
DIGEST = "a" * 64


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
        real_target_accepted=True,
        multi_node_ha_restart_qualified=True,
    )


def _provider(revision: str = REVISION) -> ProviderAdapterEvidence:
    return ProviderAdapterEvidence(
        binding=_binding(revision),
        adapter_id="provider.example",
        adapter_version="1.0.0",
        evidence_sha256=DIGEST,
        qualified=True,
    )


def _artifacts(revision: str = REVISION, *, stable: bool = False) -> ArtifactEvidence:
    return ArtifactEvidence(
        binding=_binding(revision),
        candidate_artifact_sha256=DIGEST,
        qualification_manifest=True,
        provenance_v2=True,
        source_artifact_sha256=DIGEST if stable else "",
        deployment_artifact_sha256=DIGEST if stable else "",
        checksum_sidecar=stable,
        sha256sums=stable,
        acceptance_manifest=stable,
        release_manifest=stable,
        spdx_sbom=stable,
    )


def _commercial(revision: str = REVISION) -> CommercialEvidence:
    return CommercialEvidence(
        binding=_binding(revision),
        disposition=APPROVED,
        evidence_sha256=DIGEST,
        dependencies_reviewed=True,
        redistribution_reviewed=True,
        notices_prepared=True,
        source_obligations_resolved=True,
        sbom_reviewed=True,
        legal_terms_dispositioned=True,
        release_claims_reviewed=True,
    )


def _decision(channel: str = CANDIDATE, *, stable_artifacts: bool = False):
    return evaluate_release_promotion(
        target_channel=channel,
        version=VERSION,
        revision=REVISION,
        qualification=_qualification(),
        security=_security(),
        recovery=_recovery(),
        provider=_provider(),
        artifacts=_artifacts(stable=stable_artifacts),
        commercial=_commercial(),
    )


class ReleasePromotionGateTests(unittest.TestCase):
    def test_candidate_ready_never_grants_release_authority(self) -> None:
        decision = _decision()
        self.assertTrue(decision.ready)
        self.assertEqual(decision.blockers, ())
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_stable_requires_public_release_asset_evidence(self) -> None:
        decision = _decision(STABLE)
        self.assertFalse(decision.ready)
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
        self.assertTrue(_decision(STABLE, stable_artifacts=True).ready)

    def test_real_environment_provider_and_commercial_gates_fail_closed(self) -> None:
        recovery = RecoveryEvidence(
            binding=_binding(),
            upgrade_qualified=True,
            rollback_qualified=True,
            user_state_preserved=True,
            real_target_accepted=False,
            multi_node_ha_restart_qualified=False,
        )
        provider = ProviderAdapterEvidence(
            binding=_binding(),
            adapter_id="provider.example",
            adapter_version="1.0.0",
            evidence_sha256=DIGEST,
            qualified=False,
        )
        commercial = CommercialEvidence(
            binding=_binding(),
            disposition="review-required",
            evidence_sha256=DIGEST,
            dependencies_reviewed=True,
            redistribution_reviewed=True,
            notices_prepared=False,
            source_obligations_resolved=True,
            sbom_reviewed=True,
            legal_terms_dispositioned=False,
            release_claims_reviewed=False,
        )
        decision = evaluate_release_promotion(
            target_channel=CANDIDATE,
            version=VERSION,
            revision=REVISION,
            qualification=_qualification(),
            security=_security(),
            recovery=recovery,
            provider=provider,
            artifacts=_artifacts(),
            commercial=commercial,
        )
        self.assertEqual(
            decision.blockers,
            (
                "real_target_acceptance",
                "multi_node_ha_restart",
                "provider_adapter_qualification",
                "commercial_disposition",
                "notices_prepared",
                "legal_terms_dispositioned",
                "release_claims_reviewed",
            ),
        )

    def test_cross_revision_evidence_is_rejected(self) -> None:
        other = "d" * 40
        decision = evaluate_release_promotion(
            target_channel=CANDIDATE,
            version=VERSION,
            revision=REVISION,
            qualification=_qualification(other),
            security=_security(other),
            recovery=_recovery(other),
            provider=_provider(other),
            artifacts=_artifacts(other),
            commercial=_commercial(other),
        )
        self.assertEqual(
            decision.blockers,
            (
                "qualification_binding",
                "security_binding",
                "recovery_binding",
                "provider_binding",
                "artifact_binding",
                "commercial_binding",
            ),
        )

    def test_approved_label_alone_is_not_commercial_evidence(self) -> None:
        commercial = CommercialEvidence(
            binding=_binding(),
            disposition=APPROVED,
            evidence_sha256="",
            dependencies_reviewed=False,
            redistribution_reviewed=False,
            notices_prepared=False,
            source_obligations_resolved=False,
            sbom_reviewed=False,
            legal_terms_dispositioned=False,
            release_claims_reviewed=False,
        )
        decision = evaluate_release_promotion(
            target_channel=CANDIDATE,
            version=VERSION,
            revision=REVISION,
            qualification=_qualification(),
            security=_security(),
            recovery=_recovery(),
            provider=_provider(),
            artifacts=_artifacts(),
            commercial=commercial,
        )
        self.assertEqual(
            decision.blockers,
            (
                "commercial_evidence",
                "dependencies_reviewed",
                "redistribution_reviewed",
                "notices_prepared",
                "source_obligations_resolved",
                "sbom_reviewed",
                "legal_terms_dispositioned",
                "release_claims_reviewed",
            ),
        )

    def test_invalid_release_identity_rejected_before_evaluation(self) -> None:
        with self.assertRaisesRegex(ReleasePromotionError, "release_revision_invalid"):
            evaluate_release_promotion(
                target_channel=CANDIDATE,
                version=VERSION,
                revision="latest",
                qualification=_qualification(),
                security=_security(),
                recovery=_recovery(),
                provider=_provider(),
                artifacts=_artifacts(),
                commercial=_commercial(),
            )

    def test_serialized_decision_matches_closed_schema(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/releases/release-promotion-decision.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(_decision().to_dict())


if __name__ == "__main__":
    unittest.main()
