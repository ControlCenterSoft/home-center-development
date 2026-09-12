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
    ArtifactEvidence,
    CommercialEvidence,
    ProviderAdapterEvidence,
    QualificationEvidence,
    RealEnvironmentEvidence,
    RecoveryEvidence,
    ReleaseBinding,
    SecurityEvidence,
    evaluate_release_promotion,
)

VERSION = "0.57.0"
REVISION = "c" * 40
OTHER_REVISION = "d" * 40
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


class ReleasePromotionDecisionSchemaBlockerTests(unittest.TestCase):
    def test_fail_closed_real_environment_and_provider_blockers_match_schema(self) -> None:
        binding = ReleaseBinding(version=VERSION, revision=REVISION)
        other_binding = ReleaseBinding(version=VERSION, revision=OTHER_REVISION)

        decision = evaluate_release_promotion(
            target_channel=CANDIDATE,
            version=VERSION,
            revision=REVISION,
            qualification=QualificationEvidence(
                binding=binding,
                ci_passed=True,
                exact_source_identity=True,
                reproducible_artifact=True,
            ),
            security=SecurityEvidence(
                binding=binding,
                codeql_passed=True,
                privacy_boundary_passed=True,
                infrastructure_neutrality_passed=True,
            ),
            recovery=RecoveryEvidence(
                binding=binding,
                upgrade_qualified=True,
                rollback_qualified=True,
                user_state_preserved=True,
                real_target_accepted=True,
                multi_node_ha_restart_qualified=True,
            ),
            real_environment=RealEnvironmentEvidence(
                binding=other_binding,
                candidate_artifact_sha256=OTHER_DIGEST,
                evidence_sha256="",
                qualified=False,
            ),
            provider=ProviderAdapterEvidence(
                binding=other_binding,
                adapter_id="provider.example",
                adapter_version="1.0.0",
                candidate_artifact_sha256=OTHER_DIGEST,
                evidence_sha256="",
                qualified=False,
            ),
            artifacts=ArtifactEvidence(
                binding=binding,
                candidate_artifact_sha256=DIGEST,
                qualification_manifest=True,
                provenance_v2=True,
            ),
            commercial=CommercialEvidence(
                binding=binding,
                candidate_artifact_sha256=DIGEST,
                disposition=APPROVED,
                evidence_sha256=DIGEST,
                dependencies_reviewed=True,
                redistribution_reviewed=True,
                notices_prepared=True,
                source_obligations_resolved=True,
                sbom_reviewed=True,
                legal_terms_dispositioned=True,
                release_claims_reviewed=True,
            ),
        )

        self.assertEqual(
            decision.blockers,
            (
                "real_environment_binding",
                "real_environment_evidence",
                "real_environment_artifact_binding",
                "real_environment_qualification",
                "provider_binding",
                "provider_evidence",
                "provider_candidate_artifact_binding",
                "provider_adapter_qualification",
            ),
        )

        schema = json.loads(
            (ROOT / "contracts/releases/release-promotion-decision.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(decision.to_dict())

    def test_commercial_candidate_binding_blocker_matches_schema(self) -> None:
        binding = ReleaseBinding(version=VERSION, revision=REVISION)
        decision = evaluate_release_promotion(
            target_channel=CANDIDATE,
            version=VERSION,
            revision=REVISION,
            qualification=QualificationEvidence(
                binding=binding,
                ci_passed=True,
                exact_source_identity=True,
                reproducible_artifact=True,
            ),
            security=SecurityEvidence(
                binding=binding,
                codeql_passed=True,
                privacy_boundary_passed=True,
                infrastructure_neutrality_passed=True,
            ),
            recovery=RecoveryEvidence(
                binding=binding,
                upgrade_qualified=True,
                rollback_qualified=True,
                user_state_preserved=True,
                real_target_accepted=True,
                multi_node_ha_restart_qualified=True,
            ),
            real_environment=RealEnvironmentEvidence(
                binding=binding,
                candidate_artifact_sha256=DIGEST,
                evidence_sha256=DIGEST,
                qualified=True,
            ),
            provider=ProviderAdapterEvidence(
                binding=binding,
                adapter_id="provider.example",
                adapter_version="1.0.0",
                candidate_artifact_sha256=DIGEST,
                evidence_sha256=DIGEST,
                qualified=True,
            ),
            artifacts=ArtifactEvidence(
                binding=binding,
                candidate_artifact_sha256=DIGEST,
                qualification_manifest=True,
                provenance_v2=True,
            ),
            commercial=CommercialEvidence(
                binding=binding,
                candidate_artifact_sha256=OTHER_DIGEST,
                disposition=APPROVED,
                evidence_sha256=DIGEST,
                dependencies_reviewed=True,
                redistribution_reviewed=True,
                notices_prepared=True,
                source_obligations_resolved=True,
                sbom_reviewed=True,
                legal_terms_dispositioned=True,
                release_claims_reviewed=True,
            ),
        )
        self.assertEqual(decision.blockers, ("commercial_candidate_artifact_binding",))

        schema = json.loads(
            (ROOT / "contracts/releases/release-promotion-decision.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(decision.to_dict())


if __name__ == "__main__":
    unittest.main()
