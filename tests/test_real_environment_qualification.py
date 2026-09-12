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

from home_center.real_environment_qualification import (  # noqa: E402
    RealEnvironmentQualificationError,
    RealEnvironmentQualificationEvidence,
    evaluate_real_environment_qualification,
)

VERSION = "0.57.0"
REVISION = "7" * 40
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64


def _evidence(**overrides: object) -> RealEnvironmentQualificationEvidence:
    values: dict[str, object] = {
        "version": VERSION,
        "revision": REVISION,
        "candidate_artifact_sha256": DIGEST_A,
        "target_node_id": "target-node-a",
        "target_environment_sha256": DIGEST_B,
        "target_execution_transcript_sha256": DIGEST_C,
        "target_install_or_upgrade_exercised": True,
        "target_health_ready": True,
        "target_user_state_preserved": True,
        "target_rollback_exercised": True,
        "ha_node_ids": ("ha-node-a", "ha-node-b"),
        "ha_environment_sha256": DIGEST_D,
        "ha_execution_transcript_sha256": DIGEST_E,
        "real_multi_node_contour_exercised": True,
        "replication_healthy": True,
        "peer_continuity_verified": True,
        "restart_exercised": True,
        "post_restart_health_ready": True,
        "ha_rollback_exercised": True,
    }
    values.update(overrides)
    return RealEnvironmentQualificationEvidence(**values)  # type: ignore[arg-type]


class RealEnvironmentQualificationTests(unittest.TestCase):
    def test_complete_real_environment_evidence_qualifies_without_authority(self) -> None:
        decision = evaluate_real_environment_qualification(_evidence())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertRegex(decision.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(decision.evidence_sha256, "0" * 64)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_hosted_or_single_node_claims_cannot_substitute_real_acceptance(self) -> None:
        decision = evaluate_real_environment_qualification(
            _evidence(
                target_install_or_upgrade_exercised=False,
                real_multi_node_contour_exercised=False,
                replication_healthy=False,
                peer_continuity_verified=False,
                restart_exercised=False,
            )
        )
        self.assertFalse(decision.qualified)
        self.assertEqual(
            decision.blockers,
            (
                "target_install_or_upgrade",
                "real_multi_node_contour",
                "replication_health",
                "peer_continuity",
                "restart",
            ),
        )
        self.assertEqual(decision.evidence_sha256, "0" * 64)

    def test_missing_target_or_ha_evidence_digests_fail_closed(self) -> None:
        decision = evaluate_real_environment_qualification(
            _evidence(
                target_environment_sha256="",
                target_execution_transcript_sha256="bad",
                ha_environment_sha256="",
                ha_execution_transcript_sha256="bad",
            )
        )
        self.assertEqual(
            decision.blockers,
            (
                "target_environment_digest",
                "target_execution_transcript_digest",
                "ha_environment_digest",
                "ha_execution_transcript_digest",
            ),
        )

    def test_duplicate_or_too_small_ha_contour_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            RealEnvironmentQualificationError, "real_environment_ha_node_count_invalid"
        ):
            evaluate_real_environment_qualification(_evidence(ha_node_ids=("ha-node-a",)))
        with self.assertRaisesRegex(
            RealEnvironmentQualificationError, "real_environment_ha_node_ids_not_unique"
        ):
            evaluate_real_environment_qualification(
                _evidence(ha_node_ids=("ha-node-a", "ha-node-a"))
            )

    def test_invalid_release_or_node_identity_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            RealEnvironmentQualificationError, "real_environment_revision_invalid"
        ):
            evaluate_real_environment_qualification(_evidence(revision="latest"))
        with self.assertRaisesRegex(
            RealEnvironmentQualificationError, "real_environment_target_node_id_invalid"
        ):
            evaluate_real_environment_qualification(_evidence(target_node_id="bad node"))

    def test_serialized_decision_matches_closed_schema(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/releases/real-environment-qualification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(
            evaluate_real_environment_qualification(_evidence()).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
