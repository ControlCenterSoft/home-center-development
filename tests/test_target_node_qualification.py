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

from home_center.target_node_qualification import (  # noqa: E402
    TargetNodeQualificationError,
    TargetNodeQualificationEvidence,
    evaluate_target_node_qualification,
)

VERSION = "0.57.0"
REVISION = "7" * 40
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def _evidence(**overrides: object) -> TargetNodeQualificationEvidence:
    values: dict[str, object] = {
        "version": VERSION,
        "revision": REVISION,
        "candidate_artifact_sha256": DIGEST_A,
        "target_node_id": "target-node-a",
        "target_environment_sha256": DIGEST_B,
        "target_execution_transcript_sha256": DIGEST_C,
        "install_or_upgrade_exercised": True,
        "health_ready": True,
        "user_state_preserved": True,
        "rollback_exercised": True,
    }
    values.update(overrides)
    return TargetNodeQualificationEvidence(**values)  # type: ignore[arg-type]


class TargetNodeQualificationTests(unittest.TestCase):
    def test_complete_target_node_evidence_qualifies_without_authority(self) -> None:
        decision = evaluate_target_node_qualification(_evidence())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertRegex(decision.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(decision.evidence_sha256, "0" * 64)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_false_real_target_observation_fails_closed(self) -> None:
        decision = evaluate_target_node_qualification(
            _evidence(health_ready=False, rollback_exercised=False)
        )
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.blockers, ("target_health_ready", "target_rollback"))
        self.assertEqual(decision.evidence_sha256, "0" * 64)

    def test_missing_content_digests_fail_closed(self) -> None:
        decision = evaluate_target_node_qualification(
            _evidence(target_environment_sha256="", target_execution_transcript_sha256="bad")
        )
        self.assertEqual(
            decision.blockers,
            ("target_environment_digest", "target_execution_transcript_digest"),
        )

    def test_invalid_release_or_node_identity_is_rejected(self) -> None:
        with self.assertRaisesRegex(TargetNodeQualificationError, "target_node_revision_invalid"):
            evaluate_target_node_qualification(_evidence(revision="latest"))
        with self.assertRaisesRegex(TargetNodeQualificationError, "target_node_id_invalid"):
            evaluate_target_node_qualification(_evidence(target_node_id="bad node"))

    def test_serialized_decision_matches_closed_schema(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/releases/target-node-qualification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(
            evaluate_target_node_qualification(_evidence()).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
