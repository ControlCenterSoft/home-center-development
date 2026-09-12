from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "product/control-plane/src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

SCRIPT = ROOT / "scripts/evaluate_target_node_evidence.py"
SPEC = importlib.util.spec_from_file_location("evaluate_target_node_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TargetNodeEvidenceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.paths: dict[str, Path] = {}
        self.digests: dict[str, str] = {}
        for name, payload in (
            ("candidate", b"candidate-artifact-0.57.0\n"),
            ("target_environment", b'{"node":"target-a","os":"linux"}\n'),
            ("target_transcript", b"install=pass\nhealth=pass\nrollback=pass\n"),
        ):
            path = self.root / f"{name}.bin"
            path.write_bytes(payload)
            self.paths[name] = path
            self.digests[name] = hashlib.sha256(payload).hexdigest()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _manifest(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "home-center.target-node-evidence.v1",
            "version": "0.57.0",
            "revision": "7" * 40,
            "candidate_artifact_sha256": self.digests["candidate"],
            "target_node_id": "target-node-a",
            "target_environment_sha256": self.digests["target_environment"],
            "target_execution_transcript_sha256": self.digests["target_transcript"],
            "install_or_upgrade_exercised": True,
            "health_ready": True,
            "user_state_preserved": True,
            "rollback_exercised": True,
        }
        value.update(overrides)
        return value

    def _qualify(self, value: dict[str, object]):
        return MODULE.qualify_manifest(
            value,
            candidate_artifact=self.paths["candidate"],
            target_environment=self.paths["target_environment"],
            target_transcript=self.paths["target_transcript"],
        )

    def test_exact_local_file_bindings_qualify_without_release_authority(self) -> None:
        decision = self._qualify(self._manifest())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_candidate_artifact_digest_mismatch_fails_before_qualification(self) -> None:
        with self.assertRaisesRegex(
            MODULE.TargetNodeEvidenceInputError,
            "candidate_artifact_digest_mismatch",
        ):
            self._qualify(self._manifest(candidate_artifact_sha256="f" * 64))

    def test_unknown_manifest_field_is_rejected_fail_closed(self) -> None:
        value = self._manifest()
        value["operator_note"] = "trusted"
        with self.assertRaisesRegex(MODULE.TargetNodeEvidenceInputError, "input_shape"):
            self._qualify(value)

    def test_false_observation_remains_blocked_after_exact_file_binding(self) -> None:
        decision = self._qualify(self._manifest(health_ready=False))
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.blockers, ("target_health_ready",))

    def test_manifest_and_decision_match_closed_contracts(self) -> None:
        manifest = self._manifest()
        evidence_schema = json.loads(
            (ROOT / "contracts/releases/target-node-evidence.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        decision_schema = json.loads(
            (ROOT / "contracts/releases/target-node-qualification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(evidence_schema).validate(manifest)
        jsonschema.Draft202012Validator(decision_schema).validate(
            self._qualify(manifest).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
