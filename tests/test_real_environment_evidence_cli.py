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

SCRIPT = ROOT / "scripts/evaluate_real_environment_evidence.py"
SPEC = importlib.util.spec_from_file_location("evaluate_real_environment_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RealEnvironmentEvidenceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.paths: dict[str, Path] = {}
        self.digests: dict[str, str] = {}
        for name, payload in (
            ("candidate", b"candidate-artifact-0.57.0\n"),
            ("target_environment", b'{"node":"target-a","os":"linux"}\n'),
            ("target_transcript", b"install=pass\nhealth=pass\nrollback=pass\n"),
            ("ha_environment", b'{"nodes":["ha-a","ha-b"]}\n'),
            ("ha_transcript", b"replication=pass\nrestart=pass\nrollback=pass\n"),
        ):
            path = self.root / f"{name}.bin"
            path.write_bytes(payload)
            self.paths[name] = path
            self.digests[name] = hashlib.sha256(payload).hexdigest()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _manifest(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "home-center.real-environment-evidence.v1",
            "version": "0.57.0",
            "revision": "7" * 40,
            "candidate_artifact_sha256": self.digests["candidate"],
            "target_node_id": "target-node-a",
            "target_environment_sha256": self.digests["target_environment"],
            "target_execution_transcript_sha256": self.digests["target_transcript"],
            "target_install_or_upgrade_exercised": True,
            "target_health_ready": True,
            "target_user_state_preserved": True,
            "target_rollback_exercised": True,
            "ha_node_ids": ["ha-node-a", "ha-node-b"],
            "ha_environment_sha256": self.digests["ha_environment"],
            "ha_execution_transcript_sha256": self.digests["ha_transcript"],
            "real_multi_node_contour_exercised": True,
            "replication_healthy": True,
            "peer_continuity_verified": True,
            "restart_exercised": True,
            "post_restart_health_ready": True,
            "ha_rollback_exercised": True,
        }
        value.update(overrides)
        return value

    def _qualify(self, value: dict[str, object]):
        return MODULE.qualify_manifest(
            value,
            candidate_artifact=self.paths["candidate"],
            target_environment=self.paths["target_environment"],
            target_transcript=self.paths["target_transcript"],
            ha_environment=self.paths["ha_environment"],
            ha_transcript=self.paths["ha_transcript"],
        )

    def test_exact_local_file_bindings_qualify_without_release_authority(self) -> None:
        decision = self._qualify(self._manifest())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertRegex(decision.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(decision.evidence_sha256, "0" * 64)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_candidate_artifact_digest_mismatch_fails_before_qualification(self) -> None:
        with self.assertRaisesRegex(
            MODULE.RealEnvironmentEvidenceInputError,
            "candidate_artifact_digest_mismatch",
        ):
            self._qualify(self._manifest(candidate_artifact_sha256="f" * 64))

    def test_transcript_digest_mismatch_fails_before_qualification(self) -> None:
        with self.assertRaisesRegex(
            MODULE.RealEnvironmentEvidenceInputError,
            "target_execution_transcript_digest_mismatch",
        ):
            self._qualify(self._manifest(target_execution_transcript_sha256="e" * 64))

    def test_unknown_manifest_field_is_rejected_fail_closed(self) -> None:
        value = self._manifest()
        value["operator_note"] = "trusted"
        with self.assertRaisesRegex(MODULE.RealEnvironmentEvidenceInputError, "input_shape"):
            self._qualify(value)

    def test_duplicate_json_key_is_rejected_before_manifest_validation(self) -> None:
        path = self.root / "duplicate.json"
        path.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.RealEnvironmentEvidenceInputError,
            "input_duplicate_key",
        ):
            MODULE._load_json(path)

    def test_false_observation_remains_blocked_after_exact_file_binding(self) -> None:
        decision = self._qualify(self._manifest(peer_continuity_verified=False))
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.blockers, ("peer_continuity",))
        self.assertEqual(decision.evidence_sha256, "0" * 64)

    def test_manifest_and_decision_match_closed_contracts(self) -> None:
        manifest = self._manifest()
        evidence_schema = json.loads(
            (ROOT / "contracts/releases/real-environment-evidence.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        decision_schema = json.loads(
            (ROOT / "contracts/releases/real-environment-qualification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(evidence_schema).validate(manifest)
        jsonschema.Draft202012Validator(decision_schema).validate(
            self._qualify(manifest).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
