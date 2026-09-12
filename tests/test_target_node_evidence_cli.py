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

        candidate_payload = b"candidate-artifact-0.57.0\n"
        candidate_path = self.root / "candidate.bin"
        candidate_path.write_bytes(candidate_payload)
        self.paths["candidate"] = candidate_path
        self.digests["candidate"] = hashlib.sha256(candidate_payload).hexdigest()

        self.environment: dict[str, object] = {
            "schema": "home-center.target-node-environment.v1",
            "target_node_id": "target-node-a",
            "hostname": "target-node-a",
            "architecture": "x86_64",
            "os_id": "ubuntu",
            "os_version": "26.04",
            "service_manager": "systemd",
            "current_version": "0.56.0",
            "current_revision": "6" * 40,
        }
        environment_payload = MODULE.canonical_json(self.environment)
        environment_path = self.root / "target_environment.json"
        environment_path.write_bytes(environment_payload)
        self.paths["target_environment"] = environment_path
        self.digests["target_environment"] = hashlib.sha256(environment_payload).hexdigest()

        self.transcript: dict[str, object] = {
            "schema": "home-center.target-node-execution-transcript.v1",
            "version": "0.57.0",
            "revision": "7" * 40,
            "candidate_artifact_sha256": self.digests["candidate"],
            "target_node_id": "target-node-a",
            "operation": "upgrade",
            "source_version": "0.56.0",
            "source_revision": "6" * 40,
            "target_version": "0.57.0",
            "target_revision": "7" * 40,
            "deployment_transaction_sha256": "d" * 64,
            "install_or_upgrade_exercised": True,
            "service_active": True,
            "readyz_status": 200,
            "user_state_preserved": True,
            "rollback_exercised": True,
            "rollback_version": "0.56.0",
            "rollback_revision": "6" * 40,
            "rollback_service_active": True,
            "rollback_readyz_status": 200,
        }
        self._write_transcript(self.transcript)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_environment(self, value: dict[str, object]) -> None:
        payload = MODULE.canonical_json(value)
        self.paths["target_environment"].write_bytes(payload)
        self.digests["target_environment"] = hashlib.sha256(payload).hexdigest()

    def _write_transcript(self, value: dict[str, object]) -> None:
        payload = MODULE.canonical_json(value)
        path = self.root / "target_transcript.json"
        path.write_bytes(payload)
        self.paths["target_transcript"] = path
        self.digests["target_transcript"] = hashlib.sha256(payload).hexdigest()

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

    def test_exact_semantic_file_bindings_qualify_without_release_authority(self) -> None:
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

    def test_unstructured_transcript_is_rejected_even_when_digest_matches(self) -> None:
        payload = b"install=pass\nhealth=pass\nrollback=pass\n"
        self.paths["target_transcript"].write_bytes(payload)
        self.digests["target_transcript"] = hashlib.sha256(payload).hexdigest()
        with self.assertRaisesRegex(MODULE.TargetNodeEvidenceInputError, "input_invalid"):
            self._qualify(self._manifest())

    def test_environment_must_bind_exact_target_node(self) -> None:
        environment = dict(self.environment)
        environment["target_node_id"] = "other-node"
        environment["hostname"] = "other-node"
        self._write_environment(environment)
        with self.assertRaisesRegex(
            MODULE.TargetNodeEvidenceInputError,
            "target_environment_node_binding",
        ):
            self._qualify(self._manifest())

    def test_transcript_must_bind_exact_candidate_artifact(self) -> None:
        transcript = dict(self.transcript)
        transcript["candidate_artifact_sha256"] = "e" * 64
        self._write_transcript(transcript)
        with self.assertRaisesRegex(
            MODULE.TargetNodeEvidenceInputError,
            "target_transcript_candidate_binding",
        ):
            self._qualify(self._manifest())

    def test_transcript_source_identity_must_match_environment(self) -> None:
        transcript = dict(self.transcript)
        transcript["source_revision"] = "5" * 40
        self._write_transcript(transcript)
        with self.assertRaisesRegex(
            MODULE.TargetNodeEvidenceInputError,
            "target_transcript_source_binding",
        ):
            self._qualify(self._manifest())

    def test_health_claim_requires_service_and_readyz_observation(self) -> None:
        transcript = dict(self.transcript)
        transcript["service_active"] = False
        transcript["readyz_status"] = 503
        self._write_transcript(transcript)
        with self.assertRaisesRegex(
            MODULE.TargetNodeEvidenceInputError,
            "target_transcript_service_active",
        ):
            self._qualify(self._manifest())

    def test_rollback_claim_requires_source_identity_and_readyz(self) -> None:
        transcript = dict(self.transcript)
        transcript["rollback_revision"] = "4" * 40
        self._write_transcript(transcript)
        with self.assertRaisesRegex(
            MODULE.TargetNodeEvidenceInputError,
            "target_transcript_rollback_identity_binding",
        ):
            self._qualify(self._manifest())

        transcript = dict(self.transcript)
        transcript["rollback_readyz_status"] = 503
        self._write_transcript(transcript)
        with self.assertRaisesRegex(
            MODULE.TargetNodeEvidenceInputError,
            "target_transcript_rollback_readyz",
        ):
            self._qualify(self._manifest())

    def test_false_observation_remains_blocked_after_exact_file_binding(self) -> None:
        decision = self._qualify(self._manifest(health_ready=False))
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.blockers, ("target_health_ready",))

    def test_manifest_environment_transcript_and_decision_match_closed_contracts(self) -> None:
        manifest = self._manifest()
        schemas = {
            "manifest": ROOT / "contracts/releases/target-node-evidence.v1.schema.json",
            "environment": ROOT / "contracts/releases/target-node-environment.v1.schema.json",
            "transcript": ROOT / "contracts/releases/target-node-execution-transcript.v1.schema.json",
            "decision": ROOT / "contracts/releases/target-node-qualification.v1.schema.json",
        }
        loaded = {
            name: json.loads(path.read_text(encoding="utf-8"))
            for name, path in schemas.items()
        }
        for schema in loaded.values():
            jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(loaded["manifest"]).validate(manifest)
        jsonschema.Draft202012Validator(loaded["environment"]).validate(self.environment)
        jsonschema.Draft202012Validator(loaded["transcript"]).validate(self.transcript)
        jsonschema.Draft202012Validator(loaded["decision"]).validate(
            self._qualify(manifest).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
