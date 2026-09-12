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

SCRIPT = ROOT / "scripts/evaluate_provider_adapter_evidence.py"
SPEC = importlib.util.spec_from_file_location("evaluate_provider_adapter_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProviderAdapterEvidenceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.paths: dict[str, Path] = {}
        self.digests: dict[str, str] = {}
        for name, payload in (
            ("candidate", b"candidate-artifact-0.57.0\n"),
            ("adapter", b"provider-adapter-1.0.0\n"),
            ("transcript", b"start=accepted\ncancel=validated\nambiguous=blocked\n"),
        ):
            path = self.root / f"{name}.bin"
            path.write_bytes(payload)
            self.paths[name] = path
            self.digests[name] = hashlib.sha256(payload).hexdigest()

        self.environment_evidence_sha256 = "d" * 64
        self.environment_decision = self.root / "real-environment-decision.json"
        self.environment_decision.write_text(
            json.dumps(
                {
                    "schema": "home-center.real-environment-qualification.v1",
                    "version": "0.57.0",
                    "revision": "7" * 40,
                    "candidate_artifact_sha256": self.digests["candidate"],
                    "evidence_sha256": self.environment_evidence_sha256,
                    "qualified": True,
                    "blockers": [],
                    "release_authorized": False,
                    "external_publication_authorized": False,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _manifest(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "home-center.provider-adapter-evidence.v1",
            "version": "0.57.0",
            "revision": "7" * 40,
            "adapter_id": "android-mdm-primary",
            "adapter_version": "1.0.0",
            "candidate_artifact_sha256": self.digests["candidate"],
            "adapter_artifact_sha256": self.digests["adapter"],
            "execution_transcript_sha256": self.digests["transcript"],
            "environment_evidence_sha256": self.environment_evidence_sha256,
            "real_provider_exercised": True,
            "real_target_exercised": True,
            "start_contract_validated": True,
            "cancel_contract_validated": True,
            "secret_reference_only": True,
            "secret_values_absent_from_evidence": True,
            "retry_safe_only_when_proven": True,
            "ambiguous_outcome_fail_closed": True,
            "post_condition_separate": True,
            "managed_state_change_forbidden": True,
        }
        value.update(overrides)
        return value

    def _qualify(self, value: dict[str, object]):
        return MODULE.qualify_manifest(
            value,
            candidate_artifact=self.paths["candidate"],
            adapter_artifact=self.paths["adapter"],
            execution_transcript=self.paths["transcript"],
            environment_decision=self.environment_decision,
        )

    def test_exact_artifact_and_environment_bindings_qualify_without_authority(self) -> None:
        decision = self._qualify(self._manifest())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertRegex(decision.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(decision.evidence_sha256, "0" * 64)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_adapter_artifact_digest_mismatch_fails_before_qualification(self) -> None:
        with self.assertRaisesRegex(
            MODULE.ProviderAdapterEvidenceInputError,
            "adapter_artifact_digest_mismatch",
        ):
            self._qualify(self._manifest(adapter_artifact_sha256="e" * 64))

    def test_environment_must_match_exact_candidate_identity(self) -> None:
        environment = json.loads(self.environment_decision.read_text(encoding="utf-8"))
        environment["revision"] = "8" * 40
        self.environment_decision.write_text(json.dumps(environment), encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ProviderAdapterEvidenceInputError,
            "environment_revision_binding",
        ):
            self._qualify(self._manifest())

    def test_environment_must_be_qualified_and_authority_free(self) -> None:
        environment = json.loads(self.environment_decision.read_text(encoding="utf-8"))
        environment["qualified"] = False
        environment["blockers"] = ["peer_continuity"]
        self.environment_decision.write_text(json.dumps(environment), encoding="utf-8")
        with self.assertRaisesRegex(
            MODULE.ProviderAdapterEvidenceInputError,
            "environment_not_qualified",
        ):
            self._qualify(self._manifest())

    def test_false_provider_safety_property_remains_blocked(self) -> None:
        decision = self._qualify(self._manifest(ambiguous_outcome_fail_closed=False))
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.blockers, ("ambiguous_outcome_fail_closed",))
        self.assertEqual(decision.evidence_sha256, "0" * 64)

    def test_unknown_manifest_field_is_rejected_fail_closed(self) -> None:
        value = self._manifest()
        value["operator_override"] = True
        with self.assertRaisesRegex(MODULE.ProviderAdapterEvidenceInputError, "input_shape"):
            self._qualify(value)

    def test_manifest_and_decision_match_closed_contracts(self) -> None:
        manifest = self._manifest()
        evidence_schema = json.loads(
            (ROOT / "contracts/releases/provider-adapter-evidence.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        decision_schema = json.loads(
            (ROOT / "contracts/releases/provider-adapter-qualification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(evidence_schema).validate(manifest)
        jsonschema.Draft202012Validator(decision_schema).validate(
            self._qualify(manifest).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
