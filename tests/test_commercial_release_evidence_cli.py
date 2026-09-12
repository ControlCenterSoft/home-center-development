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

SCRIPT = ROOT / "scripts/evaluate_commercial_release_evidence.py"
SPEC = importlib.util.spec_from_file_location("evaluate_commercial_release_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CommercialReleaseEvidenceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.paths: dict[str, Path] = {}
        self.digests: dict[str, str] = {}
        names = (
            "candidate",
            "dependencies",
            "redistribution",
            "notices",
            "source_obligations",
            "sbom",
            "legal_terms",
            "support_terms",
            "release_claims",
        )
        for index, name in enumerate(names, start=1):
            payload = f"{name}-evidence-{index}\n".encode("utf-8")
            path = self.root / f"{name}.txt"
            path.write_bytes(payload)
            self.paths[name] = path
            self.digests[name] = hashlib.sha256(payload).hexdigest()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _manifest(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "home-center.commercial-release-evidence.v1",
            "version": "0.57.0",
            "revision": "7" * 40,
            "candidate_artifact_sha256": self.digests["candidate"],
            "dependencies_evidence_sha256": self.digests["dependencies"],
            "redistribution_evidence_sha256": self.digests["redistribution"],
            "notices_sha256": self.digests["notices"],
            "source_obligations_evidence_sha256": self.digests["source_obligations"],
            "sbom_sha256": self.digests["sbom"],
            "legal_terms_sha256": self.digests["legal_terms"],
            "support_terms_sha256": self.digests["support_terms"],
            "release_claims_sha256": self.digests["release_claims"],
            "disposition": "approved",
            "dependencies_reviewed": True,
            "redistribution_reviewed": True,
            "notices_prepared": True,
            "source_obligations_resolved": True,
            "sbom_reviewed": True,
            "legal_terms_dispositioned": True,
            "release_claims_reviewed": True,
        }
        value.update(overrides)
        return value

    def _qualify(self, value: dict[str, object]):
        return MODULE.qualify_manifest(
            value,
            candidate_artifact=self.paths["candidate"],
            dependencies_evidence=self.paths["dependencies"],
            redistribution_evidence=self.paths["redistribution"],
            notices=self.paths["notices"],
            source_obligations_evidence=self.paths["source_obligations"],
            sbom=self.paths["sbom"],
            legal_terms=self.paths["legal_terms"],
            support_terms=self.paths["support_terms"],
            release_claims=self.paths["release_claims"],
        )

    def test_exact_file_bindings_qualify_without_publication_authority(self) -> None:
        decision = self._qualify(self._manifest())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.blockers, ())
        self.assertRegex(decision.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(decision.evidence_sha256, "0" * 64)
        self.assertFalse(decision.release_authorized)
        self.assertFalse(decision.external_publication_authorized)

    def test_candidate_artifact_mismatch_fails_before_review_decision(self) -> None:
        with self.assertRaisesRegex(
            MODULE.CommercialEvidenceInputError,
            "candidate_artifact_digest_mismatch",
        ):
            self._qualify(self._manifest(candidate_artifact_sha256="f" * 64))

    def test_legal_terms_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            MODULE.CommercialEvidenceInputError,
            "legal_terms_digest_mismatch",
        ):
            self._qualify(self._manifest(legal_terms_sha256="e" * 64))

    def test_review_required_remains_blocked_after_exact_file_binding(self) -> None:
        decision = self._qualify(self._manifest(disposition="review-required"))
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.blockers, ("commercial_disposition",))
        self.assertEqual(decision.evidence_sha256, "0" * 64)

    def test_unknown_field_is_rejected(self) -> None:
        value = self._manifest()
        value["implicit_approval"] = True
        with self.assertRaisesRegex(MODULE.CommercialEvidenceInputError, "input_shape"):
            self._qualify(value)

    def test_manifest_and_decision_match_closed_contracts(self) -> None:
        manifest = self._manifest()
        evidence_schema = json.loads(
            (ROOT / "contracts/releases/commercial-release-evidence.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        decision_schema = json.loads(
            (ROOT / "contracts/releases/commercial-release-qualification.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(evidence_schema).validate(manifest)
        jsonschema.Draft202012Validator(decision_schema).validate(
            self._qualify(manifest).to_dict()
        )


if __name__ == "__main__":
    unittest.main()
