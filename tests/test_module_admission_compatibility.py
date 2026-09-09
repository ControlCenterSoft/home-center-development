from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from home_center.module_admission import (
    ModuleAdmissionError,
    evaluate_module_compatibility,
)
from home_center.module_artifact import VerifiedModuleArtifact, manifest_binding_sha256


def _manifest() -> dict[str, object]:
    return {
        "schema": "home-center.module-manifest.v2",
        "module": {
            "id": "example.media",
            "version": "1.2.0",
            "name": "Example Media",
            "publisher": "example",
        },
        "compatibility": {
            "home_center": {
                "minimum": "0.28.0",
                "maximum_exclusive": "0.30.0",
            },
            "architectures": ["x86-64", "aarch64"],
            "operating_systems": ["linux"],
        },
        "dependencies": [
            {
                "id": "base.media",
                "minimum_version": "2.0.0",
                "maximum_version_exclusive": "3.0.0",
                "optional": False,
            },
            {
                "id": "optional.metrics",
                "minimum_version": "1.0.0",
                "maximum_version_exclusive": "2.0.0",
                "optional": True,
            },
        ],
        "conflicts": ["legacy.media"],
        "capabilities": ["network.lan", "storage.local"],
        "permissions": ["module.manage"],
        "actions": [
            {
                "id": "install",
                "permission": "module.manage",
                "risk": "mutation",
                "timeout_seconds": 300,
                "idempotent": True,
            },
            {
                "id": "install.rollback",
                "permission": "module.manage",
                "risk": "mutation",
                "timeout_seconds": 300,
                "idempotent": True,
            },
            {
                "id": "upgrade",
                "permission": "module.manage",
                "risk": "mutation",
                "timeout_seconds": 300,
                "idempotent": True,
            },
            {
                "id": "upgrade.rollback",
                "permission": "module.manage",
                "risk": "mutation",
                "timeout_seconds": 300,
                "idempotent": True,
            },
            {
                "id": "remove",
                "permission": "module.manage",
                "risk": "mutation",
                "timeout_seconds": 300,
                "idempotent": True,
            },
        ],
        "network": {"inbound": [], "outbound": []},
        "storage": [],
        "health": [
            {
                "id": "service.ready",
                "kind": "readiness",
                "interval_seconds": 30,
                "timeout_seconds": 5,
            }
        ],
        "backup": {
            "mode": "not-required",
            "data_ids": [],
            "restore_required": False,
        },
        "lifecycle": {
            "install": {
                "action": "install",
                "rollback_action": "install.rollback",
            },
            "upgrade": {
                "action": "upgrade",
                "rollback_action": "upgrade.rollback",
            },
            "remove": {"action": "remove", "data_policy": "preserve"},
        },
        "artifact": {
            "sha256": "a" * 64,
            "size_bytes": 123,
            "media_type": "application/vnd.home-center.module.v1+tar+gzip",
            "provenance": {
                "statement_sha256": "b" * 64,
                "signer_key_ids": ["sha256:" + "c" * 64],
                "threshold": 1,
            },
        },
    }


def _verified(manifest: dict[str, object]) -> VerifiedModuleArtifact:
    artifact = manifest["artifact"]
    module = manifest["module"]
    assert isinstance(artifact, dict)
    assert isinstance(module, dict)
    digest = artifact["sha256"]
    assert isinstance(digest, str)
    return VerifiedModuleArtifact(
        module_id=str(module["id"]),
        version=str(module["version"]),
        publisher=str(module["publisher"]),
        manifest_binding_sha256=manifest_binding_sha256(manifest),
        statement_sha256="b" * 64,
        artifact_sha256=digest,
        artifact_size_bytes=123,
        signing_key_ids=("sha256:" + "c" * 64,),
        object_key=f"sha256/{digest[:2]}/{digest}/artifact.tar.gz",
    )


def _evaluate(
    manifest: dict[str, object],
    **overrides: object,
):
    runtime: dict[str, object] = {
        "home_center_version": "0.29.0",
        "architecture": "x86-64",
        "operating_system": "linux",
        "available_capabilities": ["storage.local", "network.lan"],
        "installed_modules": {"base.media": "2.4.0"},
    }
    runtime.update(overrides)
    return evaluate_module_compatibility(
        manifest,
        _verified(manifest),
        home_center_version=runtime["home_center_version"],  # type: ignore[arg-type]
        architecture=runtime["architecture"],  # type: ignore[arg-type]
        operating_system=runtime["operating_system"],  # type: ignore[arg-type]
        available_capabilities=runtime["available_capabilities"],  # type: ignore[arg-type]
        installed_modules=runtime["installed_modules"],  # type: ignore[arg-type]
    )


class ModuleCompatibilityAdmissionTests(unittest.TestCase):
    def test_compatible_candidate_is_evidence_only(self) -> None:
        decision = _evaluate(_manifest())
        self.assertTrue(decision.compatible)
        self.assertEqual(decision.status, "compatible")
        self.assertEqual(decision.reasons, ())
        self.assertEqual(decision.missing_capabilities, ())
        self.assertEqual(decision.unsatisfied_dependencies, ())
        self.assertEqual(decision.active_conflicts, ())
        self.assertFalse(decision.installation_authorized)
        self.assertFalse(decision.execution_authorized)
        self.assertFalse(decision.production_mutation_enabled)
        self.assertFalse(decision.external_publication_authorized)
        self.assertEqual(decision.provenance_statement_sha256, "b" * 64)
        self.assertEqual(
            decision.verified_signing_key_ids,
            ("sha256:" + "c" * 64,),
        )

    def test_decision_is_deterministic_for_runtime_input_order(self) -> None:
        manifest = _manifest()
        first = _evaluate(
            manifest,
            available_capabilities=["storage.local", "network.lan"],
            installed_modules={"base.media": "2.4.0", "unrelated.tool": "1.0.0"},
        )
        second = _evaluate(
            manifest,
            available_capabilities=["network.lan", "storage.local"],
            installed_modules={"unrelated.tool": "1.0.0", "base.media": "2.4.0"},
        )
        self.assertEqual(first.decision_id, second.decision_id)
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_decision_id_is_reproducible_from_serialized_evidence(self) -> None:
        decision = _evaluate(_manifest())
        payload = decision.to_dict()
        decision_id = payload.pop("decision_id")
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        self.assertEqual(
            decision_id,
            "madm-" + hashlib.sha256(encoded).hexdigest()[:24],
        )

    def test_version_and_platform_mismatch_block_fail_closed(self) -> None:
        decision = _evaluate(
            _manifest(),
            home_center_version="0.30.0",
            architecture="riscv64",
            operating_system="freebsd",
        )
        self.assertFalse(decision.compatible)
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(
            set(decision.reasons),
            {
                "architecture_unsupported",
                "home_center_version_unsupported",
                "operating_system_unsupported",
            },
        )

    def test_missing_capability_and_required_dependency_block(self) -> None:
        decision = _evaluate(
            _manifest(),
            available_capabilities=["network.lan"],
            installed_modules={},
        )
        self.assertEqual(
            decision.reasons,
            ("capability_missing", "dependency_unsatisfied"),
        )
        self.assertEqual(decision.missing_capabilities, ("storage.local",))
        self.assertEqual(decision.unsatisfied_dependencies, ("base.media",))

    def test_present_optional_dependency_must_still_be_compatible(self) -> None:
        decision = _evaluate(
            _manifest(),
            installed_modules={
                "base.media": "2.4.0",
                "optional.metrics": "2.0.0",
            },
        )
        self.assertEqual(decision.reasons, ("dependency_unsatisfied",))
        self.assertEqual(
            decision.unsatisfied_dependencies,
            ("optional.metrics",),
        )

    def test_declared_conflict_blocks(self) -> None:
        decision = _evaluate(
            _manifest(),
            installed_modules={
                "base.media": "2.4.0",
                "legacy.media": "1.0.0",
            },
        )
        self.assertEqual(decision.reasons, ("conflict_present",))
        self.assertEqual(decision.active_conflicts, ("legacy.media",))

    def test_verified_artifact_mismatch_is_rejected_not_downgraded_to_block(self) -> None:
        manifest = _manifest()
        verified = _verified(manifest)
        forged = VerifiedModuleArtifact(
            module_id=verified.module_id,
            version=verified.version,
            publisher=verified.publisher,
            manifest_binding_sha256=verified.manifest_binding_sha256,
            statement_sha256=verified.statement_sha256,
            artifact_sha256="d" * 64,
            artifact_size_bytes=verified.artifact_size_bytes,
            signing_key_ids=verified.signing_key_ids,
            object_key=verified.object_key,
        )
        with self.assertRaisesRegex(
            ModuleAdmissionError,
            "verified_artifact_mismatch",
        ):
            evaluate_module_compatibility(
                manifest,
                forged,
                home_center_version="0.29.0",
                architecture="x86-64",
                operating_system="linux",
                available_capabilities=["network.lan", "storage.local"],
                installed_modules={"base.media": "2.4.0"},
            )

    def test_provenance_statement_mismatch_is_rejected(self) -> None:
        manifest = _manifest()
        verified = _verified(manifest)
        forged = VerifiedModuleArtifact(
            module_id=verified.module_id,
            version=verified.version,
            publisher=verified.publisher,
            manifest_binding_sha256=verified.manifest_binding_sha256,
            statement_sha256="d" * 64,
            artifact_sha256=verified.artifact_sha256,
            artifact_size_bytes=verified.artifact_size_bytes,
            signing_key_ids=verified.signing_key_ids,
            object_key=verified.object_key,
        )
        with self.assertRaisesRegex(
            ModuleAdmissionError,
            "verified_artifact_mismatch",
        ):
            evaluate_module_compatibility(
                manifest,
                forged,
                home_center_version="0.29.0",
                architecture="x86-64",
                operating_system="linux",
                available_capabilities=["network.lan", "storage.local"],
                installed_modules={"base.media": "2.4.0"},
            )

    def test_duplicate_runtime_capability_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            ModuleAdmissionError,
            "runtime_capability_duplicate",
        ):
            _evaluate(
                _manifest(),
                available_capabilities=["network.lan", "network.lan", "storage.local"],
            )

    def test_contract_schema_is_closed_and_non_authorizing(self) -> None:
        path = Path("contracts/modules/module-admission-decision.v1.schema.json")
        schema = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["installation_authorized"]["const"],
            False,
        )
        self.assertEqual(
            schema["properties"]["execution_authorized"]["const"],
            False,
        )
        self.assertEqual(
            schema["properties"]["production_mutation_enabled"]["const"],
            False,
        )
        self.assertEqual(
            schema["properties"]["external_publication_authorized"]["const"],
            False,
        )


if __name__ == "__main__":
    unittest.main()
