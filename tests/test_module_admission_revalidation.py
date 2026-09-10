from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_admission import evaluate_module_compatibility
from home_center.module_admission_revalidation import (
    ModuleAdmissionRevalidationError,
    revalidate_module_compatibility_decision,
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
                "maximum_exclusive": "0.31.0",
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
            }
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


def _decision(manifest: dict[str, object]):
    return evaluate_module_compatibility(
        manifest,
        _verified(manifest),
        home_center_version="0.29.0",
        architecture="x86-64",
        operating_system="linux",
        available_capabilities=["storage.local", "network.lan"],
        installed_modules={"base.media": "2.4.0"},
    )


def _revalidate(
    manifest: dict[str, object],
    original,
    **overrides: object,
):
    runtime: dict[str, object] = {
        "home_center_version": "0.29.0",
        "architecture": "x86-64",
        "operating_system": "linux",
        "available_capabilities": ["network.lan", "storage.local"],
        "installed_modules": {"base.media": "2.4.0"},
    }
    runtime.update(overrides)
    return revalidate_module_compatibility_decision(
        manifest,
        _verified(manifest),
        original,
        home_center_version=runtime["home_center_version"],  # type: ignore[arg-type]
        architecture=runtime["architecture"],  # type: ignore[arg-type]
        operating_system=runtime["operating_system"],  # type: ignore[arg-type]
        available_capabilities=runtime["available_capabilities"],  # type: ignore[arg-type]
        installed_modules=runtime["installed_modules"],  # type: ignore[arg-type]
    )


class ModuleAdmissionRevalidationTests(unittest.TestCase):
    def test_exact_snapshot_remains_current_and_non_authorizing(self) -> None:
        manifest = _manifest()
        original = _decision(manifest)
        result = _revalidate(manifest, original)

        self.assertTrue(result.current)
        self.assertEqual(result.status, "current")
        self.assertEqual(result.original_decision_id, original.decision_id)
        self.assertEqual(result.fresh_decision_id, original.decision_id)
        self.assertEqual(result.drift_reasons, ())
        self.assertFalse(result.installation_authorized)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.production_mutation_enabled)
        self.assertFalse(result.external_publication_authorized)

    def test_input_order_does_not_create_false_drift(self) -> None:
        manifest = _manifest()
        original = _decision(manifest)
        result = _revalidate(
            manifest,
            original,
            available_capabilities=["storage.local", "network.lan"],
            installed_modules={"base.media": "2.4.0"},
        )
        self.assertTrue(result.current)
        self.assertEqual(result.drift_reasons, ())

    def test_irrelevant_capability_change_stales_exact_decision(self) -> None:
        manifest = _manifest()
        original = _decision(manifest)
        result = _revalidate(
            manifest,
            original,
            available_capabilities=[
                "network.lan",
                "storage.local",
                "metrics.read",
            ],
        )
        self.assertEqual(result.status, "stale")
        self.assertEqual(result.drift_reasons, ("capability_set_changed",))
        self.assertEqual(result.fresh_compatibility_status, "compatible")

    def test_home_center_version_change_stales_even_if_still_compatible(self) -> None:
        manifest = _manifest()
        original = _decision(manifest)
        result = _revalidate(
            manifest,
            original,
            home_center_version="0.30.0",
        )
        self.assertEqual(result.status, "stale")
        self.assertEqual(
            result.drift_reasons,
            ("home_center_version_changed",),
        )
        self.assertEqual(result.fresh_compatibility_status, "compatible")

    def test_dependency_change_can_turn_compatible_decision_into_block(self) -> None:
        manifest = _manifest()
        original = _decision(manifest)
        result = _revalidate(
            manifest,
            original,
            installed_modules={"base.media": "3.0.0"},
        )
        self.assertEqual(result.status, "stale")
        self.assertEqual(result.fresh_compatibility_status, "blocked")
        self.assertEqual(result.fresh_reasons, ("dependency_unsatisfied",))
        self.assertEqual(
            set(result.drift_reasons),
            {
                "compatibility_reasons_changed",
                "compatibility_status_changed",
                "installed_module_set_changed",
            },
        )

    def test_tampered_original_decision_is_rejected(self) -> None:
        manifest = _manifest()
        original = _decision(manifest)
        forged = replace(
            original,
            available_capabilities=("network.lan",),
        )
        with self.assertRaisesRegex(
            ModuleAdmissionRevalidationError,
            "original_decision_evidence_rejected",
        ):
            _revalidate(manifest, forged)

    def test_authority_flag_tampering_is_rejected(self) -> None:
        manifest = _manifest()
        original = _decision(manifest)
        forged = replace(original, installation_authorized=True)
        with self.assertRaisesRegex(
            ModuleAdmissionRevalidationError,
            "original_decision_evidence_rejected",
        ):
            _revalidate(manifest, forged)

    def test_invalid_fresh_runtime_evidence_is_rejected(self) -> None:
        manifest = _manifest()
        original = _decision(manifest)
        with self.assertRaisesRegex(
            ModuleAdmissionRevalidationError,
            "fresh_runtime_evidence_rejected",
        ):
            _revalidate(
                manifest,
                original,
                available_capabilities=[
                    "network.lan",
                    "network.lan",
                    "storage.local",
                ],
            )

    def test_revalidation_id_is_reproducible_from_serialized_evidence(self) -> None:
        manifest = _manifest()
        result = _revalidate(
            manifest,
            _decision(manifest),
            home_center_version="0.30.0",
        )
        payload = result.to_dict()
        revalidation_id = payload.pop("revalidation_id")
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        self.assertEqual(
            revalidation_id,
            "madr-" + hashlib.sha256(encoded).hexdigest()[:24],
        )

    def test_contract_schema_is_closed_and_non_authorizing(self) -> None:
        path = Path(
            "contracts/modules/module-admission-revalidation.v1.schema.json"
        )
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
