from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_artifact import VerifiedModuleArtifact, manifest_binding_sha256
from home_center.module_candidate_set import (
    ModuleCandidateSetError,
    evaluate_module_candidate_set,
)
from home_center.module_compatibility_snapshot import build_module_compatibility_snapshot


def _manifest(
    module_id: str,
    version: str,
    *,
    digest: str,
    dependencies: list[dict[str, object]] | None = None,
    conflicts: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema": "home-center.module-manifest.v2",
        "module": {
            "id": module_id,
            "version": version,
            "name": module_id,
            "publisher": "example",
        },
        "compatibility": {
            "home_center": {
                "minimum": "0.29.0",
                "maximum_exclusive": "1.0.0",
            },
            "architectures": ["x86-64"],
            "operating_systems": ["linux"],
        },
        "dependencies": dependencies or [],
        "conflicts": conflicts or [],
        "capabilities": ["network.lan"],
        "permissions": ["module.manage"],
        "actions": [
            {"id": "install", "permission": "module.manage", "risk": "mutation", "timeout_seconds": 300, "idempotent": True},
            {"id": "install.rollback", "permission": "module.manage", "risk": "mutation", "timeout_seconds": 300, "idempotent": True},
            {"id": "upgrade", "permission": "module.manage", "risk": "mutation", "timeout_seconds": 300, "idempotent": True},
            {"id": "upgrade.rollback", "permission": "module.manage", "risk": "mutation", "timeout_seconds": 300, "idempotent": True},
            {"id": "remove", "permission": "module.manage", "risk": "mutation", "timeout_seconds": 300, "idempotent": True},
        ],
        "network": {"inbound": [], "outbound": []},
        "storage": [],
        "health": [{"id": "service.ready", "kind": "readiness", "interval_seconds": 30, "timeout_seconds": 5}],
        "backup": {"mode": "not-required", "data_ids": [], "restore_required": False},
        "lifecycle": {
            "install": {"action": "install", "rollback_action": "install.rollback"},
            "upgrade": {"action": "upgrade", "rollback_action": "upgrade.rollback"},
            "remove": {"action": "remove", "data_policy": "preserve"},
        },
        "artifact": {
            "sha256": digest * 64,
            "size_bytes": 123,
            "media_type": "application/vnd.home-center.module.v1+tar+gzip",
            "provenance": {
                "statement_sha256": "e" * 64,
                "signer_key_ids": ["sha256:" + "f" * 64],
                "threshold": 1,
            },
        },
    }


def _verified(manifest: dict[str, object]) -> VerifiedModuleArtifact:
    artifact = manifest["artifact"]
    module = manifest["module"]
    assert isinstance(artifact, dict)
    assert isinstance(module, dict)
    digest = str(artifact["sha256"])
    return VerifiedModuleArtifact(
        module_id=str(module["id"]),
        version=str(module["version"]),
        publisher=str(module["publisher"]),
        manifest_binding_sha256=manifest_binding_sha256(manifest),
        statement_sha256="e" * 64,
        artifact_sha256=digest,
        artifact_size_bytes=123,
        signing_key_ids=("sha256:" + "f" * 64,),
        object_key=f"sha256/{digest[:2]}/{digest}/artifact.tar.gz",
    )


def _snapshot():
    return build_module_compatibility_snapshot(
        home_center_version="0.33.0",
        architecture="x86-64",
        operating_system="linux",
        available_capabilities=["network.lan"],
        installed_modules={},
    )


def _dependency(module_id: str, minimum: str = "1.0.0", maximum: str = "3.0.0") -> dict[str, object]:
    return {"id": module_id, "minimum_version": minimum, "maximum_version_exclusive": maximum, "optional": False}


class ModuleCandidateSetTests(unittest.TestCase):
    def test_candidate_dependency_can_be_satisfied_inside_same_set(self) -> None:
        base = _manifest("base.media", "2.4.0", digest="a")
        app = _manifest("example.media", "1.2.0", digest="b", dependencies=[_dependency("base.media", "2.0.0", "3.0.0")])
        decision = evaluate_module_candidate_set(_snapshot(), [(app, _verified(app)), (base, _verified(base))])
        self.assertTrue(decision.compatible)
        self.assertEqual(decision.planned_modules, (("base.media", "2.4.0"), ("example.media", "1.2.0")))
        self.assertEqual(decision.blocked_modules, ())
        self.assertFalse(decision.installation_authorized)
        self.assertFalse(decision.execution_authorized)

    def test_candidate_conflict_blocks_set(self) -> None:
        base = _manifest("base.media", "2.4.0", digest="a", conflicts=["example.media"])
        app = _manifest("example.media", "1.2.0", digest="b")
        decision = evaluate_module_candidate_set(_snapshot(), [(base, _verified(base)), (app, _verified(app))])
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.blocked_modules, ("base.media",))
        self.assertIn("conflict_present", decision.candidates[0][-1])

    def test_candidate_dependency_version_mismatch_blocks_depender(self) -> None:
        base = _manifest("base.media", "2.4.0", digest="a")
        app = _manifest("example.media", "1.2.0", digest="b", dependencies=[_dependency("base.media", "3.0.0", "4.0.0")])
        decision = evaluate_module_candidate_set(_snapshot(), [(base, _verified(base)), (app, _verified(app))])
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.blocked_modules, ("example.media",))
        self.assertIn("dependency_unsatisfied", decision.candidates[1][-1])

    def test_candidate_overlays_installed_version_for_cross_compatibility(self) -> None:
        snapshot = build_module_compatibility_snapshot(home_center_version="0.33.0", architecture="x86-64", operating_system="linux", available_capabilities=["network.lan"], installed_modules={"base.media": "1.5.0"})
        base = _manifest("base.media", "2.4.0", digest="a")
        app = _manifest("example.media", "1.2.0", digest="b", dependencies=[_dependency("base.media", "2.0.0", "3.0.0")])
        decision = evaluate_module_candidate_set(snapshot, [(base, _verified(base)), (app, _verified(app))])
        self.assertTrue(decision.compatible)
        self.assertIn(("base.media", "2.4.0"), decision.planned_modules)
        self.assertNotIn(("base.media", "1.5.0"), decision.planned_modules)

    def test_candidate_order_does_not_change_identity(self) -> None:
        base = _manifest("base.media", "2.4.0", digest="a")
        app = _manifest("example.media", "1.2.0", digest="b")
        first = evaluate_module_candidate_set(_snapshot(), [(base, _verified(base)), (app, _verified(app))])
        second = evaluate_module_candidate_set(_snapshot(), [(app, _verified(app)), (base, _verified(base))])
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.candidate_set_id, second.candidate_set_id)

    def test_duplicate_candidate_module_is_rejected(self) -> None:
        first = _manifest("base.media", "2.4.0", digest="a")
        second = _manifest("base.media", "2.5.0", digest="b")
        with self.assertRaisesRegex(ModuleCandidateSetError, "candidate_module_duplicate"):
            evaluate_module_candidate_set(_snapshot(), [(first, _verified(first)), (second, _verified(second))])

    def test_tampered_snapshot_is_rejected(self) -> None:
        snapshot = replace(_snapshot(), snapshot_id="mcs-" + "0" * 24)
        candidate = _manifest("base.media", "2.4.0", digest="a")
        with self.assertRaisesRegex(ModuleCandidateSetError, "compatibility_snapshot_rejected"):
            evaluate_module_candidate_set(snapshot, [(candidate, _verified(candidate))])

    def test_contract_schema_is_closed_and_non_authorizing(self) -> None:
        schema = json.loads(Path("contracts/modules/module-candidate-set-decision.v1.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        for field in ("installation_authorized", "execution_authorized", "production_mutation_enabled", "external_publication_authorized"):
            self.assertEqual(schema["properties"][field]["const"], False)


if __name__ == "__main__":
    unittest.main()
