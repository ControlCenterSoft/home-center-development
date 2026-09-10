from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_admission import evaluate_module_compatibility
from home_center.module_admission_set_revalidation import (
    ModuleAdmissionSetMember,
    ModuleAdmissionSetRevalidationError,
    revalidate_module_admission_set,
)
from home_center.module_artifact import VerifiedModuleArtifact, manifest_binding_sha256
from home_center.module_compatibility_snapshot import (
    bind_module_admission_decisions_to_snapshot,
    build_module_compatibility_snapshot,
)


def _manifest(module_id: str, *, requires_base: bool = True) -> dict[str, object]:
    dependencies = []
    capabilities = ["network.lan", "storage.local"]
    if requires_base:
        dependencies = [{
            "id": "base.media",
            "minimum_version": "2.0.0",
            "maximum_version_exclusive": "3.0.0",
            "optional": False,
        }]
    else:
        capabilities = ["network.lan"]
    return {
        "schema": "home-center.module-manifest.v2",
        "module": {
            "id": module_id,
            "version": "1.2.0",
            "name": "Example Module",
            "publisher": "example",
        },
        "compatibility": {
            "home_center": {"minimum": "0.29.0", "maximum_exclusive": "0.40.0"},
            "architectures": ["x86-64", "aarch64"],
            "operating_systems": ["linux"],
        },
        "dependencies": dependencies,
        "conflicts": ["legacy.media"],
        "capabilities": capabilities,
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
    module = manifest["module"]
    artifact = manifest["artifact"]
    assert isinstance(module, dict)
    assert isinstance(artifact, dict)
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


def _snapshot(*, home_center_version: str = "0.31.0", capabilities: tuple[str, ...] = ("network.lan", "storage.local"), installed_modules: dict[str, str] | None = None):
    return build_module_compatibility_snapshot(
        home_center_version=home_center_version,
        architecture="x86-64",
        operating_system="linux",
        available_capabilities=capabilities,
        installed_modules=installed_modules or {"base.media": "2.4.0"},
    )


def _member(module_id: str, *, requires_base: bool = True) -> ModuleAdmissionSetMember:
    manifest = _manifest(module_id, requires_base=requires_base)
    verified = _verified(manifest)
    decision = evaluate_module_compatibility(
        manifest,
        verified,
        home_center_version="0.31.0",
        architecture="x86-64",
        operating_system="linux",
        available_capabilities=["network.lan", "storage.local"],
        installed_modules={"base.media": "2.4.0"},
    )
    return ModuleAdmissionSetMember(manifest=manifest, verified=verified, decision=decision)


def _binding(members: list[ModuleAdmissionSetMember]):
    snapshot = _snapshot()
    return snapshot, bind_module_admission_decisions_to_snapshot(
        snapshot, [member.decision for member in members]
    )


class ModuleAdmissionSetRevalidationTests(unittest.TestCase):
    def test_exact_set_remains_current_and_non_authorizing(self) -> None:
        members = [_member("example.media"), _member("example.backup", requires_base=False)]
        snapshot, binding = _binding(members)
        result = revalidate_module_admission_set(snapshot, binding, members, snapshot)
        self.assertTrue(result.current)
        self.assertEqual(result.stale_module_ids, ())
        self.assertEqual(result.snapshot_drift_reasons, ())
        self.assertFalse(result.installation_authorized)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.production_mutation_enabled)
        self.assertFalse(result.external_publication_authorized)

    def test_member_order_is_deterministic(self) -> None:
        members = [_member("example.media"), _member("example.backup", requires_base=False)]
        snapshot, binding = _binding(members)
        left = revalidate_module_admission_set(snapshot, binding, members, snapshot)
        right = revalidate_module_admission_set(snapshot, binding, list(reversed(members)), snapshot)
        self.assertEqual(left, right)

    def test_runtime_version_change_stales_entire_set(self) -> None:
        members = [_member("example.media"), _member("example.backup", requires_base=False)]
        snapshot, binding = _binding(members)
        result = revalidate_module_admission_set(snapshot, binding, members, _snapshot(home_center_version="0.32.0"))
        self.assertEqual(result.status, "stale")
        self.assertEqual(result.snapshot_drift_reasons, ("home_center_version_changed",))
        self.assertEqual(result.stale_module_ids, ("example.backup", "example.media"))

    def test_dependency_drift_blocks_affected_member_and_stales_set(self) -> None:
        members = [_member("example.media"), _member("example.backup", requires_base=False)]
        snapshot, binding = _binding(members)
        fresh = _snapshot(installed_modules={"base.media": "3.0.0"})
        result = revalidate_module_admission_set(snapshot, binding, members, fresh)
        self.assertEqual(result.status, "stale")
        by_module = {entry[0]: entry for entry in result.members}
        self.assertEqual(by_module["example.media"][5], "blocked")
        self.assertEqual(by_module["example.backup"][5], "compatible")

    def test_capability_drift_stales_even_if_member_stays_compatible(self) -> None:
        members = [_member("example.backup", requires_base=False)]
        snapshot, binding = _binding(members)
        fresh = _snapshot(capabilities=("metrics.read", "network.lan", "storage.local"))
        result = revalidate_module_admission_set(snapshot, binding, members, fresh)
        self.assertEqual(result.snapshot_drift_reasons, ("capability_set_changed",))
        self.assertEqual(result.members[0][5], "compatible")
        self.assertEqual(result.members[0][4], "stale")

    def test_incomplete_member_set_is_rejected(self) -> None:
        members = [_member("example.media"), _member("example.backup", requires_base=False)]
        snapshot, binding = _binding(members)
        with self.assertRaisesRegex(ModuleAdmissionSetRevalidationError, "original_binding_evidence_rejected"):
            revalidate_module_admission_set(snapshot, binding, members[:1], snapshot)

    def test_tampered_binding_and_snapshot_are_rejected(self) -> None:
        members = [_member("example.media")]
        snapshot, binding = _binding(members)
        forged_binding = replace(binding, binding_id="masb-" + "0" * 24)
        with self.assertRaisesRegex(ModuleAdmissionSetRevalidationError, "original_binding_evidence_rejected"):
            revalidate_module_admission_set(snapshot, forged_binding, members, snapshot)
        forged_snapshot = replace(snapshot, snapshot_id="mcs-" + "0" * 24)
        with self.assertRaisesRegex(ModuleAdmissionSetRevalidationError, "fresh_snapshot_evidence_rejected"):
            revalidate_module_admission_set(snapshot, binding, members, forged_snapshot)

    def test_revalidation_id_is_reproducible(self) -> None:
        members = [_member("example.media")]
        snapshot, binding = _binding(members)
        result = revalidate_module_admission_set(snapshot, binding, members, _snapshot(home_center_version="0.32.0"))
        payload = result.to_dict()
        revalidation_id = payload.pop("revalidation_id")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        self.assertEqual(revalidation_id, "masr-" + hashlib.sha256(encoded).hexdigest()[:24])

    def test_contract_schema_is_closed_and_non_authorizing(self) -> None:
        schema = json.loads(Path("contracts/modules/module-admission-set-revalidation.v1.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        for field in ("installation_authorized", "execution_authorized", "production_mutation_enabled", "external_publication_authorized"):
            self.assertEqual(schema["properties"][field]["const"], False)


if __name__ == "__main__":
    unittest.main()
