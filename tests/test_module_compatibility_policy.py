from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_artifact import (
    VerifiedModuleArtifact,
    manifest_binding_sha256,
)
from home_center.module_compatibility_policy import (
    ModuleCompatibilityPolicyError,
    build_module_compatibility_policy_snapshot,
    evaluate_module_candidate_set_under_policy,
)
from home_center.module_compatibility_snapshot import (
    build_module_compatibility_snapshot,
)


def _manifest(
    module_id: str,
    version: str,
    *,
    digest: str,
    publisher: str = "example",
    dependencies: list[dict[str, object]] | None = None,
    conflicts: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema": "home-center.module-manifest.v2",
        "module": {
            "id": module_id,
            "version": version,
            "name": module_id,
            "publisher": publisher,
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
            "remove": {
                "action": "remove",
                "data_policy": "preserve",
            },
        },
        "artifact": {
            "sha256": digest * 64,
            "size_bytes": 123,
            "media_type": (
                "application/vnd.home-center.module.v1+tar+gzip"
            ),
            "provenance": {
                "statement_sha256": "e" * 64,
                "signer_key_ids": ["sha256:" + "f" * 64],
                "threshold": 1,
            },
        },
    }


def _verified(
    manifest: dict[str, object],
) -> VerifiedModuleArtifact:
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
        object_key=(
            f"sha256/{digest[:2]}/{digest}/artifact.tar.gz"
        ),
    )


def _snapshot(
    *,
    capabilities: list[str] | None = None,
):
    return build_module_compatibility_snapshot(
        home_center_version="0.34.0",
        architecture="x86-64",
        operating_system="linux",
        available_capabilities=capabilities or ["network.lan"],
        installed_modules={},
    )


def _policy(**overrides: object):
    values: dict[str, object] = {
        "policy_version": "1.0.0",
        "blocked_module_ids": (),
        "restrict_publishers": False,
        "allowed_publishers": (),
        "required_runtime_capabilities": (),
        "max_candidate_modules": 128,
    }
    values.update(overrides)
    return build_module_compatibility_policy_snapshot(**values)


def _dependency(
    module_id: str,
    minimum: str = "1.0.0",
    maximum: str = "3.0.0",
) -> dict[str, object]:
    return {
        "id": module_id,
        "minimum_version": minimum,
        "maximum_version_exclusive": maximum,
        "optional": False,
    }


class ModuleCompatibilityPolicyTests(unittest.TestCase):
    def test_policy_identity_is_order_independent(self) -> None:
        first = _policy(
            blocked_module_ids=["zeta.module", "alpha.module"],
            restrict_publishers=True,
            allowed_publishers=["vendor-b", "vendor-a"],
            required_runtime_capabilities=[
                "storage.local",
                "network.lan",
            ],
        )
        second = _policy(
            blocked_module_ids=["alpha.module", "zeta.module"],
            restrict_publishers=True,
            allowed_publishers=["vendor-a", "vendor-b"],
            required_runtime_capabilities=[
                "network.lan",
                "storage.local",
            ],
        )
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.policy_id, second.policy_id)

    def test_publisher_policy_is_canonical(self) -> None:
        with self.assertRaisesRegex(
            ModuleCompatibilityPolicyError,
            "allowed_publishers_required",
        ):
            _policy(restrict_publishers=True)
        with self.assertRaisesRegex(
            ModuleCompatibilityPolicyError,
            "allowed_publishers_not_permitted",
        ):
            _policy(allowed_publishers=["example"])

    def test_compatible_candidate_set_remains_compatible(self) -> None:
        candidate = _manifest("media.server", "1.0.0", digest="a")
        decision = evaluate_module_candidate_set_under_policy(
            _policy(),
            _snapshot(),
            [(candidate, _verified(candidate))],
        )
        self.assertTrue(decision.compatible)
        self.assertEqual(decision.base_status, "compatible")
        self.assertEqual(decision.blocked_modules, ())
        self.assertFalse(decision.installation_authorized)
        self.assertFalse(decision.execution_authorized)

    def test_explicit_module_block_is_fail_closed(self) -> None:
        candidate = _manifest("media.server", "1.0.0", digest="a")
        decision = evaluate_module_candidate_set_under_policy(
            _policy(blocked_module_ids=["media.server"]),
            _snapshot(),
            [(candidate, _verified(candidate))],
        )
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(
            decision.policy_blocked_modules,
            ("media.server",),
        )
        self.assertIn(
            "module_blocked_by_policy",
            decision.policy_reasons,
        )

    def test_publisher_allow_list_blocks_unlisted_publisher(self) -> None:
        candidate = _manifest(
            "media.server",
            "1.0.0",
            digest="a",
            publisher="vendor-b",
        )
        decision = evaluate_module_candidate_set_under_policy(
            _policy(
                restrict_publishers=True,
                allowed_publishers=["vendor-a"],
            ),
            _snapshot(),
            [(candidate, _verified(candidate))],
        )
        self.assertEqual(decision.status, "blocked")
        self.assertIn("publisher_not_allowed", decision.policy_reasons)

    def test_missing_policy_runtime_capability_blocks_all(self) -> None:
        first = _manifest("media.server", "1.0.0", digest="a")
        second = _manifest("files.server", "1.0.0", digest="b")
        decision = evaluate_module_candidate_set_under_policy(
            _policy(
                required_runtime_capabilities=["storage.local"],
            ),
            _snapshot(),
            [(first, _verified(first)), (second, _verified(second))],
        )
        self.assertEqual(
            decision.missing_required_runtime_capabilities,
            ("storage.local",),
        )
        self.assertEqual(
            decision.policy_blocked_modules,
            ("files.server", "media.server"),
        )
        self.assertIn(
            "runtime_capability_required",
            decision.policy_reasons,
        )

    def test_candidate_limit_blocks_whole_set(self) -> None:
        first = _manifest("media.server", "1.0.0", digest="a")
        second = _manifest("files.server", "1.0.0", digest="b")
        decision = evaluate_module_candidate_set_under_policy(
            _policy(max_candidate_modules=1),
            _snapshot(),
            [(first, _verified(first)), (second, _verified(second))],
        )
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(
            decision.policy_blocked_modules,
            ("files.server", "media.server"),
        )
        self.assertIn(
            "candidate_limit_exceeded",
            decision.policy_reasons,
        )

    def test_base_candidate_failure_is_preserved(self) -> None:
        dependency = _manifest("base.media", "1.0.0", digest="a")
        app = _manifest(
            "media.server",
            "1.0.0",
            digest="b",
            dependencies=[
                _dependency("base.media", "2.0.0", "3.0.0")
            ],
        )
        decision = evaluate_module_candidate_set_under_policy(
            _policy(),
            _snapshot(),
            [
                (dependency, _verified(dependency)),
                (app, _verified(app)),
            ],
        )
        self.assertEqual(decision.base_status, "blocked")
        self.assertEqual(
            decision.base_blocked_modules,
            ("media.server",),
        )
        self.assertEqual(decision.policy_blocked_modules, ())
        self.assertEqual(decision.blocked_modules, ("media.server",))

    def test_tampered_policy_snapshot_is_rejected(self) -> None:
        policy = replace(
            _policy(),
            policy_id="mcp-" + "0" * 24,
        )
        candidate = _manifest("media.server", "1.0.0", digest="a")
        with self.assertRaisesRegex(
            ModuleCompatibilityPolicyError,
            "compatibility_policy_rejected",
        ):
            evaluate_module_candidate_set_under_policy(
                policy,
                _snapshot(),
                [(candidate, _verified(candidate))],
            )

    def test_policy_version_changes_bound_identity(self) -> None:
        candidate = _manifest("media.server", "1.0.0", digest="a")
        first = evaluate_module_candidate_set_under_policy(
            _policy(policy_version="1.0.0"),
            _snapshot(),
            [(candidate, _verified(candidate))],
        )
        second = evaluate_module_candidate_set_under_policy(
            _policy(policy_version="1.0.1"),
            _snapshot(),
            [(candidate, _verified(candidate))],
        )
        self.assertNotEqual(first.policy_id, second.policy_id)
        self.assertNotEqual(first.decision_id, second.decision_id)
        self.assertEqual(first.candidate_set_id, second.candidate_set_id)

    def test_contract_schemas_are_closed_and_non_authorizing(self) -> None:
        paths = (
            Path(
                "contracts/modules/"
                "module-compatibility-policy-snapshot.v1.schema.json"
            ),
            Path(
                "contracts/modules/"
                "module-policy-candidate-set-decision.v1.schema.json"
            ),
        )
        for path in paths:
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"])
            for field in (
                "installation_authorized",
                "execution_authorized",
                "production_mutation_enabled",
                "external_publication_authorized",
            ):
                self.assertEqual(
                    schema["properties"][field]["const"],
                    False,
                )


if __name__ == "__main__":
    unittest.main()
