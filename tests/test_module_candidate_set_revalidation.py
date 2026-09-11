from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_artifact import VerifiedModuleArtifact, manifest_binding_sha256
from home_center.module_candidate_set import evaluate_module_candidate_set
from home_center.module_candidate_set_revalidation import (
    ModuleCandidateSetRevalidationError,
    revalidate_module_candidate_set,
)
from home_center.module_compatibility_snapshot import (
    build_module_compatibility_snapshot,
)


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


def _snapshot(
    *,
    version: str = "0.33.0",
    capabilities: list[str] | None = None,
    installed: dict[str, str] | None = None,
):
    return build_module_compatibility_snapshot(
        home_center_version=version,
        architecture="x86-64",
        operating_system="linux",
        available_capabilities=(
            ["network.lan"] if capabilities is None else capabilities
        ),
        installed_modules={} if installed is None else installed,
    )


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


class ModuleCandidateSetRevalidationTests(unittest.TestCase):
    def test_exact_same_state_is_current_and_order_independent(self) -> None:
        base = _manifest("base.media", "2.4.0", digest="a")
        app = _manifest(
            "example.media",
            "1.2.0",
            digest="b",
            dependencies=[_dependency("base.media", "2.0.0", "3.0.0")],
        )
        candidates = [(base, _verified(base)), (app, _verified(app))]
        snapshot = _snapshot()
        original = evaluate_module_candidate_set(snapshot, candidates)

        result = revalidate_module_candidate_set(
            snapshot,
            candidates,
            original,
            fresh_snapshot=snapshot,
            fresh_candidates=list(reversed(candidates)),
        )

        self.assertTrue(result.current)
        self.assertEqual(result.drift_reasons, ())
        self.assertEqual(result.stale_modules, ())
        self.assertEqual(
            result.original_candidate_set_id,
            result.fresh_candidate_set_id,
        )
        self.assertFalse(result.installation_authorized)
        self.assertFalse(result.execution_authorized)

    def test_runtime_version_drift_makes_all_decisions_stale(self) -> None:
        base = _manifest("base.media", "2.4.0", digest="a")
        app = _manifest("example.media", "1.2.0", digest="b")
        candidates = [(base, _verified(base)), (app, _verified(app))]
        snapshot = _snapshot()
        original = evaluate_module_candidate_set(snapshot, candidates)

        result = revalidate_module_candidate_set(
            snapshot,
            candidates,
            original,
            fresh_snapshot=_snapshot(version="0.34.0"),
        )

        self.assertEqual(result.status, "stale")
        self.assertIn("home_center_version_changed", result.drift_reasons)
        self.assertIn("snapshot_changed", result.drift_reasons)
        self.assertEqual(
            result.stale_modules,
            ("base.media", "example.media"),
        )

    def test_capability_drift_can_block_candidate(self) -> None:
        candidate = _manifest("base.media", "2.4.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        snapshot = _snapshot()
        original = evaluate_module_candidate_set(snapshot, candidates)

        result = revalidate_module_candidate_set(
            snapshot,
            candidates,
            original,
            fresh_snapshot=_snapshot(capabilities=[]),
        )

        self.assertEqual(result.status, "stale")
        self.assertEqual(result.fresh_blocked_modules, ("base.media",))
        self.assertIn("capability_set_changed", result.drift_reasons)
        self.assertIn("candidate_compatibility_changed", result.drift_reasons)
        self.assertIn("base.media", result.stale_modules)

    def test_installed_module_drift_can_activate_conflict(self) -> None:
        candidate = _manifest(
            "base.media",
            "2.4.0",
            digest="a",
            conflicts=["legacy.media"],
        )
        candidates = [(candidate, _verified(candidate))]
        snapshot = _snapshot()
        original = evaluate_module_candidate_set(snapshot, candidates)

        result = revalidate_module_candidate_set(
            snapshot,
            candidates,
            original,
            fresh_snapshot=_snapshot(installed={"legacy.media": "1.0.0"}),
        )

        self.assertEqual(result.fresh_blocked_modules, ("base.media",))
        self.assertIn("installed_module_set_changed", result.drift_reasons)
        self.assertIn("set_compatibility_status_changed", result.drift_reasons)

    def test_candidate_membership_change_makes_set_stale(self) -> None:
        base = _manifest("base.media", "2.4.0", digest="a")
        original_candidates = [(base, _verified(base))]
        snapshot = _snapshot()
        original = evaluate_module_candidate_set(snapshot, original_candidates)
        app = _manifest("example.media", "1.2.0", digest="b")

        result = revalidate_module_candidate_set(
            snapshot,
            original_candidates,
            original,
            fresh_snapshot=snapshot,
            fresh_candidates=[
                (base, _verified(base)),
                (app, _verified(app)),
            ],
        )

        self.assertEqual(result.status, "stale")
        self.assertIn("candidate_membership_changed", result.drift_reasons)
        self.assertIn("planned_module_set_changed", result.drift_reasons)
        self.assertEqual(
            result.stale_modules,
            ("base.media", "example.media"),
        )

    def test_candidate_version_and_artifact_change_are_detected(self) -> None:
        original_manifest = _manifest("base.media", "2.4.0", digest="a")
        original_candidates = [
            (original_manifest, _verified(original_manifest))
        ]
        snapshot = _snapshot()
        original = evaluate_module_candidate_set(snapshot, original_candidates)
        fresh_manifest = _manifest("base.media", "2.5.0", digest="b")

        result = revalidate_module_candidate_set(
            snapshot,
            original_candidates,
            original,
            fresh_snapshot=snapshot,
            fresh_candidates=[(fresh_manifest, _verified(fresh_manifest))],
        )

        self.assertEqual(result.status, "stale")
        self.assertIn("candidate_version_changed", result.drift_reasons)
        self.assertIn(
            "candidate_artifact_evidence_changed",
            result.drift_reasons,
        )
        self.assertEqual(result.stale_modules, ("base.media",))

    def test_tampered_original_candidate_set_is_rejected(self) -> None:
        candidate = _manifest("base.media", "2.4.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        snapshot = _snapshot()
        original = evaluate_module_candidate_set(snapshot, candidates)
        tampered = replace(
            original,
            candidate_set_id="mcsd-" + "0" * 24,
        )

        with self.assertRaisesRegex(
            ModuleCandidateSetRevalidationError,
            "original_candidate_set_evidence_rejected",
        ):
            revalidate_module_candidate_set(
                snapshot,
                candidates,
                tampered,
                fresh_snapshot=snapshot,
            )

    def test_tampered_fresh_snapshot_is_rejected(self) -> None:
        candidate = _manifest("base.media", "2.4.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        snapshot = _snapshot()
        original = evaluate_module_candidate_set(snapshot, candidates)
        tampered_snapshot = replace(
            snapshot,
            snapshot_id="mcs-" + "0" * 24,
        )

        with self.assertRaisesRegex(
            ModuleCandidateSetRevalidationError,
            "fresh_candidate_set_evidence_rejected",
        ):
            revalidate_module_candidate_set(
                snapshot,
                candidates,
                original,
                fresh_snapshot=tampered_snapshot,
            )

    def test_contract_schema_is_closed_and_non_authorizing(self) -> None:
        schema = json.loads(
            Path(
                "contracts/modules/"
                "module-candidate-set-revalidation.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        for field in (
            "installation_authorized",
            "execution_authorized",
            "production_mutation_enabled",
            "external_publication_authorized",
        ):
            self.assertEqual(schema["properties"][field]["const"], False)


if __name__ == "__main__":
    unittest.main()
