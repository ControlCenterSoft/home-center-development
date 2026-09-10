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
    build_module_compatibility_policy_snapshot,
    evaluate_module_candidate_set_under_policy,
)
from home_center.module_compatibility_snapshot import (
    build_module_compatibility_snapshot,
)
from home_center.module_policy_candidate_set_revalidation import (
    ModulePolicyCandidateSetRevalidationError,
    revalidate_module_candidate_set_under_policy,
)


def _manifest(
    module_id: str,
    version: str,
    *,
    digest: str,
    publisher: str = "example",
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
        "dependencies": [],
        "conflicts": [],
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
        object_key=f"sha256/{digest[:2]}/{digest}/artifact.tar.gz",
    )


def _snapshot(
    *,
    version: str = "0.35.0",
    capabilities: list[str] | None = None,
):
    return build_module_compatibility_snapshot(
        home_center_version=version,
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


def _decision(policy, snapshot, candidates):
    return evaluate_module_candidate_set_under_policy(
        policy,
        snapshot,
        candidates,
    )


class ModulePolicyCandidateSetRevalidationTests(unittest.TestCase):
    def test_unchanged_evidence_is_current_and_deterministic(self) -> None:
        policy = _policy()
        snapshot = _snapshot()
        candidate = _manifest("media.server", "1.0.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        original = _decision(policy, snapshot, candidates)

        first = revalidate_module_candidate_set_under_policy(
            policy,
            snapshot,
            candidates,
            original,
            fresh_snapshot=snapshot,
        )
        second = revalidate_module_candidate_set_under_policy(
            policy,
            snapshot,
            candidates,
            original,
            fresh_snapshot=snapshot,
        )

        self.assertTrue(first.current)
        self.assertEqual(first.revalidation_id, second.revalidation_id)
        self.assertEqual(first.drift_reasons, ())
        self.assertEqual(first.stale_modules, ())
        self.assertFalse(first.installation_authorized)
        self.assertFalse(first.execution_authorized)

    def test_policy_version_change_makes_evidence_stale(self) -> None:
        policy = _policy(policy_version="1.0.0")
        fresh_policy = _policy(policy_version="1.0.1")
        snapshot = _snapshot()
        candidate = _manifest("media.server", "1.0.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        original = _decision(policy, snapshot, candidates)

        result = revalidate_module_candidate_set_under_policy(
            policy,
            snapshot,
            candidates,
            original,
            fresh_snapshot=snapshot,
            fresh_policy=fresh_policy,
        )

        self.assertEqual(result.status, "stale")
        self.assertIn("compatibility_policy_changed", result.drift_reasons)
        self.assertIn("policy_version_changed", result.drift_reasons)
        self.assertEqual(result.stale_modules, ("media.server",))

    def test_policy_rule_change_reports_module_outcome_drift(self) -> None:
        policy = _policy()
        fresh_policy = _policy(blocked_module_ids=["media.server"])
        snapshot = _snapshot()
        candidate = _manifest("media.server", "1.0.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        original = _decision(policy, snapshot, candidates)

        result = revalidate_module_candidate_set_under_policy(
            policy,
            snapshot,
            candidates,
            original,
            fresh_snapshot=snapshot,
            fresh_policy=fresh_policy,
        )

        self.assertEqual(result.fresh_status, "blocked")
        self.assertIn("aggregate_status_changed", result.drift_reasons)
        self.assertIn(
            "policy_blocked_module_set_changed",
            result.drift_reasons,
        )
        self.assertIn("module_policy_outcome_changed", result.drift_reasons)

    def test_runtime_snapshot_change_is_stale_even_if_compatible(self) -> None:
        policy = _policy()
        original_snapshot = _snapshot()
        fresh_snapshot = _snapshot(
            capabilities=["network.lan", "storage.local"]
        )
        candidate = _manifest("media.server", "1.0.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        original = _decision(policy, original_snapshot, candidates)

        result = revalidate_module_candidate_set_under_policy(
            policy,
            original_snapshot,
            candidates,
            original,
            fresh_snapshot=fresh_snapshot,
        )

        self.assertEqual(result.original_status, "compatible")
        self.assertEqual(result.fresh_status, "compatible")
        self.assertIn("runtime_snapshot_changed", result.drift_reasons)
        self.assertIn("candidate_set_changed", result.drift_reasons)
        self.assertEqual(result.stale_modules, ("media.server",))

    def test_candidate_artifact_change_makes_evidence_stale(self) -> None:
        policy = _policy()
        snapshot = _snapshot()
        original_manifest = _manifest(
            "media.server",
            "1.0.0",
            digest="a",
        )
        fresh_manifest = _manifest(
            "media.server",
            "1.0.0",
            digest="b",
        )
        original_candidates = [
            (original_manifest, _verified(original_manifest))
        ]
        fresh_candidates = [
            (fresh_manifest, _verified(fresh_manifest))
        ]
        original = _decision(
            policy,
            snapshot,
            original_candidates,
        )

        result = revalidate_module_candidate_set_under_policy(
            policy,
            snapshot,
            original_candidates,
            original,
            fresh_snapshot=snapshot,
            fresh_candidates=fresh_candidates,
        )

        self.assertIn("candidate_set_changed", result.drift_reasons)
        self.assertEqual(result.stale_modules, ("media.server",))

    def test_candidate_order_is_not_drift(self) -> None:
        policy = _policy()
        snapshot = _snapshot()
        first = _manifest("media.server", "1.0.0", digest="a")
        second = _manifest("files.server", "1.0.0", digest="b")
        original_candidates = [
            (first, _verified(first)),
            (second, _verified(second)),
        ]
        fresh_candidates = list(reversed(original_candidates))
        original = _decision(
            policy,
            snapshot,
            original_candidates,
        )

        result = revalidate_module_candidate_set_under_policy(
            policy,
            snapshot,
            original_candidates,
            original,
            fresh_snapshot=snapshot,
            fresh_candidates=fresh_candidates,
        )

        self.assertTrue(result.current)
        self.assertEqual(result.drift_reasons, ())

    def test_tampered_original_decision_is_rejected(self) -> None:
        policy = _policy()
        snapshot = _snapshot()
        candidate = _manifest("media.server", "1.0.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        original = replace(
            _decision(policy, snapshot, candidates),
            decision_id="mpcs-" + "0" * 24,
        )

        with self.assertRaisesRegex(
            ModulePolicyCandidateSetRevalidationError,
            "original_policy_candidate_set_evidence_rejected",
        ):
            revalidate_module_candidate_set_under_policy(
                policy,
                snapshot,
                candidates,
                original,
                fresh_snapshot=snapshot,
            )

    def test_tampered_original_policy_is_rejected(self) -> None:
        policy = replace(
            _policy(),
            policy_id="mcp-" + "0" * 24,
        )
        valid_policy = _policy()
        snapshot = _snapshot()
        candidate = _manifest("media.server", "1.0.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        original = _decision(valid_policy, snapshot, candidates)

        with self.assertRaisesRegex(
            ModulePolicyCandidateSetRevalidationError,
            "original_policy_candidate_set_evidence_rejected",
        ):
            revalidate_module_candidate_set_under_policy(
                policy,
                snapshot,
                candidates,
                original,
                fresh_snapshot=snapshot,
            )

    def test_tampered_fresh_policy_is_rejected(self) -> None:
        policy = _policy()
        fresh_policy = replace(
            policy,
            policy_id="mcp-" + "0" * 24,
        )
        snapshot = _snapshot()
        candidate = _manifest("media.server", "1.0.0", digest="a")
        candidates = [(candidate, _verified(candidate))]
        original = _decision(policy, snapshot, candidates)

        with self.assertRaisesRegex(
            ModulePolicyCandidateSetRevalidationError,
            "fresh_policy_candidate_set_evidence_rejected",
        ):
            revalidate_module_candidate_set_under_policy(
                policy,
                snapshot,
                candidates,
                original,
                fresh_snapshot=snapshot,
                fresh_policy=fresh_policy,
            )

    def test_contract_schema_is_closed_and_non_authorizing(self) -> None:
        path = Path(
            "contracts/modules/"
            "module-policy-candidate-set-revalidation.v1.schema.json"
        )
        schema = json.loads(path.read_text(encoding="utf-8"))
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
