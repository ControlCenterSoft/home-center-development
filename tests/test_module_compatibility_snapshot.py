from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from home_center.module_admission import ModuleAdmissionDecision
from home_center.module_compatibility_snapshot import (
    ModuleCompatibilitySnapshotError,
    bind_module_admission_decisions_to_snapshot,
    build_module_compatibility_snapshot,
)


def _decision(
    *,
    module_id: str = "example.media",
    module_version: str = "1.2.0",
    home_center_version: str = "0.31.0",
    architecture: str = "x86-64",
    operating_system: str = "linux",
    available_capabilities: tuple[str, ...] = ("network.lan", "storage.local"),
    installed_modules: tuple[tuple[str, str], ...] = (("base.media", "2.1.0"),),
    status: str = "compatible",
    reasons: tuple[str, ...] = (),
) -> ModuleAdmissionDecision:
    kwargs = {
        "status": status,
        "module_id": module_id,
        "module_version": module_version,
        "publisher": "example",
        "manifest_binding_sha256": "a" * 64,
        "provenance_statement_sha256": "b" * 64,
        "verified_signing_key_ids": ("sha256:" + "c" * 64,),
        "artifact_sha256": "d" * 64,
        "home_center_version": home_center_version,
        "architecture": architecture,
        "operating_system": operating_system,
        "available_capabilities": available_capabilities,
        "installed_modules": installed_modules,
        "missing_capabilities": (),
        "unsatisfied_dependencies": (),
        "active_conflicts": (),
        "reasons": reasons,
    }
    provisional = ModuleAdmissionDecision(decision_id="pending", **kwargs)
    payload = provisional.to_dict()
    payload.pop("decision_id")
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return ModuleAdmissionDecision(
        decision_id="madm-" + hashlib.sha256(encoded).hexdigest()[:24],
        **kwargs,
    )


def _snapshot():
    return build_module_compatibility_snapshot(
        home_center_version="0.31.0",
        architecture="x86-64",
        operating_system="linux",
        available_capabilities=["storage.local", "network.lan"],
        installed_modules={"base.media": "2.1.0"},
    )


class ModuleCompatibilitySnapshotTests(unittest.TestCase):
    def test_snapshot_is_order_independent_and_reproducible(self) -> None:
        first = _snapshot()
        second = build_module_compatibility_snapshot(
            home_center_version="0.31.0",
            architecture="x86-64",
            operating_system="linux",
            available_capabilities=["network.lan", "storage.local"],
            installed_modules={"base.media": "2.1.0"},
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first.available_capabilities,
            ("network.lan", "storage.local"),
        )

    def test_binding_accepts_multiple_decisions_for_one_snapshot(self) -> None:
        snapshot = _snapshot()
        first = _decision(module_id="example.media")
        second = _decision(
            module_id="example.backup",
            module_version="2.0.0",
        )
        result = bind_module_admission_decisions_to_snapshot(
            snapshot,
            [first, second],
        )
        self.assertEqual(result.snapshot_id, snapshot.snapshot_id)
        self.assertEqual(len(result.decisions), 2)
        self.assertFalse(result.installation_authorized)
        self.assertFalse(result.execution_authorized)

    def test_binding_order_is_deterministic(self) -> None:
        snapshot = _snapshot()
        first = _decision(module_id="example.media")
        second = _decision(
            module_id="example.backup",
            module_version="2.0.0",
        )
        left = bind_module_admission_decisions_to_snapshot(
            snapshot,
            [first, second],
        )
        right = bind_module_admission_decisions_to_snapshot(
            snapshot,
            [second, first],
        )
        self.assertEqual(left, right)

    def test_mixed_runtime_version_is_rejected(self) -> None:
        snapshot = _snapshot()
        decision = _decision(home_center_version="0.30.0")
        with self.assertRaisesRegex(
            ModuleCompatibilitySnapshotError,
            "admission_decision_snapshot_mismatch",
        ):
            bind_module_admission_decisions_to_snapshot(snapshot, [decision])

    def test_mixed_capability_set_is_rejected(self) -> None:
        snapshot = _snapshot()
        decision = _decision(available_capabilities=("network.lan",))
        with self.assertRaisesRegex(
            ModuleCompatibilitySnapshotError,
            "admission_decision_snapshot_mismatch",
        ):
            bind_module_admission_decisions_to_snapshot(snapshot, [decision])

    def test_mixed_installed_module_state_is_rejected(self) -> None:
        snapshot = _snapshot()
        decision = _decision(installed_modules=(("base.media", "2.2.0"),))
        with self.assertRaisesRegex(
            ModuleCompatibilitySnapshotError,
            "admission_decision_snapshot_mismatch",
        ):
            bind_module_admission_decisions_to_snapshot(snapshot, [decision])

    def test_duplicate_module_decision_is_rejected(self) -> None:
        snapshot = _snapshot()
        with self.assertRaisesRegex(
            ModuleCompatibilitySnapshotError,
            "admission_module_duplicate",
        ):
            bind_module_admission_decisions_to_snapshot(
                snapshot,
                [
                    _decision(),
                    _decision(module_version="1.3.0"),
                ],
            )

    def test_tampered_decision_identity_is_rejected(self) -> None:
        snapshot = _snapshot()
        forged = replace(_decision(), artifact_sha256="e" * 64)
        with self.assertRaisesRegex(
            ModuleCompatibilitySnapshotError,
            "admission_decision_rejected",
        ):
            bind_module_admission_decisions_to_snapshot(snapshot, [forged])

    def test_authority_flag_tampering_is_rejected(self) -> None:
        snapshot = _snapshot()
        forged = replace(_decision(), installation_authorized=True)
        with self.assertRaisesRegex(
            ModuleCompatibilitySnapshotError,
            "admission_decision_rejected",
        ):
            bind_module_admission_decisions_to_snapshot(snapshot, [forged])

    def test_tampered_snapshot_identity_is_rejected(self) -> None:
        snapshot = replace(_snapshot(), snapshot_id="mcs-" + "0" * 24)
        with self.assertRaisesRegex(
            ModuleCompatibilitySnapshotError,
            "compatibility_snapshot_rejected",
        ):
            bind_module_admission_decisions_to_snapshot(snapshot, [_decision()])

    def test_ids_are_reproducible_from_serialized_evidence(self) -> None:
        snapshot = _snapshot()
        snapshot_payload = snapshot.to_dict()
        snapshot_id = snapshot_payload.pop("snapshot_id")
        encoded = json.dumps(
            snapshot_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        self.assertEqual(
            snapshot_id,
            "mcs-" + hashlib.sha256(encoded).hexdigest()[:24],
        )

        binding = bind_module_admission_decisions_to_snapshot(
            snapshot,
            [_decision()],
        )
        binding_payload = binding.to_dict()
        binding_id = binding_payload.pop("binding_id")
        encoded = json.dumps(
            binding_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        self.assertEqual(
            binding_id,
            "masb-" + hashlib.sha256(encoded).hexdigest()[:24],
        )

    def test_contract_schemas_are_closed_and_non_authorizing(self) -> None:
        for filename in (
            "module-compatibility-snapshot.v1.schema.json",
            "module-admission-snapshot-binding.v1.schema.json",
        ):
            schema = json.loads(
                Path("contracts/modules", filename).read_text(encoding="utf-8")
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
