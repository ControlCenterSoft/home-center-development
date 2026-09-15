from __future__ import annotations

import unittest

from home_center.manual_failover import ManualFailoverRejected, NodeEvidence


class ManualFailoverEvidenceTypeTests(unittest.TestCase):
    def _evidence(self, **overrides: object) -> NodeEvidence:
        values: dict[str, object] = {
            "node_id": "node-a",
            "version": "0.64.0",
            "revision": "a" * 40,
            "ready": True,
            "service_active": True,
            "fenced": False,
            "authoritative_sha256": "b" * 64,
            "source_sequence": 10,
        }
        values.update(overrides)
        return NodeEvidence(**values)  # type: ignore[arg-type]

    def test_node_evidence_rejects_non_boolean_runtime_flags(self) -> None:
        cases = (
            ("ready", "false", "ready_boolean_required"),
            ("service_active", 1, "service_active_boolean_required"),
            ("fenced", "true", "fenced_boolean_required"),
        )
        for field_name, value, error in cases:
            with self.subTest(field_name=field_name, value=value):
                with self.assertRaisesRegex(ManualFailoverRejected, error):
                    self._evidence(**{field_name: value}).validate()

    def test_node_evidence_accepts_real_booleans(self) -> None:
        self._evidence(ready=True, service_active=False, fenced=True).validate()


if __name__ == "__main__":
    unittest.main()
