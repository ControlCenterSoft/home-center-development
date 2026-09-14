from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema

from home_center.manual_failover import (
    ManualFailoverRejected,
    NodeEvidence,
    begin_manual_failover,
    complete_manual_failover,
    fail_manual_failover,
    promote_membership,
    record_final_sync_verified,
    record_source_fenced,
    record_source_quiesced,
    record_target_verified,
)


REVISION = "a" * 40
DIGEST = "b" * 64
FINAL_DIGEST = "c" * 64


def membership(*, generation: int = 7, writer: str = "node-a", automatic_failover: bool = False) -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": generation,
        "writer": writer,
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": "node-b", "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": automatic_failover,
            "witness_id": None,
        },
        "observed_at": "2026-09-14T12:00:00Z",
    }


def evidence(
    node_id: str,
    *,
    ready: bool = True,
    active: bool = True,
    fenced: bool = False,
    digest: str = DIGEST,
    sequence: int = 10,
    version: str = "0.64.0",
    revision: str = REVISION,
) -> NodeEvidence:
    return NodeEvidence(
        node_id=node_id,
        version=version,
        revision=revision,
        ready=ready,
        service_active=active,
        fenced=fenced,
        authoritative_sha256=digest,
        source_sequence=sequence,
    )


class ManualFailoverTests(unittest.TestCase):
    def test_complete_handoff_advances_writer_generation_only_after_safety_gates(self) -> None:
        current = membership()
        transition = begin_manual_failover(
            current,
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
            transition_id="transition-test",
        )
        self.assertEqual("planned", transition.phase)
        self.assertEqual(7, transition.from_generation)
        self.assertEqual(8, transition.to_generation)

        transition = record_source_quiesced(
            transition,
            evidence("node-a", active=False),
        )
        transition = record_final_sync_verified(
            transition,
            source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        self.assertEqual(11, transition.final_source_sequence)
        self.assertEqual(FINAL_DIGEST, transition.authoritative_sha256)

        transition = record_source_fenced(
            transition,
            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        transition, promoted = promote_membership(transition, current)
        self.assertEqual("target_promoted", transition.phase)
        self.assertEqual(8, promoted["generation"])
        self.assertEqual("node-b", promoted["writer"])
        self.assertFalse(promoted["quorum"]["automatic_failover"])

        transition = record_target_verified(
            transition,
            source=evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", active=True, fenced=False, digest=FINAL_DIGEST, sequence=11),
            write_readback_verified=True,
            source_write_rejected=True,
        )
        transition = complete_manual_failover(transition)
        self.assertEqual("completed", transition.phase)

        schema_path = Path("contracts/cluster/manual-failover-transition.v1.schema.json")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
            transition.as_dict()
        )

    def test_preflight_rejects_release_state_fence_and_automatic_failover_drift(self) -> None:
        with self.assertRaisesRegex(ManualFailoverRejected, "release_drift"):
            begin_manual_failover(
                membership(),
                target_node_id="node-b",
                source=evidence("node-a"),
                target=evidence("node-b", fenced=True, version="0.64.1"),
            )

        with self.assertRaisesRegex(ManualFailoverRejected, "authoritative_state_drift"):
            begin_manual_failover(
                membership(),
                target_node_id="node-b",
                source=evidence("node-a"),
                target=evidence("node-b", fenced=True, digest="d" * 64),
            )

        with self.assertRaisesRegex(ManualFailoverRejected, "standby_must_be_fenced"):
            begin_manual_failover(
                membership(),
                target_node_id="node-b",
                source=evidence("node-a"),
                target=evidence("node-b", fenced=False),
            )

        with self.assertRaisesRegex(ManualFailoverRejected, "automatic_or_nonmanual"):
            begin_manual_failover(
                membership(automatic_failover=True),
                target_node_id="node-b",
                source=evidence("node-a"),
                target=evidence("node-b", fenced=True),
            )

    def test_final_sync_must_match_digest_and_monotonic_sequence(self) -> None:
        transition = begin_manual_failover(
            membership(),
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
        )
        transition = record_source_quiesced(transition, evidence("node-a", active=False))

        with self.assertRaisesRegex(ManualFailoverRejected, "final_sync_digest_mismatch"):
            record_final_sync_verified(
                transition,
                source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=12),
                target=evidence("node-b", fenced=True, digest=DIGEST, sequence=12),
            )

        with self.assertRaisesRegex(ManualFailoverRejected, "final_sync_sequence_not_applied"):
            record_final_sync_verified(
                transition,
                source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=12),
                target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
            )

    def test_promotion_rejects_stale_membership_generation(self) -> None:
        current = membership()
        transition = begin_manual_failover(
            current,
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
        )
        transition = record_source_quiesced(transition, evidence("node-a", active=False))
        transition = record_final_sync_verified(
            transition,
            source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        transition = record_source_fenced(
            transition,
            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
        )

        with self.assertRaisesRegex(ManualFailoverRejected, "membership_generation_changed"):
            promote_membership(transition, membership(generation=8))

    def test_target_verification_requires_old_writer_fence_and_write_readback(self) -> None:
        current = membership()
        transition = begin_manual_failover(
            current,
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
        )
        transition = record_source_quiesced(transition, evidence("node-a", active=False))
        transition = record_final_sync_verified(
            transition,
            source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        transition = record_source_fenced(
            transition,
            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        transition, _ = promote_membership(transition, current)

        with self.assertRaisesRegex(ManualFailoverRejected, "old_writer_not_safely_fenced"):
            record_target_verified(
                transition,
                source=evidence("node-a", active=False, fenced=False, digest=FINAL_DIGEST, sequence=11),
                target=evidence("node-b", active=True, fenced=False, digest=FINAL_DIGEST, sequence=11),
                write_readback_verified=True,
                source_write_rejected=True,
            )

        with self.assertRaisesRegex(ManualFailoverRejected, "readback_unverified"):
            record_target_verified(
                transition,
                source=evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
                target=evidence("node-b", active=True, fenced=False, digest=FINAL_DIGEST, sequence=11),
                write_readback_verified=False,
                source_write_rejected=True,
            )

        with self.assertRaisesRegex(ManualFailoverRejected, "write_rejection_unverified"):
            record_target_verified(
                transition,
                source=evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
                target=evidence("node-b", active=True, fenced=False, digest=FINAL_DIGEST, sequence=11),
                write_readback_verified=True,
                source_write_rejected=False,
            )

    def test_failure_is_durable_terminal_evidence_but_completed_transition_is_immutable(self) -> None:
        transition = begin_manual_failover(
            membership(),
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
        )
        failed = fail_manual_failover(transition, "final sync unavailable")
        self.assertEqual("failed", failed.phase)
        self.assertEqual("final sync unavailable", failed.failure_reason)

        completed = transition
        completed = record_source_quiesced(completed, evidence("node-a", active=False))
        completed = record_final_sync_verified(
            completed,
            source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        completed = record_source_fenced(
            completed,
            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        completed, _ = promote_membership(completed, membership())
        completed = record_target_verified(
            completed,
            source=evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", active=True, fenced=False, digest=FINAL_DIGEST, sequence=11),
            write_readback_verified=True,
            source_write_rejected=True,
        )
        completed = complete_manual_failover(completed)
        with self.assertRaisesRegex(ManualFailoverRejected, "immutable"):
            fail_manual_failover(completed, "must not change")


if __name__ == "__main__":
    unittest.main()
