from __future__ import annotations

import unittest

from home_center.manual_failover import (
    ManualFailoverRejected,
    NodeEvidence,
    begin_manual_failover,
    promote_membership,
    record_final_sync_verified,
    record_source_fenced,
    record_source_quiesced,
    record_target_verified,
)

REVISION = "a" * 40
DIGEST = "b" * 64
FINAL_DIGEST = "c" * 64
DRIFT_DIGEST = "d" * 64


def membership() -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-final-sync-binding",
        "generation": 7,
        "writer": "node-a",
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": "node-b", "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-14T12:00:00Z",
    }


def evidence(
    node_id: str,
    *,
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
        ready=True,
        service_active=active,
        fenced=fenced,
        authoritative_sha256=digest,
        source_sequence=sequence,
    )


def final_sync_transition():
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
    return current, transition


class ManualFailoverFinalSyncBindingTests(unittest.TestCase):
    def test_source_fence_rejects_authoritative_drift_after_final_sync(self) -> None:
        _, transition = final_sync_transition()

        with self.assertRaisesRegex(
            ManualFailoverRejected,
            "source_state_changed_after_final_sync",
        ):
            record_source_fenced(
                transition,
                evidence("node-a", active=False, fenced=True, digest=DRIFT_DIGEST, sequence=11),
            )

        with self.assertRaisesRegex(
            ManualFailoverRejected,
            "source_sequence_changed_after_final_sync",
        ):
            record_source_fenced(
                transition,
                evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=12),
            )

    def test_target_verification_rechecks_old_writer_final_sync_identity(self) -> None:
        current, transition = final_sync_transition()
        transition = record_source_fenced(
            transition,
            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        transition, _ = promote_membership(transition, current)

        with self.assertRaisesRegex(
            ManualFailoverRejected,
            "old_writer_state_changed_after_final_sync",
        ):
            record_target_verified(
                transition,
                source=evidence("node-a", active=False, fenced=True, digest=DRIFT_DIGEST, sequence=11),
                target=evidence("node-b", fenced=False, digest=FINAL_DIGEST, sequence=11),
                write_readback_verified=True,
                source_write_rejected=True,
            )

        with self.assertRaisesRegex(
            ManualFailoverRejected,
            "old_writer_release_changed",
        ):
            record_target_verified(
                transition,
                source=evidence(
                    "node-a",
                    active=False,
                    fenced=True,
                    digest=FINAL_DIGEST,
                    sequence=11,
                    version="0.64.1",
                ),
                target=evidence("node-b", fenced=False, digest=FINAL_DIGEST, sequence=11),
                write_readback_verified=True,
                source_write_rejected=True,
            )

    def test_target_verification_rejects_sequence_regression_after_promotion(self) -> None:
        current, transition = final_sync_transition()
        transition = record_source_fenced(
            transition,
            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        transition, _ = promote_membership(transition, current)

        with self.assertRaisesRegex(
            ManualFailoverRejected,
            "promoted_writer_sequence_regressed",
        ):
            record_target_verified(
                transition,
                source=evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
                target=evidence("node-b", fenced=False, digest=FINAL_DIGEST, sequence=10),
                write_readback_verified=True,
                source_write_rejected=True,
            )

        verified = record_target_verified(
            transition,
            source=evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=False, digest=DRIFT_DIGEST, sequence=12),
            write_readback_verified=True,
            source_write_rejected=True,
        )
        self.assertEqual("target_verified", verified.phase)


if __name__ == "__main__":
    unittest.main()
