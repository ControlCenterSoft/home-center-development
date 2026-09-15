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
DIGEST = "c" * 64


def membership() -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
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
        "observed_at": "2026-09-15T04:00:00Z",
    }


def evidence(
    node_id: str,
    *,
    active: bool = True,
    fenced: bool = False,
    sequence: int = 11,
) -> NodeEvidence:
    return NodeEvidence(
        node_id=node_id,
        version="0.64.0",
        revision=REVISION,
        ready=True,
        service_active=active,
        fenced=fenced,
        authoritative_sha256=DIGEST,
        source_sequence=sequence,
    )


def promoted_transition():
    current = membership()
    transition = begin_manual_failover(
        current,
        target_node_id="node-b",
        source=evidence("node-a"),
        target=evidence("node-b", fenced=True),
        transition_id="verification-types",
    )
    transition = record_source_quiesced(
        transition,
        evidence("node-a", active=False),
    )
    transition = record_final_sync_verified(
        transition,
        source=evidence("node-a", active=False),
        target=evidence("node-b", fenced=True),
    )
    transition = record_source_fenced(
        transition,
        evidence("node-a", active=False, fenced=True),
    )
    transition, _ = promote_membership(transition, current)
    return transition


class ManualFailoverVerificationEvidenceTypeTests(unittest.TestCase):
    def test_target_verification_rejects_non_boolean_outcome_evidence(self) -> None:
        transition = promoted_transition()
        cases = (
            ("write_readback_verified", "false", "write_readback_verified_boolean_required"),
            ("source_write_rejected", 1, "source_write_rejected_boolean_required"),
        )
        for field_name, value, error in cases:
            kwargs = {
                "write_readback_verified": True,
                "source_write_rejected": True,
                field_name: value,
            }
            with self.subTest(field_name=field_name, value=value):
                with self.assertRaisesRegex(ManualFailoverRejected, error):
                    record_target_verified(
                        transition,
                        source=evidence("node-a", active=False, fenced=True),
                        target=evidence("node-b", active=True, fenced=False),
                        **kwargs,  # type: ignore[arg-type]
                    )

    def test_target_verification_accepts_real_boolean_outcome_evidence(self) -> None:
        transition = record_target_verified(
            promoted_transition(),
            source=evidence("node-a", active=False, fenced=True),
            target=evidence("node-b", active=True, fenced=False),
            write_readback_verified=True,
            source_write_rejected=True,
        )
        self.assertEqual("target_verified", transition.phase)


if __name__ == "__main__":
    unittest.main()
