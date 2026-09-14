from __future__ import annotations

import json
import unittest

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
from home_center.manual_failover_recovery import restore_manual_failover_transition

REVISION = "a" * 40
DIGEST = "b" * 64
FINAL_DIGEST = "c" * 64


def membership() -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-restart-test",
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
) -> NodeEvidence:
    return NodeEvidence(
        node_id=node_id,
        version="0.64.0",
        revision=REVISION,
        ready=True,
        service_active=active,
        fenced=fenced,
        authoritative_sha256=digest,
        source_sequence=sequence,
    )


def durable_roundtrip(transition):
    payload = json.loads(json.dumps(transition.as_dict()))
    return restore_manual_failover_transition(payload)


class ManualFailoverRecoveryTests(unittest.TestCase):
    def _phases(self):
        current = membership()
        planned = begin_manual_failover(
            current,
            target_node_id="node-b",
            source=evidence("node-a"),
            target=evidence("node-b", fenced=True),
            transition_id="restart-test",
        )
        source_quiesced = record_source_quiesced(planned, evidence("node-a", active=False))
        final_sync_verified = record_final_sync_verified(
            source_quiesced,
            source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        source_fenced = record_source_fenced(
            final_sync_verified,
            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
        )
        target_promoted, _ = promote_membership(source_fenced, current)
        target_verified = record_target_verified(
            target_promoted,
            source=evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
            target=evidence("node-b", fenced=False, digest=FINAL_DIGEST, sequence=11),
            write_readback_verified=True,
            source_write_rejected=True,
        )
        completed = complete_manual_failover(target_verified)
        return {
            "planned": planned,
            "source_quiesced": source_quiesced,
            "final_sync_verified": final_sync_verified,
            "source_fenced": source_fenced,
            "target_promoted": target_promoted,
            "target_verified": target_verified,
            "completed": completed,
        }

    def test_restart_roundtrip_and_resume_from_every_promotion_phase(self) -> None:
        phases = self._phases()
        for name, transition in phases.items():
            with self.subTest(phase=name):
                restored = durable_roundtrip(transition)
                self.assertEqual(transition, restored)

                if name == "planned":
                    self.assertEqual(
                        "source_quiesced",
                        record_source_quiesced(restored, evidence("node-a", active=False)).phase,
                    )
                elif name == "source_quiesced":
                    self.assertEqual(
                        "final_sync_verified",
                        record_final_sync_verified(
                            restored,
                            source=evidence("node-a", active=False, digest=FINAL_DIGEST, sequence=11),
                            target=evidence("node-b", fenced=True, digest=FINAL_DIGEST, sequence=11),
                        ).phase,
                    )
                elif name == "final_sync_verified":
                    self.assertEqual(
                        "source_fenced",
                        record_source_fenced(
                            restored,
                            evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
                        ).phase,
                    )
                elif name == "source_fenced":
                    resumed, promoted = promote_membership(restored, membership())
                    self.assertEqual("target_promoted", resumed.phase)
                    self.assertEqual("node-b", promoted["writer"])
                    self.assertEqual(8, promoted["generation"])
                elif name == "target_promoted":
                    self.assertEqual(
                        "target_verified",
                        record_target_verified(
                            restored,
                            source=evidence("node-a", active=False, fenced=True, digest=FINAL_DIGEST, sequence=11),
                            target=evidence("node-b", fenced=False, digest=FINAL_DIGEST, sequence=11),
                            write_readback_verified=True,
                            source_write_rejected=True,
                        ).phase,
                    )
                elif name == "target_verified":
                    self.assertEqual("completed", complete_manual_failover(restored).phase)
                else:
                    with self.assertRaisesRegex(ManualFailoverRejected, "immutable"):
                        fail_manual_failover(restored, "restart must not reopen completed transition")

    def test_restart_rejects_ambiguous_or_tampered_durable_state(self) -> None:
        payload = self._phases()["target_promoted"].as_dict()

        cases = []
        extra = dict(payload)
        extra["unexpected"] = True
        cases.append((extra, "fields_rejected"))

        generation = dict(payload)
        generation["to_generation"] = generation["from_generation"] + 2
        cases.append((generation, "to_generation_rejected"))

        missing_sequence = dict(payload)
        missing_sequence["final_source_sequence"] = None
        cases.append((missing_sequence, "final_sequence_missing"))

        failed_without_reason = dict(payload)
        failed_without_reason["phase"] = "failed"
        cases.append((failed_without_reason, "failure_reason_missing"))

        naive_timestamp = dict(payload)
        naive_timestamp["updated_at"] = "2026-09-14T12:05:00"
        cases.append((naive_timestamp, "updated_at_timezone_missing"))

        for candidate, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ManualFailoverRejected, reason):
                    restore_manual_failover_transition(candidate)


if __name__ == "__main__":
    unittest.main()
