from __future__ import annotations

import unittest
from contextlib import contextmanager
from dataclasses import replace
from typing import Any, Iterator

from home_center.ha_update_interlock import UpdateInterlockEvidence
from home_center.manual_failover import (
    NodeEvidence,
    begin_manual_failover,
    promote_membership,
    record_final_sync_verified,
    record_source_fenced,
    record_source_quiesced,
)
from home_center.manual_failover_executor import (
    ManualFailoverExecutorRejected,
    execute_manual_failover,
)


REVISION = "a" * 40
INITIAL_DIGEST = "b" * 64
FINAL_DIGEST = "c" * 64


def membership(*, writer: str = "node-a", generation: int = 7) -> dict[str, Any]:
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
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-15T12:00:00Z",
    }


def evidence(
    node_id: str,
    *,
    active: bool = True,
    fenced: bool = False,
    digest: str = INITIAL_DIGEST,
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


class FakeBackend:
    def __init__(self) -> None:
        self.membership = membership()
        self.transition: dict[str, Any] | None = None
        self.evidence = {
            "node-a": evidence("node-a"),
            "node-b": evidence("node-b", fenced=True),
        }
        self.trace: list[str] = []
        self.fail_target_unfence = False

    def load_membership(self) -> dict[str, Any]:
        return dict(self.membership)

    def load_transition(self) -> dict[str, Any] | None:
        return None if self.transition is None else dict(self.transition)

    def persist_transition(self, transition, *, expected_phase: str | None) -> None:
        current_phase = None if self.transition is None else self.transition["phase"]
        if current_phase in {"completed", "failed"} and expected_phase is None:
            pass
        elif current_phase != expected_phase:
            raise AssertionError(f"CAS phase mismatch: {current_phase!r} != {expected_phase!r}")
        self.trace.append(f"persist:{transition.phase}")
        self.transition = transition.as_dict()

    def commit_promotion(
        self,
        *,
        before_membership: dict[str, Any],
        after_membership: dict[str, Any],
        before_transition,
        after_transition,
    ) -> None:
        self.trace.append("commit_promotion")
        if self.membership != before_membership:
            raise AssertionError("membership changed before promotion")
        if self.transition != before_transition.as_dict():
            raise AssertionError("transition changed before promotion")
        self.membership = dict(after_membership)
        self.transition = after_transition.as_dict()

    def node_evidence(self, node_id: str) -> NodeEvidence:
        self.trace.append(f"evidence:{node_id}")
        return self.evidence[node_id]

    def quiesce_source(self, node_id: str) -> None:
        self.trace.append(f"quiesce:{node_id}")
        self.evidence[node_id] = replace(self.evidence[node_id], service_active=False)

    def synchronize_authoritative_state(self, source_node_id: str, target_node_id: str) -> None:
        self.trace.append(f"sync:{source_node_id}->{target_node_id}")
        self.evidence[source_node_id] = replace(
            self.evidence[source_node_id],
            authoritative_sha256=FINAL_DIGEST,
            source_sequence=11,
        )
        self.evidence[target_node_id] = replace(
            self.evidence[target_node_id],
            authoritative_sha256=FINAL_DIGEST,
            source_sequence=11,
        )

    def apply_fence(self, node_id: str, mode: str) -> None:
        self.trace.append(f"fence:{node_id}:{mode}")
        if node_id == "node-b" and mode == "auto" and self.fail_target_unfence:
            raise RuntimeError("simulated_target_unfence_failure")
        if mode == "isolated":
            self.evidence[node_id] = replace(self.evidence[node_id], fenced=True)
        elif mode == "auto":
            is_writer = self.membership["writer"] == node_id
            self.evidence[node_id] = replace(self.evidence[node_id], fenced=not is_writer)
        else:
            raise AssertionError(f"unexpected fence mode: {mode}")

    def verify_authoritative_write_readback(self, node_id: str) -> bool:
        self.trace.append(f"write_readback:{node_id}")
        if self.membership["writer"] != node_id or self.evidence[node_id].fenced:
            return False
        # A verified writer mutation advances the authoritative sequence.  The
        # old writer remains bound to the exact final-sync sequence.
        self.evidence[node_id] = replace(self.evidence[node_id], source_sequence=12)
        return True

    def verify_write_rejected(self, node_id: str) -> bool:
        self.trace.append(f"write_rejected:{node_id}")
        return self.membership["writer"] != node_id and self.evidence[node_id].fenced


def good_interlock(trace: list[str]):
    @contextmanager
    def _factory() -> Iterator[UpdateInterlockEvidence]:
        trace.append("interlock:enter")
        try:
            yield UpdateInterlockEvidence(lock_path="/test/update.lock", acquired=True)
        finally:
            trace.append("interlock:exit")

    return _factory


class ManualFailoverExecutorTests(unittest.TestCase):
    def test_complete_transition_holds_update_interlock_across_all_mutations(self) -> None:
        backend = FakeBackend()
        transition = execute_manual_failover(
            backend,
            target_node_id="node-b",
            transition_id="executor-test",
            interlock_factory=good_interlock(backend.trace),
        )

        self.assertEqual("completed", transition.phase)
        self.assertEqual("node-b", backend.membership["writer"])
        self.assertEqual(8, backend.membership["generation"])
        self.assertTrue(backend.evidence["node-a"].fenced)
        self.assertFalse(backend.evidence["node-b"].fenced)
        self.assertEqual("interlock:enter", backend.trace[0])
        self.assertEqual("interlock:exit", backend.trace[-1])
        self.assertLess(
            backend.trace.index("fence:node-a:isolated"),
            backend.trace.index("commit_promotion"),
        )
        self.assertLess(
            backend.trace.index("commit_promotion"),
            backend.trace.index("fence:node-b:auto"),
        )
        self.assertLess(
            backend.trace.index("fence:node-b:auto"),
            backend.trace.index("write_readback:node-b"),
        )
        self.assertIn("persist:completed", backend.trace)

    def test_target_unfence_failure_after_atomic_promotion_stays_fail_closed(self) -> None:
        backend = FakeBackend()
        backend.fail_target_unfence = True

        with self.assertRaisesRegex(RuntimeError, "simulated_target_unfence_failure"):
            execute_manual_failover(
                backend,
                target_node_id="node-b",
                transition_id="executor-fence-failure",
                interlock_factory=good_interlock(backend.trace),
            )

        self.assertEqual("node-b", backend.membership["writer"])
        self.assertEqual(8, backend.membership["generation"])
        self.assertIsNotNone(backend.transition)
        self.assertEqual("target_promoted", backend.transition["phase"])
        self.assertTrue(backend.evidence["node-a"].fenced)
        self.assertTrue(backend.evidence["node-b"].fenced)
        self.assertNotIn("write_readback:node-b", backend.trace)
        self.assertEqual("interlock:exit", backend.trace[-1])

    def test_resume_from_target_promoted_reapplies_role_fence_then_verifies(self) -> None:
        backend = FakeBackend()
        current = backend.membership
        transition = begin_manual_failover(
            current,
            target_node_id="node-b",
            source=backend.evidence["node-a"],
            target=backend.evidence["node-b"],
            transition_id="executor-resume",
        )
        backend.evidence["node-a"] = replace(backend.evidence["node-a"], service_active=False)
        transition = record_source_quiesced(transition, backend.evidence["node-a"])
        backend.evidence["node-a"] = replace(
            backend.evidence["node-a"], authoritative_sha256=FINAL_DIGEST, source_sequence=11
        )
        backend.evidence["node-b"] = replace(
            backend.evidence["node-b"], authoritative_sha256=FINAL_DIGEST, source_sequence=11
        )
        transition = record_final_sync_verified(
            transition,
            source=backend.evidence["node-a"],
            target=backend.evidence["node-b"],
        )
        backend.evidence["node-a"] = replace(backend.evidence["node-a"], fenced=True)
        transition = record_source_fenced(transition, backend.evidence["node-a"])
        transition, promoted = promote_membership(transition, current)
        backend.membership = promoted
        backend.transition = transition.as_dict()
        # Simulate a crash immediately after the atomic membership commit: the
        # target still has the old standby fence and no write was attempted.
        self.assertTrue(backend.evidence["node-b"].fenced)

        result = execute_manual_failover(
            backend,
            target_node_id="node-b",
            transition_id="executor-resume",
            interlock_factory=good_interlock(backend.trace),
        )

        self.assertEqual("completed", result.phase)
        self.assertFalse(backend.evidence["node-b"].fenced)
        self.assertEqual(0, sum(item.startswith("quiesce:") for item in backend.trace))
        self.assertEqual(0, sum(item.startswith("sync:") for item in backend.trace))
        self.assertEqual(0, backend.trace.count("commit_promotion"))
        self.assertLess(
            backend.trace.index("fence:node-b:auto"),
            backend.trace.index("write_readback:node-b"),
        )

    def test_invalid_interlock_evidence_blocks_before_transition_creation(self) -> None:
        backend = FakeBackend()

        @contextmanager
        def bad_interlock() -> Iterator[UpdateInterlockEvidence]:
            backend.trace.append("interlock:enter")
            try:
                yield UpdateInterlockEvidence(lock_path="/test/update.lock", acquired=False)
            finally:
                backend.trace.append("interlock:exit")

        with self.assertRaisesRegex(
            ManualFailoverExecutorRejected,
            "update_interlock_evidence_rejected",
        ):
            execute_manual_failover(
                backend,
                target_node_id="node-b",
                interlock_factory=bad_interlock,
            )

        self.assertIsNone(backend.transition)
        self.assertEqual(["interlock:enter", "interlock:exit"], backend.trace)

    def test_active_transition_rejects_different_target_before_side_effects(self) -> None:
        backend = FakeBackend()
        transition = begin_manual_failover(
            backend.membership,
            target_node_id="node-b",
            source=backend.evidence["node-a"],
            target=backend.evidence["node-b"],
            transition_id="executor-active",
        )
        backend.transition = transition.as_dict()

        with self.assertRaisesRegex(
            ManualFailoverExecutorRejected,
            "active_transition_target_mismatch",
        ):
            execute_manual_failover(
                backend,
                target_node_id="node-a",
                interlock_factory=good_interlock(backend.trace),
            )

        self.assertNotIn("quiesce:node-a", backend.trace)
        self.assertEqual("planned", backend.transition["phase"])


if __name__ == "__main__":
    unittest.main()
