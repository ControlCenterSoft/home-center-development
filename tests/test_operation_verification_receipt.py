from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import unittest

from home_center.operation_commands import ACTION_ID, SYSTEMCTL
from home_center.operation_execution_receipt import OperationExecutionReceipt
from home_center.operation_verification_receipt import (
    OperationVerificationObservation,
    OperationVerificationReceiptCoordinator,
    OperationVerificationReceiptError,
)
from home_center.operation_worker_handoff import OperationWorkerIdentity
from home_center.util import canonical_json


class _VerificationStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(":memory:")
        self._connection.row_factory = sqlite3.Row
        self._audit_seq = 0
        self._connection.executescript(
            """
            CREATE TABLE jobs (
                job_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                result_json TEXT,
                evidence_json TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE operation_job_metadata (
                job_id TEXT PRIMARY KEY,
                state_version INTEGER NOT NULL,
                mutation_may_have_occurred INTEGER NOT NULL,
                recovery_required INTEGER NOT NULL,
                last_audit_event_id TEXT NOT NULL
            );
            CREATE TABLE operation_test_jobs (
                job_id TEXT PRIMARY KEY,
                job_json TEXT NOT NULL
            );
            CREATE TABLE audit (
                event_id TEXT PRIMARY KEY,
                details_json TEXT NOT NULL
            );
            CREATE TABLE operation_execution_receipts (
                receipt_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL UNIQUE,
                job_id TEXT NOT NULL UNIQUE,
                worker_id TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                from_state_version INTEGER NOT NULL,
                to_state_version INTEGER NOT NULL,
                next_state TEXT NOT NULL,
                command_sha256 TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                audit_event_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

    def _operation_job_row(self, job_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            "SELECT * FROM operation_test_jobs WHERE job_id=?",
            (job_id,),
        ).fetchone()

    @classmethod
    def _decode_operation_job(cls, row: sqlite3.Row) -> dict[str, object]:
        return json.loads(row["job_json"])

    def _append_operation_audit_locked(self, **kwargs: object) -> str:
        self._audit_seq += 1
        event_id = f"audit-{self._audit_seq}"
        self._connection.execute(
            "INSERT INTO audit(event_id,details_json) VALUES(?,?)",
            (event_id, canonical_json(kwargs)),
        )
        return event_id

    def audit_count(self) -> int:
        return self._connection.execute("SELECT COUNT(*) FROM audit").fetchone()[0]


class OperationVerificationReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = _VerificationStore()
        self.coordinator = OperationVerificationReceiptCoordinator(self.store)
        self.worker = OperationWorkerIdentity("worker-001", "home-node-a")
        self.execution_receipt = self._seed_verifying_job()

    def _seed_verifying_job(self) -> OperationExecutionReceipt:
        receipt = OperationExecutionReceipt(
            receipt_id="opreceipt-" + "a" * 24,
            claim_id="opclaim-" + "b" * 24,
            job_id="opjob-" + "c" * 24,
            action_id=ACTION_ID,
            plan_id="opcmd-" + "d" * 24,
            plan_sha256="e" * 64,
            worker_id=self.worker.worker_id,
            target_node_id=self.worker.node_id,
            command_sha256="f" * 64,
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=125,
            mutation_may_have_occurred=True,
            next_state="verifying",
            from_state_version=2,
            to_state_version=3,
            audit_event_id="audit-execution",
        )
        self.store._connection.execute(
            "INSERT INTO audit(event_id,details_json) VALUES(?,?)",
            (receipt.audit_event_id, "{}"),
        )
        value = receipt.to_dict()
        receipt_json = canonical_json(value)
        receipt_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
        self.store._connection.execute(
            """INSERT INTO operation_execution_receipts(
            receipt_id,claim_id,job_id,worker_id,plan_id,from_state_version,
            to_state_version,next_state,command_sha256,receipt_sha256,receipt_json,
            audit_event_id,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                receipt.receipt_id,
                receipt.claim_id,
                receipt.job_id,
                receipt.worker_id,
                receipt.plan_id,
                receipt.from_state_version,
                receipt.to_state_version,
                receipt.next_state,
                receipt.command_sha256,
                receipt_sha256,
                receipt_json,
                receipt.audit_event_id,
                "2026-09-10T00:00:00Z",
            ),
        )
        worker_claim = {
            "claim_id": receipt.claim_id,
            "job_id": receipt.job_id,
            "action_id": receipt.action_id,
            "plan_id": receipt.plan_id,
            "plan_sha256": receipt.plan_sha256,
            "worker_id": receipt.worker_id,
            "target_node_id": receipt.target_node_id,
            "to_state_version": receipt.from_state_version,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }
        verification = {
            "argv": [
                SYSTEMCTL,
                "show",
                "home-center.service",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=UnitFileState",
                "--no-pager",
            ],
            "timeout_seconds": 5,
            "required_active_state": "active",
        }
        plan = {
            "action_id": ACTION_ID,
            "service": "home-center.service",
            "target_node_id": receipt.target_node_id,
            "verification": verification,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }
        evidence = {
            "worker_claim": worker_claim,
            "execution_receipt": receipt.to_dict(),
        }
        job = {
            "job_id": receipt.job_id,
            "action_id": receipt.action_id,
            "state": "verifying",
            "state_version": receipt.to_state_version,
            "plan_id": receipt.plan_id,
            "plan_sha256": receipt.plan_sha256,
            "target_node_id": receipt.target_node_id,
            "service": "home-center.service",
            "correlation_id": "correlation-verification-001",
            "plan": plan,
            "result": {"execution": {"receipt_id": receipt.receipt_id}},
            "evidence": evidence,
            "mutation_may_have_occurred": True,
            "recovery_required": False,
        }
        self.store._connection.execute(
            "INSERT INTO jobs(job_id,state,result_json,evidence_json,updated_at) VALUES(?,?,?,?,?)",
            (
                receipt.job_id,
                "verifying",
                canonical_json(job["result"]),
                canonical_json(evidence),
                "2026-09-10T00:00:00Z",
            ),
        )
        self.store._connection.execute(
            """INSERT INTO operation_job_metadata(
            job_id,state_version,mutation_may_have_occurred,recovery_required,last_audit_event_id
            ) VALUES(?,?,?,?,?)""",
            (receipt.job_id, 3, 1, 0, receipt.audit_event_id),
        )
        self.store._connection.execute(
            "INSERT INTO operation_test_jobs(job_id,job_json) VALUES(?,?)",
            (receipt.job_id, canonical_json(job)),
        )
        self.store._connection.commit()
        return receipt

    @staticmethod
    def _healthy() -> OperationVerificationObservation:
        return OperationVerificationObservation(
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=80,
            load_state="loaded",
            active_state="active",
            sub_state="running",
            unit_file_state="enabled",
        )

    def _replace_job(self, mutate) -> None:
        row = self.store._operation_job_row(self.execution_receipt.job_id)
        assert row is not None
        job = self.store._decode_operation_job(row)
        mutate(job)
        self.store._connection.execute(
            "UPDATE operation_test_jobs SET job_json=? WHERE job_id=?",
            (canonical_json(job), self.execution_receipt.job_id),
        )
        self.store._connection.commit()

    def test_healthy_verification_moves_to_succeeded_without_command_material(self) -> None:
        receipt, created = self.coordinator.record(
            self.execution_receipt.receipt_id,
            worker=self.worker,
            observation=self._healthy(),
        )
        self.assertTrue(created)
        self.assertTrue(receipt.verified)
        self.assertEqual("succeeded", receipt.next_state)
        self.assertEqual(3, receipt.from_state_version)
        self.assertEqual(4, receipt.to_state_version)
        value = receipt.to_dict()
        self.assertFalse(value["contains_command_material"])
        self.assertFalse(value["accepts_caller_argv"])
        self.assertFalse(value["accepts_shell"])
        self.assertFalse(value["grants_execution_authority"])
        self.assertFalse(value["production_mutation_enabled"])
        self.assertNotIn("argv", value)
        persisted = self.store._connection.execute(
            "SELECT state FROM jobs WHERE job_id=?",
            (receipt.job_id,),
        ).fetchone()
        self.assertEqual("succeeded", persisted["state"])

    def test_unhealthy_service_requires_rollback(self) -> None:
        observation = OperationVerificationObservation(
            True, False, 0, 90, "loaded", "inactive", "dead", "enabled"
        )
        receipt, _ = self.coordinator.record(
            self.execution_receipt.receipt_id,
            worker=self.worker,
            observation=observation,
        )
        self.assertFalse(receipt.verified)
        self.assertEqual("rolling_back", receipt.next_state)

    def test_timeout_requires_rollback_without_trusting_partial_state(self) -> None:
        observation = OperationVerificationObservation(True, True, None, 5_000)
        receipt, _ = self.coordinator.record(
            self.execution_receipt.receipt_id,
            worker=self.worker,
            observation=observation,
        )
        self.assertFalse(receipt.verified)
        self.assertEqual("rolling_back", receipt.next_state)
        self.assertIsNone(receipt.active_state)

    def test_exact_replay_is_idempotent(self) -> None:
        first, created = self.coordinator.record(
            self.execution_receipt.receipt_id,
            worker=self.worker,
            observation=self._healthy(),
        )
        self.assertTrue(created)
        before = self.store.audit_count()
        second, created = self.coordinator.record(
            self.execution_receipt.receipt_id,
            worker=self.worker,
            observation=self._healthy(),
        )
        self.assertFalse(created)
        self.assertEqual(first, second)
        self.assertEqual(before, self.store.audit_count())

    def test_conflicting_replay_is_rejected(self) -> None:
        self.coordinator.record(
            self.execution_receipt.receipt_id,
            worker=self.worker,
            observation=self._healthy(),
        )
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "operation_verification_receipt_conflict",
        ):
            self.coordinator.record(
                self.execution_receipt.receipt_id,
                worker=self.worker,
                observation=OperationVerificationObservation(
                    True, False, 0, 80, "loaded", "inactive", "dead", "enabled"
                ),
            )

    def test_wrong_worker_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "operation_worker_identity_mismatch",
        ):
            self.coordinator.record(
                self.execution_receipt.receipt_id,
                worker=OperationWorkerIdentity("worker-002", "home-node-a"),
                observation=self._healthy(),
            )

    def test_stale_job_version_is_rejected(self) -> None:
        self._replace_job(lambda job: job.__setitem__("state_version", 4))
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "operation_job_state_stale",
        ):
            self.coordinator.record(
                self.execution_receipt.receipt_id,
                worker=self.worker,
                observation=self._healthy(),
            )

    def test_tampered_execution_receipt_is_rejected(self) -> None:
        self.store._connection.execute(
            "UPDATE operation_execution_receipts SET receipt_sha256=? WHERE receipt_id=?",
            ("0" * 64, self.execution_receipt.receipt_id),
        )
        self.store._connection.commit()
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "operation_verification_receipt_rejected",
        ):
            self.coordinator.record(
                self.execution_receipt.receipt_id,
                worker=self.worker,
                observation=self._healthy(),
            )

    def test_tampered_job_evidence_is_rejected(self) -> None:
        def mutate(job: dict[str, object]) -> None:
            evidence = dict(job["evidence"])
            execution = dict(evidence["execution_receipt"])
            execution["plan_sha256"] = "0" * 64
            evidence["execution_receipt"] = execution
            job["evidence"] = evidence

        self._replace_job(mutate)
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "operation_execution_receipt_evidence_mismatch",
        ):
            self.coordinator.record(
                self.execution_receipt.receipt_id,
                worker=self.worker,
                observation=self._healthy(),
            )

    def test_verification_contract_drift_is_rejected(self) -> None:
        def mutate(job: dict[str, object]) -> None:
            plan = dict(job["plan"])
            verification = dict(plan["verification"])
            verification["timeout_seconds"] = 30
            plan["verification"] = verification
            job["plan"] = plan

        self._replace_job(mutate)
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "operation_verification_contract_mismatch",
        ):
            self.coordinator.record(
                self.execution_receipt.receipt_id,
                worker=self.worker,
                observation=self._healthy(),
            )

    def test_invalid_observation_shapes_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "invalid_not_started_verification",
        ):
            OperationVerificationObservation(False, False, None, 1)
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "invalid_timeout_verification",
        ):
            OperationVerificationObservation(True, True, None, 5_000, active_state="active")
        with self.assertRaisesRegex(
            OperationVerificationReceiptError,
            "state_from_failed_verification",
        ):
            OperationVerificationObservation(True, False, 1, 25, active_state="failed")


if __name__ == "__main__":
    unittest.main()
