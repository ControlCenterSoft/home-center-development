from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import unittest

from home_center.operation_commands import ACTION_ID, SYSTEMCTL
from home_center.operation_rollback_claim import (
    OperationRollbackClaimCoordinator,
    OperationRollbackClaimError,
    revalidate_operation_rollback_claim,
)
from home_center.operation_verification_receipt import OperationVerificationReceipt
from home_center.operation_worker_handoff import OperationWorkerIdentity
from home_center.util import canonical_json


class _RollbackStore:
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
                recovery_json TEXT NOT NULL,
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
            CREATE TABLE operation_verification_receipts (
                receipt_id TEXT PRIMARY KEY,
                execution_receipt_id TEXT NOT NULL UNIQUE,
                job_id TEXT NOT NULL UNIQUE,
                worker_id TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                from_state_version INTEGER NOT NULL,
                to_state_version INTEGER NOT NULL,
                next_state TEXT NOT NULL,
                verification_sha256 TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                audit_event_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

    def _operation_job_row(self, job_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            """SELECT t.job_json,j.state,j.result_json,j.evidence_json,j.recovery_json,
            m.state_version,m.mutation_may_have_occurred,m.recovery_required,
            m.last_audit_event_id
            FROM operation_test_jobs AS t
            JOIN jobs AS j ON j.job_id=t.job_id
            JOIN operation_job_metadata AS m ON m.job_id=t.job_id
            WHERE t.job_id=?""",
            (job_id,),
        ).fetchone()

    @classmethod
    def _decode_operation_job(cls, row: sqlite3.Row) -> dict[str, object]:
        job = json.loads(row["job_json"])
        job["state"] = row["state"]
        job["state_version"] = row["state_version"]
        job["result"] = json.loads(row["result_json"]) if row["result_json"] else None
        job["evidence"] = json.loads(row["evidence_json"]) if row["evidence_json"] else None
        job["recovery"] = json.loads(row["recovery_json"])
        job["mutation_may_have_occurred"] = bool(row["mutation_may_have_occurred"])
        job["recovery_required"] = bool(row["recovery_required"])
        job["last_audit_event_id"] = row["last_audit_event_id"]
        return job

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


class OperationRollbackClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = _RollbackStore()
        self.coordinator = OperationRollbackClaimCoordinator(self.store)
        self.worker = OperationWorkerIdentity("worker-001", "home-node-a")
        self.receipt = self._seed_rolling_back_job()

    def _seed_rolling_back_job(
        self,
        *,
        expected_active_state: str = "active",
    ) -> OperationVerificationReceipt:
        recovery_verb = "start" if expected_active_state == "active" else "stop"
        recovery = {
            "strategy": "restore-observed-active-state",
            "argv": [SYSTEMCTL, recovery_verb, "home-center.service"],
            "timeout_seconds": 15,
            "expected_active_state": expected_active_state,
            "verification_required": True,
        }
        plan = {
            "schema": "home-center.operation-command-plan.v1",
            "plan_id": "opcmd-" + "d" * 24,
            "request_sha256": "1" * 64,
            "action_id": ACTION_ID,
            "authorization_id": "opauth-" + "2" * 24,
            "idempotency_key": "operation-restart-001",
            "target_node_id": self.worker.node_id,
            "service": "home-center.service",
            "snapshot_sha256": "3" * 64,
            "execution": {
                "executable": SYSTEMCTL,
                "argv": [SYSTEMCTL, "restart", "home-center.service"],
                "timeout_seconds": 15,
                "shell": False,
            },
            "verification": {
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
            },
            "recovery": recovery,
            "audit": {
                "required": True,
                "correlation_id": "correlation-rollback-001",
                "reason": "bounded rollback claim test",
            },
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }
        plan_sha256 = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
        receipt = OperationVerificationReceipt(
            receipt_id="opverify-" + "a" * 24,
            execution_receipt_id="opreceipt-" + "b" * 24,
            job_id="opjob-" + "c" * 24,
            action_id=ACTION_ID,
            plan_id=plan["plan_id"],
            plan_sha256=plan_sha256,
            worker_id=self.worker.worker_id,
            target_node_id=self.worker.node_id,
            verification_sha256="4" * 64,
            started=True,
            timed_out=False,
            exit_code=0,
            elapsed_ms=90,
            load_state="loaded",
            active_state="inactive",
            sub_state="dead",
            unit_file_state="enabled",
            verified=False,
            next_state="rolling_back",
            from_state_version=3,
            to_state_version=4,
            audit_event_id="audit-verification",
        )
        self.store._connection.execute(
            "INSERT INTO audit(event_id,details_json) VALUES(?,?)",
            (receipt.audit_event_id, "{}"),
        )
        receipt_json = canonical_json(receipt.to_dict())
        receipt_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
        self.store._connection.execute(
            """INSERT INTO operation_verification_receipts(
            receipt_id,execution_receipt_id,job_id,worker_id,plan_id,from_state_version,
            to_state_version,next_state,verification_sha256,receipt_sha256,receipt_json,
            audit_event_id,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                receipt.receipt_id,
                receipt.execution_receipt_id,
                receipt.job_id,
                receipt.worker_id,
                receipt.plan_id,
                receipt.from_state_version,
                receipt.to_state_version,
                receipt.next_state,
                receipt.verification_sha256,
                receipt_sha256,
                receipt_json,
                receipt.audit_event_id,
                "2026-09-10T00:00:00Z",
            ),
        )
        worker_claim = {
            "claim_id": "opclaim-" + "5" * 24,
            "job_id": receipt.job_id,
            "action_id": receipt.action_id,
            "plan_id": receipt.plan_id,
            "plan_sha256": receipt.plan_sha256,
            "worker_id": receipt.worker_id,
            "target_node_id": receipt.target_node_id,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }
        execution_receipt = {
            "receipt_id": receipt.execution_receipt_id,
            "job_id": receipt.job_id,
            "action_id": receipt.action_id,
            "plan_id": receipt.plan_id,
            "plan_sha256": receipt.plan_sha256,
            "worker_id": receipt.worker_id,
            "target_node_id": receipt.target_node_id,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }
        evidence = {
            "worker_claim": worker_claim,
            "execution_receipt": execution_receipt,
            "verification_receipt": receipt.to_dict(),
        }
        job = {
            "job_id": receipt.job_id,
            "action_id": receipt.action_id,
            "state": "rolling_back",
            "state_version": 4,
            "plan_id": receipt.plan_id,
            "plan_sha256": receipt.plan_sha256,
            "target_node_id": receipt.target_node_id,
            "service": "home-center.service",
            "correlation_id": "correlation-rollback-001",
            "plan": plan,
            "result": {
                "verification": {
                    "receipt_id": receipt.receipt_id,
                    "verified": False,
                }
            },
            "evidence": evidence,
            "recovery": recovery,
            "mutation_may_have_occurred": True,
            "recovery_required": False,
        }
        self.store._connection.execute(
            """INSERT INTO jobs(
            job_id,state,result_json,evidence_json,recovery_json,updated_at
            ) VALUES(?,?,?,?,?,?)""",
            (
                receipt.job_id,
                "rolling_back",
                canonical_json(job["result"]),
                canonical_json(evidence),
                canonical_json(recovery),
                "2026-09-10T00:00:00Z",
            ),
        )
        self.store._connection.execute(
            """INSERT INTO operation_job_metadata(
            job_id,state_version,mutation_may_have_occurred,recovery_required,last_audit_event_id
            ) VALUES(?,?,?,?,?)""",
            (receipt.job_id, 4, 1, 0, receipt.audit_event_id),
        )
        self.store._connection.execute(
            "INSERT INTO operation_test_jobs(job_id,job_json) VALUES(?,?)",
            (receipt.job_id, canonical_json(job)),
        )
        self.store._connection.commit()
        return receipt

    def test_claim_binds_exact_recovery_without_command_material(self) -> None:
        claim, created = self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)
        self.assertTrue(created)
        self.assertEqual("rolling_back", claim.state)
        self.assertEqual("active", claim.expected_active_state)
        self.assertEqual(4, claim.from_state_version)
        self.assertEqual(5, claim.to_state_version)
        value = claim.to_dict()
        self.assertFalse(value["contains_command_material"])
        self.assertFalse(value["accepts_caller_argv"])
        self.assertFalse(value["accepts_shell"])
        self.assertFalse(value["execution_authorized"])
        self.assertFalse(value["production_mutation_enabled"])
        self.assertNotIn("argv", value)
        row = self.store._operation_job_row(claim.job_id)
        assert row is not None
        job = self.store._decode_operation_job(row)
        self.assertEqual("rolling_back", job["state"])
        self.assertEqual(5, job["state_version"])
        self.assertEqual(value, job["evidence"]["rollback_claim"])
        revalidate_operation_rollback_claim(self.store, claim)

    def test_exact_replay_is_idempotent(self) -> None:
        first, created = self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)
        self.assertTrue(created)
        before = self.store.audit_count()
        second, created = self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)
        self.assertFalse(created)
        self.assertEqual(first, second)
        self.assertEqual(before, self.store.audit_count())

    def test_wrong_worker_cannot_take_over_rollback(self) -> None:
        with self.assertRaisesRegex(
            OperationRollbackClaimError,
            "operation_worker_identity_mismatch",
        ):
            self.coordinator.claim(
                self.receipt.receipt_id,
                worker=OperationWorkerIdentity("worker-002", self.worker.node_id),
            )

    def test_stale_state_version_is_rejected(self) -> None:
        self.store._connection.execute(
            "UPDATE operation_job_metadata SET state_version=5 WHERE job_id=?",
            (self.receipt.job_id,),
        )
        self.store._connection.commit()
        with self.assertRaisesRegex(OperationRollbackClaimError, "operation_job_state_stale"):
            self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)

    def test_recovery_contract_drift_is_rejected(self) -> None:
        recovery = {
            "strategy": "restore-observed-active-state",
            "argv": [SYSTEMCTL, "restart", "home-center.service"],
            "timeout_seconds": 15,
            "expected_active_state": "active",
            "verification_required": True,
        }
        self.store._connection.execute(
            "UPDATE jobs SET recovery_json=? WHERE job_id=?",
            (canonical_json(recovery), self.receipt.job_id),
        )
        self.store._connection.commit()
        with self.assertRaisesRegex(
            OperationRollbackClaimError,
            "operation_recovery_contract_mismatch",
        ):
            self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)

    def test_prior_evidence_drift_is_rejected(self) -> None:
        row = self.store._operation_job_row(self.receipt.job_id)
        assert row is not None
        job = self.store._decode_operation_job(row)
        evidence = dict(job["evidence"])
        execution = dict(evidence["execution_receipt"])
        execution["plan_sha256"] = "0" * 64
        evidence["execution_receipt"] = execution
        self.store._connection.execute(
            "UPDATE jobs SET evidence_json=? WHERE job_id=?",
            (canonical_json(evidence), self.receipt.job_id),
        )
        self.store._connection.commit()
        with self.assertRaisesRegex(
            OperationRollbackClaimError,
            "operation_execution_receipt_plan_integrity_mismatch",
        ):
            self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)

    def test_tampered_verification_receipt_is_rejected(self) -> None:
        self.store._connection.execute(
            "UPDATE operation_verification_receipts SET receipt_sha256=? WHERE receipt_id=?",
            ("0" * 64, self.receipt.receipt_id),
        )
        self.store._connection.commit()
        with self.assertRaisesRegex(
            OperationRollbackClaimError,
            "operation_rollback_claim_rejected",
        ):
            self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)

    def test_revalidation_fails_after_state_progress(self) -> None:
        claim, _ = self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)
        self.store._connection.execute(
            "UPDATE jobs SET state='rolled_back' WHERE job_id=?",
            (claim.job_id,),
        )
        self.store._connection.execute(
            "UPDATE operation_job_metadata SET state_version=6 WHERE job_id=?",
            (claim.job_id,),
        )
        self.store._connection.commit()
        with self.assertRaisesRegex(OperationRollbackClaimError, "operation_rollback_claim_stale"):
            revalidate_operation_rollback_claim(self.store, claim)

    def test_revalidation_rejects_prior_evidence_drift_after_claim(self) -> None:
        claim, _ = self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)
        row = self.store._operation_job_row(claim.job_id)
        assert row is not None
        job = self.store._decode_operation_job(row)
        evidence = dict(job["evidence"])
        execution = dict(evidence["execution_receipt"])
        execution["plan_sha256"] = "0" * 64
        evidence["execution_receipt"] = execution
        self.store._connection.execute(
            "UPDATE jobs SET evidence_json=? WHERE job_id=?",
            (canonical_json(evidence), claim.job_id),
        )
        self.store._connection.commit()
        with self.assertRaisesRegex(
            OperationRollbackClaimError,
            "operation_execution_receipt_plan_integrity_mismatch",
        ):
            revalidate_operation_rollback_claim(self.store, claim)

    def test_tampered_claim_storage_is_rejected(self) -> None:
        claim, _ = self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)
        self.store._connection.execute(
            "UPDATE operation_rollback_claims SET claim_sha256=? WHERE claim_id=?",
            ("0" * 64, claim.claim_id),
        )
        self.store._connection.commit()
        with self.assertRaisesRegex(
            OperationRollbackClaimError,
            "operation_rollback_claim_integrity_mismatch",
        ):
            revalidate_operation_rollback_claim(self.store, claim)

    def test_inactive_original_state_binds_stop_recovery(self) -> None:
        store = _RollbackStore()
        coordinator = OperationRollbackClaimCoordinator(store)
        self.store = store
        self.coordinator = coordinator
        self.receipt = self._seed_rolling_back_job(expected_active_state="inactive")
        claim, _ = coordinator.claim(self.receipt.receipt_id, worker=self.worker)
        self.assertEqual("inactive", claim.expected_active_state)
        row = store._operation_job_row(claim.job_id)
        assert row is not None
        job = store._decode_operation_job(row)
        self.assertEqual([SYSTEMCTL, "stop", "home-center.service"], job["recovery"]["argv"])

    def test_claim_evidence_cannot_grant_privileged_authority(self) -> None:
        claim, _ = self.coordinator.claim(self.receipt.receipt_id, worker=self.worker)
        value = claim.to_dict()
        for key in (
            "contains_command_material",
            "accepts_caller_argv",
            "accepts_shell",
            "execution_authorized",
            "production_mutation_enabled",
        ):
            self.assertIs(value[key], False)


if __name__ == "__main__":
    unittest.main()
