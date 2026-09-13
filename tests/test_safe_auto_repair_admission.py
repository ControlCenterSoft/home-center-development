from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_admission import (
    SafeAutoRepairAdmissionError,
    SafeAutoRepairAdmissionService,
)
from home_center.store import StateStore


ROOT = Path(__file__).resolve().parents[1]


def _candidate(*, generation: int = 7, evidence: str = "a" * 64, recovery: bool = True) -> RepairCandidate:
    return RepairCandidate(
        household_id="home-main",
        resource_id="household-derived-index",
        resource_generation=generation,
        evidence_sha256=evidence,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=RepairRisk.LOW,
        recovery_proven=recovery,
        post_condition_verifiable=True,
    )


def _policy(*, digest: str = "b" * 64) -> SafeRepairPolicy:
    return SafeRepairPolicy(
        policy_id="safe-default",
        policy_sha256=digest,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        allowed_risks=frozenset({RepairRisk.LOW}),
    )


def _recommendation(candidate: RepairCandidate | None = None, policy: SafeRepairPolicy | None = None):
    candidate = candidate or _candidate()
    policy = policy or _policy()
    return candidate, policy, evaluate_safe_auto_repair(candidate=candidate, policy=policy)


def test_exact_eligible_recommendation_admits_one_nonexecuting_typed_job(tmp_path) -> None:
    candidate, policy, recommendation = _recommendation()
    store = StateStore(tmp_path / "state.db", b"a" * 32, "cluster-test")
    try:
        service = SafeAutoRepairAdmissionService(store)
        receipt = service.admit(
            actor="parent-session",
            correlation_id="corr-repair-admit-1",
            recommendation=recommendation,
            current_candidate=candidate,
            current_policy=policy,
            idempotency_key="repair-admit-0001",
        )
        assert receipt.required_job_type == "safe-auto-repair-rebuild-derived-index-job"
        assert receipt.state == "preflight"
        assert receipt.execution_authorized is False
        assert receipt.post_condition_verified is False
        assert receipt.repair_success_claimed is False
        assert receipt.provider_execution_authorized is False
        assert receipt.infrastructure_mutation_authorized is False
        assert receipt.external_publication_authorized is False

        job = store.job(receipt.job_id)
        assert job is not None
        assert job["job_type"] == receipt.required_job_type
        assert job["state"] == "preflight"
        assert job["result"] is None
        assert job["evidence"] is None
        assert job["steps"] == [
            {"state": "succeeded", "step": "recommendation-revalidate"},
            {"state": "pending", "step": "typed-repair-execute"},
            {"state": "pending", "step": "authoritative-readback"},
            {"state": "pending", "step": "post-condition-verify"},
            {"state": "pending", "step": "repair-history-record"},
        ]
        assert job["preflight"]["recommendation"] == recommendation.to_dict()
        assert job["preflight"]["execution_authorized"] is False
        assert job["preflight"]["post_condition_verification_required"] is True
        assert job["preflight"]["repair_history_required"] is True

        events = store.audit_events()
        matching = [event for event in events if event["action"] == "automation.safe-auto-repair.admit"]
        assert len(matching) == 1
        details = matching[0]["details"]
        assert details["recommendation_id"] == recommendation.recommendation_id
        assert details["execution_authorized"] is False
        assert details["post_condition_verified"] is False
        assert details["repair_success_claimed"] is False
        store.verify_audit_chain()
    finally:
        store.close()


def test_blocked_recommendation_is_rejected_before_job_creation(tmp_path) -> None:
    candidate, policy, recommendation = _recommendation(candidate=_candidate(recovery=False))
    assert recommendation.eligible_for_auto_repair is False
    store = StateStore(tmp_path / "state.db", b"b" * 32, "cluster-test")
    try:
        service = SafeAutoRepairAdmissionService(store)
        with pytest.raises(SafeAutoRepairAdmissionError, match="safe_auto_repair_admission_recommendation_blocked"):
            service.admit(
                actor="parent-session",
                correlation_id="corr-repair-admit-2",
                recommendation=recommendation,
                current_candidate=candidate,
                current_policy=policy,
                idempotency_key="repair-admit-0002",
            )
        assert store.jobs() == []
        assert not any(event["action"] == "automation.safe-auto-repair.admit" for event in store.audit_events())
    finally:
        store.close()


def test_current_generation_or_evidence_drift_fails_closed_before_job_creation(tmp_path) -> None:
    candidate, policy, recommendation = _recommendation()
    store = StateStore(tmp_path / "state.db", b"c" * 32, "cluster-test")
    try:
        service = SafeAutoRepairAdmissionService(store)
        current = _candidate(generation=candidate.resource_generation + 1, evidence="c" * 64)
        with pytest.raises(SafeAutoRepairAdmissionError, match="safe_auto_repair_admission_recommendation_stale"):
            service.admit(
                actor="parent-session",
                correlation_id="corr-repair-admit-3",
                recommendation=recommendation,
                current_candidate=current,
                current_policy=policy,
                idempotency_key="repair-admit-0003",
            )
        assert store.jobs() == []
    finally:
        store.close()


def test_current_policy_drift_fails_closed_before_job_creation(tmp_path) -> None:
    candidate, policy, recommendation = _recommendation()
    store = StateStore(tmp_path / "state.db", b"d" * 32, "cluster-test")
    try:
        service = SafeAutoRepairAdmissionService(store)
        changed_policy = _policy(digest="d" * 64)
        with pytest.raises(SafeAutoRepairAdmissionError, match="safe_auto_repair_admission_recommendation_stale"):
            service.admit(
                actor="parent-session",
                correlation_id="corr-repair-admit-4",
                recommendation=recommendation,
                current_candidate=candidate,
                current_policy=changed_policy,
                idempotency_key="repair-admit-0004",
            )
        assert store.jobs() == []
    finally:
        store.close()


def test_exact_replay_returns_same_job_without_duplicate(tmp_path) -> None:
    candidate, policy, recommendation = _recommendation()
    store = StateStore(tmp_path / "state.db", b"e" * 32, "cluster-test")
    try:
        service = SafeAutoRepairAdmissionService(store)
        first = service.admit(
            actor="parent-session",
            correlation_id="corr-repair-admit-5",
            recommendation=recommendation,
            current_candidate=candidate,
            current_policy=policy,
            idempotency_key="repair-admit-replay",
        )
        second = service.admit(
            actor="parent-session",
            correlation_id="corr-repair-admit-6",
            recommendation=recommendation,
            current_candidate=candidate,
            current_policy=policy,
            idempotency_key="repair-admit-replay",
        )
        assert second.job_id == first.job_id
        jobs = [job for job in store.jobs() if job["job_type"] == first.required_job_type]
        assert len(jobs) == 1
    finally:
        store.close()


def test_recovery_after_store_reopen_is_read_only_and_exact(tmp_path) -> None:
    candidate, policy, recommendation = _recommendation()
    path = tmp_path / "state.db"
    key = b"f" * 32
    store = StateStore(path, key, "cluster-test")
    service = SafeAutoRepairAdmissionService(store)
    receipt = service.admit(
        actor="parent-session",
        correlation_id="corr-repair-admit-7",
        recommendation=recommendation,
        current_candidate=candidate,
        current_policy=policy,
        idempotency_key="repair-admit-recover",
    )
    audit_count = len(store.audit_events())
    store.close()

    reopened = StateStore(path, key, "cluster-test")
    try:
        recovered = SafeAutoRepairAdmissionService(reopened).recover(receipt.job_id)
        assert recovered.to_dict() == receipt.to_dict()
        assert len(reopened.jobs()) == 1
        assert len(reopened.audit_events()) == audit_count
        reopened.verify_audit_chain()
    finally:
        reopened.close()


def test_admission_receipt_matches_closed_public_schema(tmp_path) -> None:
    candidate, policy, recommendation = _recommendation()
    store = StateStore(tmp_path / "state.db", b"g" * 32, "cluster-test")
    try:
        receipt = SafeAutoRepairAdmissionService(store).admit(
            actor="parent-session",
            correlation_id="corr-repair-admit-8",
            recommendation=recommendation,
            current_candidate=candidate,
            current_policy=policy,
            idempotency_key="repair-admit-schema",
        )
        schema = json.loads(
            (ROOT / "contracts/automation/safe-auto-repair-admission.v1.schema.json").read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator(schema).validate(receipt.to_dict())
    finally:
        store.close()
