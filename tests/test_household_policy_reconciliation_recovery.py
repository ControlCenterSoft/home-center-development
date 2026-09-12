from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_reconciliation_recovery import (
    RECOVERY_EVIDENCE_SCHEMA,
    RECOVERY_FAILURE_SCHEMA,
    HouseholdPolicyReconciliationRecoveryService,
)
from home_center.household_policy_reconciliation_runtime import (
    ACTION,
    HouseholdPolicyReconciliationRuntimeService,
    STATE_KEY_PREFIX,
)
from home_center.household_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DESIRED_KEY_PREFIX,
    PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

PARENT_ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
NOW = "2026-09-12T13:30:00Z"
BACKEND = "policy-backend.readonly"
KEY = b"r" * 32


def _store(path: Path) -> StateStore:
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id=PARENT, display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id=CHILD, display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    reference = HouseholdStore()
    reference.create(household)
    snapshot = reference.read("home")
    store = StateStore(path, KEY, "cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(
            snapshot,
            (ActorBinding(actor=PARENT_ACTOR, member_id=PARENT),),
        ),
    )
    return store


def _desired(store: StateStore) -> dict[str, object]:
    policy = HouseholdPolicyRuntimeService(store)
    plan = policy.plan(
        actor=PARENT_ACTOR,
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "subject_member_id": CHILD,
            "bundle": {
                "internet_policy": "guest",
                "vpn_allowed": False,
                "managed_device_required": True,
                "home_files_allowed": False,
                "smart_home_control_allowed": False,
                "administration_allowed": False,
                "external_publication_allowed": False,
            },
            "reason": "Вечерний семейный режим",
        },
        correlation_id="policy-plan",
    )
    policy.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm",
    )
    desired = store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD)
    assert isinstance(desired, dict)
    return desired


class ExactReadOnlyAdapter:
    reconciliation_read_only = True

    def __init__(self) -> None:
        self.calls = 0

    def read_back(self, request: dict[str, object]) -> object:
        self.calls += 1
        binding = request["binding"]
        assert isinstance(binding, dict)
        return {
            "schema": "home-center.household-policy-actual-state-observation.v1",
            "request_id": request["request_id"],
            "backend_id": request["backend_id"],
            "observed_at": NOW,
            "observed_state": "enforced",
            "binding": dict(binding),
            "actual_policy_sha256": binding["policy_sha256"],
            "read_only": True,
        }


def _interrupt_after_evidence(
    store: StateStore,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[HouseholdPolicyReconciliationRuntimeService, ExactReadOnlyAdapter]:
    adapter = ExactReadOnlyAdapter()
    service = HouseholdPolicyReconciliationRuntimeService(store, now=lambda: NOW)
    service.register_adapter(BACKEND, adapter)
    original_transition = store.transition_action_job

    def interrupted_transition(job_id: str, **kwargs):
        if kwargs.get("expected_state") == "verifying" and kwargs.get("new_state") == "succeeded":
            raise RuntimeError("simulated-process-loss-after-evidence-persist")
        return original_transition(job_id, **kwargs)

    monkeypatch.setattr(store, "transition_action_job", interrupted_transition)
    with pytest.raises(RuntimeError, match="simulated-process-loss-after-evidence-persist"):
        service.reconcile(
            actor=PARENT_ACTOR,
            member_id=CHILD,
            backend_id=BACKEND,
            max_observed_age_seconds=300,
            correlation_id="policy-reconcile-crash",
        )
    monkeypatch.setattr(store, "transition_action_job", original_transition)
    assert adapter.calls == 1
    return service, adapter


def _reconciliation_envelope(store: StateStore) -> tuple[str, dict[str, object]]:
    connection = getattr(store, "_connection")
    row = connection.execute(
        "SELECT key FROM cluster_meta WHERE key LIKE ? ORDER BY key LIMIT 1",
        (STATE_KEY_PREFIX + "%",),
    ).fetchone()
    assert row is not None
    key = str(row["key"])
    envelope = store.get_meta(key)
    assert isinstance(envelope, dict)
    return key, envelope


def test_recovery_finalizes_persisted_evidence_without_backend_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path / "state.db")
    original_desired = _desired(store)
    service, adapter = _interrupt_after_evidence(store, monkeypatch)

    state_key, interrupted = _reconciliation_envelope(store)
    assert interrupted["status"] == "evidence-persisted"
    persisted_evidence = interrupted["evidence"]
    job = store.job(str(interrupted["job_id"]))
    assert job is not None and job["state"] == "verifying"

    recovered = HouseholdPolicyReconciliationRecoveryService(store).recover_incomplete()
    assert recovered == 1
    assert adapter.calls == 1

    completed = store.get_meta(state_key)
    assert isinstance(completed, dict)
    assert completed["status"] == "completed"
    assert completed["evidence"] == persisted_evidence
    assert completed["recovery_failure"] is None
    assert completed["completion"]["state"] == "verified"
    assert completed["completion"]["desired_state_transition_performed"] is False
    recovered_job = store.job(str(interrupted["job_id"]))
    assert recovered_job is not None and recovered_job["state"] == "succeeded"
    assert recovered_job["evidence"]["schema"] == RECOVERY_EVIDENCE_SCHEMA
    assert recovered_job["evidence"]["backend_reinvoked"] is False
    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) == original_desired

    replay = service.reconcile(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        max_observed_age_seconds=300,
        correlation_id="policy-reconcile-replay",
    )
    assert replay == completed["completion"]
    assert adapter.calls == 1
    store.close()


def test_recovery_blocks_on_desired_state_drift_but_preserves_verified_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path / "state.db")
    _desired(store)
    _service, adapter = _interrupt_after_evidence(store, monkeypatch)
    state_key, interrupted = _reconciliation_envelope(store)
    persisted_evidence = interrupted["evidence"]

    desired_key = DESIRED_KEY_PREFIX + "home." + CHILD
    changed = store.get_meta(desired_key)
    assert isinstance(changed, dict)
    changed = dict(changed)
    changed["generation"] = int(changed["generation"]) + 1
    store.set_meta(desired_key, changed)

    recovered = HouseholdPolicyReconciliationRecoveryService(store).recover_incomplete()
    assert recovered == 0
    assert adapter.calls == 1

    blocked = store.get_meta(state_key)
    assert isinstance(blocked, dict)
    assert blocked["status"] == "recovery-blocked"
    assert blocked["evidence"] == persisted_evidence
    assert blocked["recovery_failure"]["schema"] == RECOVERY_FAILURE_SCHEMA
    assert blocked["recovery_failure"]["code"] == (
        "household_policy_reconciliation_recovery_desired_state_stale"
    )
    job = store.job(str(interrupted["job_id"]))
    assert job is not None and job["state"] == "failed"
    assert job["evidence"]["reconciliation_evidence"] == persisted_evidence
    assert job["evidence"]["backend_reinvoked"] is False
    store.close()


def test_backup_restore_preserves_interrupted_reconciliation_for_safe_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _store(tmp_path / "source.db")
    original_desired = _desired(source)
    _service, adapter = _interrupt_after_evidence(source, monkeypatch)
    state_key, interrupted = _reconciliation_envelope(source)
    persisted_evidence = interrupted["evidence"]

    backup = tmp_path / "backup.db"
    source.backup_to(backup)
    source.close()

    restored = StateStore(backup, KEY, "cluster-test")
    restored_envelope = restored.get_meta(state_key)
    assert isinstance(restored_envelope, dict)
    assert restored_envelope["status"] == "evidence-persisted"
    assert restored_envelope["evidence"] == persisted_evidence
    assert restored.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) == original_desired

    recovered = HouseholdPolicyReconciliationRecoveryService(restored).recover_incomplete()
    assert recovered == 1
    assert adapter.calls == 1

    job = restored.job(str(interrupted["job_id"]))
    assert job is not None and job["state"] == "succeeded"
    assert job["evidence"]["schema"] == RECOVERY_EVIDENCE_SCHEMA
    assert job["evidence"]["recovered_after_interruption"] is True
    assert job["evidence"]["backend_reinvoked"] is False
    desired = restored.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD)
    assert isinstance(desired, dict)
    assert desired["enforcement_verified"] is False
    assert desired["reconciliation_required"] is True
    restored.close()
