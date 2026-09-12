from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_reconciliation_runtime import (
    HouseholdPolicyReconciliationRuntimeService,
)
from home_center.household_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DESIRED_KEY_PREFIX,
    PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_policy_verification_state import (
    ACTION,
    VERIFIED_KEY_PREFIX,
    HouseholdPolicyVerificationStateError,
    HouseholdPolicyVerificationStateService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

PARENT_ACTOR = "local-admin:admin"
CHILD_ACTOR = "local-user:child"
PARENT = "member-parent"
CHILD = "member-child"
NOW = "2026-09-12T14:10:00Z"
BACKEND = "policy-backend.readonly"


class InterruptingStore(StateStore):
    interrupt_verification_transition = False

    def transition_action_job(self, job_id: str, **kwargs):  # type: ignore[no-untyped-def]
        if (
            self.interrupt_verification_transition
            and kwargs.get("expected_state") == "running"
            and kwargs.get("new_state") == "verifying"
        ):
            self.interrupt_verification_transition = False
            raise RuntimeError("simulated verification-state interruption")
        return super().transition_action_job(job_id, **kwargs)


def _store(tmp_path: Path, *, interrupting: bool = False) -> StateStore:
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
    store_type = InterruptingStore if interrupting else StateStore
    store = store_type(tmp_path / "state.db", b"v" * 32, "cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(
            snapshot,
            (
                ActorBinding(actor=PARENT_ACTOR, member_id=PARENT),
                ActorBinding(actor=CHILD_ACTOR, member_id=CHILD),
            ),
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


class PendingReadOnlyAdapter(ExactReadOnlyAdapter):
    def read_back(self, request: dict[str, object]) -> object:
        self.calls += 1
        binding = request["binding"]
        assert isinstance(binding, dict)
        return {
            "schema": "home-center.household-policy-actual-state-observation.v1",
            "request_id": request["request_id"],
            "backend_id": request["backend_id"],
            "observed_at": NOW,
            "observed_state": "not-enforced",
            "binding": dict(binding),
            "actual_policy_sha256": None,
            "read_only": True,
        }


def _reconcile(
    store: StateStore,
    adapter: ExactReadOnlyAdapter,
) -> dict[str, object]:
    runtime = HouseholdPolicyReconciliationRuntimeService(store, now=lambda: NOW)
    runtime.register_adapter(BACKEND, adapter)
    return runtime.reconcile(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        max_observed_age_seconds=300,
        correlation_id="policy-reconcile",
    )


def _transition(
    store: StateStore,
    completion: dict[str, object],
    *,
    actor: str = PARENT_ACTOR,
) -> dict[str, object]:
    evidence = completion["evidence"]
    assert isinstance(evidence, dict)
    return HouseholdPolicyVerificationStateService(store).transition(
        actor=actor,
        request_id=str(completion["request_id"]),
        evidence_id=str(evidence["evidence_id"]),
        correlation_id="policy-verification-transition",
    )


def test_verified_evidence_persists_exact_projection_without_backend_replay_or_desired_mutation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    original_desired = _desired(store)
    adapter = ExactReadOnlyAdapter()
    completion = _reconcile(store, adapter)

    receipt = _transition(store, completion)

    assert receipt["state"] == "verified-state-persisted"
    assert receipt["enforcement_verified"] is True
    assert receipt["reconciliation_required"] is False
    assert receipt["backend_reinvoked"] is False
    assert receipt["desired_state_mutated"] is False
    assert adapter.calls == 1
    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) == original_desired

    projection = store.get_meta(VERIFIED_KEY_PREFIX + "home." + CHILD)
    assert isinstance(projection, dict)
    assert projection["enforcement_verified"] is True
    assert projection["reconciliation_required"] is False
    assert projection["desired_state"] == original_desired
    assert projection["request_id"] == completion["request_id"]
    assert projection["evidence_id"] == completion["evidence"]["evidence_id"]

    replay = _transition(store, completion)
    assert replay == receipt
    assert adapter.calls == 1
    jobs = [item for item in store.jobs() if item["job_type"] == ACTION]
    assert len(jobs) == 1
    assert jobs[0]["state"] == "succeeded"
    store.close()


def test_pending_reconciliation_cannot_create_verified_projection(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    completion = _reconcile(store, PendingReadOnlyAdapter())

    with pytest.raises(
        HouseholdPolicyVerificationStateError,
        match="household_policy_verification_reconciliation_completion_invalid",
    ):
        _transition(store, completion)

    assert store.get_meta(VERIFIED_KEY_PREFIX + "home." + CHILD) is None
    assert not [item for item in store.jobs() if item["job_type"] == ACTION]
    store.close()


def test_transition_revalidates_current_parent_authority(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    completion = _reconcile(store, ExactReadOnlyAdapter())

    with pytest.raises(
        HouseholdPolicyVerificationStateError,
        match="household_policy_verification_transition_not_authorized",
    ):
        _transition(store, completion, actor=CHILD_ACTOR)

    assert store.get_meta(VERIFIED_KEY_PREFIX + "home." + CHILD) is None
    store.close()


def test_stale_or_tampered_desired_state_fails_closed_before_projection(tmp_path: Path) -> None:
    store = _store(tmp_path)
    desired = _desired(store)
    completion = _reconcile(store, ExactReadOnlyAdapter())

    changed = dict(desired)
    changed["reason"] = "tampered"
    store.set_meta(DESIRED_KEY_PREFIX + "home." + CHILD, changed)

    with pytest.raises(
        HouseholdPolicyVerificationStateError,
        match="household_policy_verification_desired_state_stale",
    ):
        _transition(store, completion)

    assert store.get_meta(VERIFIED_KEY_PREFIX + "home." + CHILD) is None
    store.close()


@pytest.mark.parametrize(
    ("request_id", "evidence_id", "error"),
    [
        ("../../etc/passwd", "hpev-" + "0" * 24, "invalid_household_policy_verification_request_id"),
        ("hprq-" + "0" * 24, "HPEV-" + "0" * 24, "invalid_household_policy_verification_evidence_id"),
        ("hprq-" + "0" * 64, "hpev-" + "0" * 24, "invalid_household_policy_verification_request_id"),
    ],
)
def test_hostile_identifiers_are_rejected_before_store_lookup(
    tmp_path: Path,
    request_id: str,
    evidence_id: str,
    error: str,
) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyVerificationStateService(store)
    with pytest.raises(HouseholdPolicyVerificationStateError, match=error):
        service.transition(
            actor=PARENT_ACTOR,
            request_id=request_id,
            evidence_id=evidence_id,
            correlation_id="hostile-id",
        )
    store.close()


def test_interruption_after_projection_write_recovers_without_backend_replay(tmp_path: Path) -> None:
    store = _store(tmp_path, interrupting=True)
    assert isinstance(store, InterruptingStore)
    _desired(store)
    adapter = ExactReadOnlyAdapter()
    completion = _reconcile(store, adapter)
    store.interrupt_verification_transition = True

    with pytest.raises(RuntimeError, match="simulated verification-state interruption"):
        _transition(store, completion)

    projection = store.get_meta(VERIFIED_KEY_PREFIX + "home." + CHILD)
    assert isinstance(projection, dict)
    assert projection["enforcement_verified"] is True
    assert adapter.calls == 1

    receipt = _transition(store, completion)
    assert receipt["state"] == "verified-state-persisted"
    assert adapter.calls == 1
    jobs = [item for item in store.jobs() if item["job_type"] == ACTION]
    assert len(jobs) == 1
    assert jobs[0]["state"] == "succeeded"
    store.close()


def test_verified_projection_survives_state_store_backup_restore(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    completion = _reconcile(store, ExactReadOnlyAdapter())
    _transition(store, completion)
    projection = store.get_meta(VERIFIED_KEY_PREFIX + "home." + CHILD)
    assert isinstance(projection, dict)

    backup = tmp_path / "backup.db"
    store.backup_to(backup)
    store.close()

    restored = StateStore(backup, b"v" * 32, "cluster-test")
    assert restored.get_meta(VERIFIED_KEY_PREFIX + "home." + CHILD) == projection
    restored.close()


def test_projection_matches_draft_2020_12_contract(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    completion = _reconcile(store, ExactReadOnlyAdapter())
    _transition(store, completion)
    projection = store.get_meta(VERIFIED_KEY_PREFIX + "home." + CHILD)
    assert isinstance(projection, dict)

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "contracts"
        / "household"
        / "household-policy-verified-desired-state.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(projection)
    store.close()
