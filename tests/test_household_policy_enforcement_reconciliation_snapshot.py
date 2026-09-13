from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_enforcement_reconciliation_snapshot import (
    HouseholdPolicyEnforcementReconciliationSnapshotError,
    ReconciliationSnapshotPolicyAdapter,
    build_reconciliation_request_from_enforcement_snapshot,
    load_enforcement_reconciliation_snapshot,
)
from home_center.household_policy_enforcement_runtime import (
    HouseholdPolicyEnforcementError,
    HouseholdPolicyEnforcementRuntimeService,
)
from home_center.household_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

PARENT_ACTOR = "local-admin:admin"
CHILD_ACTOR = "local-user:child"
PARENT = "member-parent"
CHILD = "member-child"
BACKEND = "policy-backend.test"
ARTIFACT_SHA = "a" * 64
QUALIFICATION_SHA = "b" * 64


def _store(tmp_path: Path) -> StateStore:
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
    store = StateStore(tmp_path / "state.db", b"s" * 32, "cluster-test")
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


def _commit_desired(store: StateStore, *, reason: str = "Семейный режим") -> dict[str, object]:
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
            "reason": reason,
        },
        correlation_id="policy-plan",
    )
    return policy.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm",
    )


class QualifiedDelegate:
    policy_mutation_capable = True
    policy_backend_qualified = True
    adapter_id = BACKEND
    adapter_version = "1.0.0"
    adapter_artifact_sha256 = ARTIFACT_SHA
    qualification_evidence_sha256 = QUALIFICATION_SHA

    def __init__(
        self,
        store: StateStore,
        *,
        accepted: bool = True,
        fail: bool = False,
    ) -> None:
        self.store = store
        self.accepted = accepted
        self.fail = fail
        self.calls = 0
        self.requests: list[dict[str, object]] = []
        self.snapshot_states_at_call: list[str] = []

    def apply_policy(self, request: dict[str, object]) -> object:
        self.calls += 1
        self.requests.append(copy.deepcopy(request))
        snapshot = load_enforcement_reconciliation_snapshot(
            self.store,
            str(request["plan_id"]),
        )
        self.snapshot_states_at_call.append(str(snapshot["state"]))
        if self.fail:
            raise RuntimeError("ambiguous backend failure")
        return {"accepted": self.accepted}


class UnqualifiedDelegate(QualifiedDelegate):
    policy_backend_qualified = False


def _services(
    store: StateStore,
    *,
    accepted: bool = True,
    fail: bool = False,
) -> tuple[
    HouseholdPolicyEnforcementRuntimeService,
    ReconciliationSnapshotPolicyAdapter,
    QualifiedDelegate,
]:
    delegate = QualifiedDelegate(store, accepted=accepted, fail=fail)
    wrapper = ReconciliationSnapshotPolicyAdapter(store, BACKEND, delegate)
    enforcement = HouseholdPolicyEnforcementRuntimeService(store)
    enforcement.register_adapter(BACKEND, wrapper)
    return enforcement, wrapper, delegate


def _plan_confirm(
    enforcement: HouseholdPolicyEnforcementRuntimeService,
) -> dict[str, object]:
    plan = enforcement.plan(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        correlation_id="enforcement-plan",
    )
    confirmation = enforcement.confirm(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        confirmed=True,
        correlation_id="enforcement-confirm",
    )
    assert confirmation["backend_mutation_authorized"] is True
    return plan


def test_snapshot_is_persisted_before_mutation_and_exact_bound(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, _wrapper, delegate = _services(store)
    plan = _plan_confirm(enforcement)

    receipt = enforcement.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )
    snapshot = load_enforcement_reconciliation_snapshot(store, str(plan["plan_id"]))

    assert delegate.calls == 1
    assert delegate.snapshot_states_at_call == ["invoking"]
    assert snapshot["state"] == "completed"
    assert snapshot["backend_outcome"] == "accepted"
    assert snapshot["backend_command_accepted"] is True
    assert snapshot["desired_generation"] == plan["desired_generation"]
    assert snapshot["desired_plan_id"] == plan["desired_plan_id"]
    assert snapshot["policy_id"] == plan["policy_id"]
    assert snapshot["policy_sha256"] == plan["policy_sha256"]
    assert snapshot["desired_state_sha256"] == plan["desired_state_sha256"]
    assert snapshot["adapter_id"] == BACKEND
    assert snapshot["adapter_artifact_sha256"] == ARTIFACT_SHA
    assert snapshot["qualification_evidence_sha256"] == QUALIFICATION_SHA
    assert snapshot["enforcement_verified"] is False
    assert snapshot["reconciliation_required"] is True
    assert snapshot["automatic_retry_authorized"] is False
    assert snapshot["backend_reinvocation_authorized"] is False
    assert snapshot["infrastructure_mutation_authorized"] is False
    assert snapshot["external_publication_authorized"] is False
    assert receipt["enforcement_verified"] is False
    assert receipt["reconciliation_required"] is True

    request = snapshot["backend_request"]
    assert isinstance(request, dict)
    assert request["policy"] == delegate.requests[0]["policy"]
    assert request["secret_values_present"] is False
    assert request["automatic_retry_authorized"] is False
    assert request["infrastructure_mutation_authorized"] is False
    assert request["external_publication_authorized"] is False
    store.close()


def test_ambiguous_backend_failure_keeps_crash_safe_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, _wrapper, delegate = _services(store, fail=True)
    plan = _plan_confirm(enforcement)

    with pytest.raises(
        HouseholdPolicyEnforcementError,
        match="household_policy_enforcement_backend_outcome_ambiguous",
    ):
        enforcement.execute(
            actor=PARENT_ACTOR,
            plan_id=str(plan["plan_id"]),
            correlation_id="enforcement-execute",
        )

    snapshot = load_enforcement_reconciliation_snapshot(store, str(plan["plan_id"]))
    assert delegate.calls == 1
    assert delegate.snapshot_states_at_call == ["invoking"]
    assert snapshot["state"] == "in-doubt"
    assert snapshot["backend_outcome"] == "ambiguous"
    assert snapshot["backend_command_accepted"] is None
    assert snapshot["reconciliation_required"] is True
    assert snapshot["automatic_retry_authorized"] is False
    assert snapshot["backend_reinvocation_authorized"] is False

    with pytest.raises(
        HouseholdPolicyEnforcementError,
        match="household_policy_enforcement_reconciliation_required",
    ):
        enforcement.execute(
            actor=PARENT_ACTOR,
            plan_id=str(plan["plan_id"]),
            correlation_id="enforcement-replay",
        )
    assert delegate.calls == 1
    store.close()


def test_snapshot_remains_exact_after_new_desired_generation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, _wrapper, delegate = _services(store)
    plan = _plan_confirm(enforcement)
    enforcement.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )
    before = load_enforcement_reconciliation_snapshot(store, str(plan["plan_id"]))

    _commit_desired(store, reason="Следующая версия семейных правил")
    after = load_enforcement_reconciliation_snapshot(store, str(plan["plan_id"]))

    assert after == before
    assert after["desired_generation"] == plan["desired_generation"]
    assert after["desired_state_sha256"] == plan["desired_state_sha256"]
    assert delegate.calls == 1
    store.close()


def test_wrapper_forbids_direct_backend_reinvocation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, wrapper, delegate = _services(store)
    plan = _plan_confirm(enforcement)
    enforcement.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )
    request = delegate.requests[0]

    with pytest.raises(
        HouseholdPolicyEnforcementReconciliationSnapshotError,
        match="household_policy_enforcement_backend_reinvocation_forbidden",
    ):
        wrapper.apply_policy(request)

    assert delegate.calls == 1
    store.close()


def test_unqualified_delegate_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(
        HouseholdPolicyEnforcementReconciliationSnapshotError,
        match="invalid_household_policy_enforcement_snapshot_adapter_registration",
    ):
        ReconciliationSnapshotPolicyAdapter(store, BACKEND, UnqualifiedDelegate(store))
    store.close()


def test_tampered_snapshot_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, _wrapper, _delegate = _services(store)
    plan = _plan_confirm(enforcement)
    enforcement.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )

    key = "cozy.household.policy.enforcement-reconciliation." + str(plan["plan_id"])
    tampered = store.get_meta(key)
    assert isinstance(tampered, dict)
    tampered = copy.deepcopy(tampered)
    tampered["backend_request_sha256"] = "f" * 64
    store.set_meta(key, tampered)

    with pytest.raises(
        HouseholdPolicyEnforcementReconciliationSnapshotError,
        match="household_policy_enforcement_snapshot_invalid",
    ):
        load_enforcement_reconciliation_snapshot(store, str(plan["plan_id"]))
    store.close()


def test_snapshot_contract_is_valid_and_matches_runtime_value(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (
            root
            / "contracts"
            / "household"
            / "household-policy-enforcement-reconciliation-snapshot.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)

    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, _wrapper, _delegate = _services(store)
    plan = _plan_confirm(enforcement)
    enforcement.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )
    snapshot = load_enforcement_reconciliation_snapshot(store, str(plan["plan_id"]))
    Draft202012Validator(schema).validate(snapshot)
    store.close()


def test_new_wrapper_after_restart_still_forbids_backend_reinvocation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, _wrapper, delegate = _services(store)
    plan = _plan_confirm(enforcement)
    enforcement.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )
    request = delegate.requests[0]

    restarted_wrapper = ReconciliationSnapshotPolicyAdapter(store, BACKEND, delegate)
    with pytest.raises(
        HouseholdPolicyEnforcementReconciliationSnapshotError,
        match="household_policy_enforcement_backend_reinvocation_forbidden",
    ):
        restarted_wrapper.apply_policy(request)

    assert delegate.calls == 1
    snapshot = load_enforcement_reconciliation_snapshot(store, str(plan["plan_id"]))
    assert snapshot["backend_reinvocation_authorized"] is False
    store.close()


def test_snapshot_survives_state_store_backup_restore(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, _wrapper, _delegate = _services(store)
    plan = _plan_confirm(enforcement)
    enforcement.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )
    before = load_enforcement_reconciliation_snapshot(store, str(plan["plan_id"]))

    backup_path = tmp_path / "backup" / "state.db"
    store.backup_to(backup_path)
    store.close()

    restored = StateStore(backup_path, b"s" * 32, "cluster-test")
    after = load_enforcement_reconciliation_snapshot(restored, str(plan["plan_id"]))
    assert after == before
    restored.close()


def test_read_only_reconciliation_request_keeps_original_binding_after_desired_drift(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    enforcement, _wrapper, _delegate = _services(store)
    plan = _plan_confirm(enforcement)
    enforcement.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )

    _commit_desired(store, reason="Новая версия после исходного enforcement")
    request = build_reconciliation_request_from_enforcement_snapshot(
        store,
        str(plan["plan_id"]),
        requested_at="2026-09-12T18:40:00Z",
        max_observed_age_seconds=300,
    )

    assert request["backend_read_only_required"] is True
    assert request["backend_mutation_authorized"] is False
    assert request["infrastructure_mutation_authorized"] is False
    assert request["external_publication_authorized"] is False
    binding = request["binding"]
    assert isinstance(binding, dict)
    assert binding["household_id"] == plan["household_id"]
    assert binding["member_id"] == plan["member_id"]
    assert binding["desired_generation"] == plan["desired_generation"]
    assert binding["desired_plan_id"] == plan["desired_plan_id"]
    assert binding["policy_id"] == plan["policy_id"]
    assert binding["policy_sha256"] == plan["policy_sha256"]

    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "contracts"
            / "household"
            / "household-policy-reconciliation-request.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(request)
    store.close()
