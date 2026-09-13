from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_effective_state import (
    STATUS_SCHEMA,
    HouseholdPolicyEffectiveStateError,
    HouseholdPolicyEffectiveStateService,
)
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
    VERIFIED_KEY_PREFIX,
    HouseholdPolicyVerificationStateService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

PARENT_ACTOR = "local-admin:admin"
CHILD_ACTOR = "local-user:child"
PARENT = "member-parent"
CHILD = "member-child"
BACKEND = "policy-backend.readonly"
NOW = "2026-09-12T14:40:00Z"


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


def _bundle() -> dict[str, object]:
    return {
        "internet_policy": "guest",
        "vpn_allowed": False,
        "managed_device_required": True,
        "home_files_allowed": False,
        "smart_home_control_allowed": False,
        "administration_allowed": False,
        "external_publication_allowed": False,
    }


def _desired(store: StateStore, *, reason: str) -> dict[str, object]:
    runtime = HouseholdPolicyRuntimeService(store)
    plan = runtime.plan(
        actor=PARENT_ACTOR,
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "subject_member_id": CHILD,
            "bundle": _bundle(),
            "reason": reason,
        },
        correlation_id="policy-plan",
    )
    runtime.confirm(
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


def _verified(store: StateStore) -> tuple[dict[str, object], ExactReadOnlyAdapter]:
    adapter = ExactReadOnlyAdapter()
    reconciliation = HouseholdPolicyReconciliationRuntimeService(store, now=lambda: NOW)
    reconciliation.register_adapter(BACKEND, adapter)
    completion = reconciliation.reconcile(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        max_observed_age_seconds=300,
        correlation_id="policy-reconcile",
    )
    evidence = completion["evidence"]
    assert isinstance(evidence, dict)
    HouseholdPolicyVerificationStateService(store).transition(
        actor=PARENT_ACTOR,
        request_id=str(completion["request_id"]),
        evidence_id=str(evidence["evidence_id"]),
        correlation_id="policy-verified-state",
    )
    return completion, adapter


def _validate_contract(value: dict[str, object]) -> None:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "contracts/household/household-policy-effective-state.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(value)


def test_role_default_projection_is_read_only_and_self_visible(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyEffectiveStateService(store)

    state = service.read(actor=CHILD_ACTOR, member_id=CHILD)

    assert state["schema"] == STATUS_SCHEMA
    assert state["source"] == "role-preset"
    assert state["state"] == "role-default"
    assert state["desired_generation"] == 0
    assert state["enforcement_verified"] is False
    assert state["reconciliation_required"] is False
    assert state["verified_evidence"] is None
    assert state["technical_policy"]["internet_policy"] == "filtered"
    assert state["technical_policy"]["external_publication_allowed"] is False
    assert "семейной фильтрацией" in state["explanation_ru"]
    _validate_contract(state)
    store.close()


def test_non_parent_cannot_read_another_members_policy(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyEffectiveStateService(store)

    with pytest.raises(
        HouseholdPolicyEffectiveStateError,
        match="household_policy_effective_state_not_authorized",
    ):
        service.read(actor=CHILD_ACTOR, member_id=PARENT)

    store.close()


def test_parent_reads_pending_composed_policy_without_false_success(tmp_path: Path) -> None:
    store = _store(tmp_path)
    desired = _desired(store, reason="Вечерний режим")

    state = HouseholdPolicyEffectiveStateService(store).read(
        actor=PARENT_ACTOR,
        member_id=CHILD,
    )

    assert state["source"] == "composed-desired"
    assert state["state"] == "pending-reconciliation"
    assert state["desired_generation"] == desired["generation"]
    assert state["technical_policy"]["policy_id"] == desired["policy"]["policy_id"]
    assert state["enforcement_verified"] is False
    assert state["reconciliation_required"] is True
    assert state["verified_evidence"] is None
    assert state["production_mutation_enabled"] is False
    _validate_contract(state)
    store.close()


def test_exact_verified_projection_is_reported_only_after_durable_evidence(tmp_path: Path) -> None:
    store = _store(tmp_path)
    desired = _desired(store, reason="Проверяемый режим")
    completion, adapter = _verified(store)

    state = HouseholdPolicyEffectiveStateService(store).read(
        actor=PARENT_ACTOR,
        member_id=CHILD,
    )

    assert adapter.calls == 1
    assert state["state"] == "verified"
    assert state["desired_generation"] == desired["generation"]
    assert state["enforcement_verified"] is True
    assert state["reconciliation_required"] is False
    evidence = state["verified_evidence"]
    assert isinstance(evidence, dict)
    assert evidence["request_id"] == completion["request_id"]
    assert evidence["evidence_id"] == completion["evidence"]["evidence_id"]
    assert evidence["backend_id"] == BACKEND
    _validate_contract(state)
    store.close()


def test_new_desired_generation_never_reuses_previous_verified_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = _desired(store, reason="Первое правило")
    _verified(store)
    second = _desired(store, reason="Следующая редакция правила")
    assert second["generation"] == first["generation"] + 1

    state = HouseholdPolicyEffectiveStateService(store).read(
        actor=PARENT_ACTOR,
        member_id=CHILD,
    )

    assert state["desired_generation"] == second["generation"]
    assert state["state"] == "pending-reconciliation"
    assert state["enforcement_verified"] is False
    assert state["reconciliation_required"] is True
    assert state["verified_evidence"] is None
    _validate_contract(state)
    store.close()


def test_tampered_durable_evidence_digest_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store, reason="Проверка evidence")
    _verified(store)

    key = VERIFIED_KEY_PREFIX + "home." + CHILD
    projection = store.get_meta(key)
    assert isinstance(projection, dict)
    tampered = dict(projection)
    tampered["evidence_sha256"] = "0" * 64
    store.set_meta(key, tampered)

    with pytest.raises(
        HouseholdPolicyEffectiveStateError,
        match="household_policy_effective_state_verification_evidence_invalid",
    ):
        HouseholdPolicyEffectiveStateService(store).read(
            actor=PARENT_ACTOR,
            member_id=CHILD,
        )

    store.close()


def test_orphan_verified_projection_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store, reason="Orphan check")
    _verified(store)
    store.set_meta(DESIRED_KEY_PREFIX + "home." + CHILD, None)

    with pytest.raises(
        HouseholdPolicyEffectiveStateError,
        match="household_policy_effective_state_orphan_verified",
    ):
        HouseholdPolicyEffectiveStateService(store).read(
            actor=PARENT_ACTOR,
            member_id=CHILD,
        )

    store.close()
