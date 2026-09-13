from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
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
    store = StateStore(tmp_path / "state.db", b"i" * 32, "cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(
            snapshot,
            (ActorBinding(actor=PARENT_ACTOR, member_id=PARENT),),
        ),
    )
    return store


def _plan(service: HouseholdPolicyRuntimeService) -> dict[str, object]:
    return service.plan(
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
            "reason": "Interrupted write recovery qualification",
        },
        correlation_id="policy-interrupted-plan",
    )


def _confirm(service: HouseholdPolicyRuntimeService, plan: dict[str, object]) -> dict[str, object]:
    return service.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-interrupted-confirm",
    )


def test_confirm_recovers_after_desired_write_before_job_transition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyRuntimeService(store)
    plan = _plan(service)
    original_transition = store.transition_action_job
    interrupted = False

    def interrupt_once(job_id: str, **kwargs):
        nonlocal interrupted
        if (
            not interrupted
            and kwargs.get("expected_state") == "running"
            and kwargs.get("new_state") == "verifying"
        ):
            interrupted = True
            raise RuntimeError("simulated interruption after desired-state write")
        return original_transition(job_id, **kwargs)

    monkeypatch.setattr(store, "transition_action_job", interrupt_once)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        _confirm(service, plan)

    desired_key = DESIRED_KEY_PREFIX + "home." + CHILD
    interrupted_desired = store.get_meta(desired_key)
    assert isinstance(interrupted_desired, dict)
    assert interrupted_desired["plan_id"] == plan["plan_id"]
    assert interrupted_desired["generation"] == plan["expected_desired_generation"]

    jobs = [item for item in store.jobs() if item["job_type"] == "household.policy.desired-state.commit"]
    assert len(jobs) == 1
    assert jobs[0]["state"] == "running"

    monkeypatch.setattr(store, "transition_action_job", original_transition)
    receipt = _confirm(service, plan)

    assert receipt["state"] == "desired-state-committed"
    assert receipt["desired_generation"] == plan["expected_desired_generation"]
    assert receipt["enforcement_verified"] is False
    assert receipt["reconciliation_required"] is True
    assert store.get_meta(desired_key) == interrupted_desired

    jobs = [item for item in store.jobs() if item["job_type"] == "household.policy.desired-state.commit"]
    assert len(jobs) == 1
    assert jobs[0]["job_id"] == receipt["job_id"]
    assert jobs[0]["state"] == "succeeded"
    assert jobs[0]["evidence"]["receipt"] == receipt
    store.close()
