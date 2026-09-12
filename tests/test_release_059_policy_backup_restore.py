from __future__ import annotations

from pathlib import Path

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"


def _source_store(path: Path) -> StateStore:
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
    store = StateStore(path, b"r" * 32, "cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=ACTOR, member_id=PARENT),)),
    )
    return store


def test_policy_desired_state_job_and_audit_survive_sqlite_backup_restore(tmp_path: Path) -> None:
    source_path = tmp_path / "source" / "state.db"
    backup_path = tmp_path / "backup" / "state.db"
    source = _source_store(source_path)
    service = HouseholdPolicyRuntimeService(source)
    plan = service.plan(
        actor=ACTOR,
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
            "reason": "backup qualification",
        },
        correlation_id="policy-plan-backup",
    )
    receipt = service.confirm(
        actor=ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm-backup",
    )
    desired_before = service.desired_state(actor=ACTOR, member_id=CHILD)
    assert desired_before is not None
    audit_head = source.verify_audit_chain()
    assert audit_head != "0" * 64
    source.backup_to(backup_path)
    source.close()

    restored = StateStore(backup_path, b"r" * 32, "cluster-test")
    restored_service = HouseholdPolicyRuntimeService(restored)
    assert restored.integrity_check() is True
    assert restored.verify_audit_chain() == audit_head
    assert restored_service.desired_state(actor=ACTOR, member_id=CHILD) == desired_before
    restored_job = restored.job(receipt["job_id"])
    assert restored_job is not None
    assert restored_job["state"] == "succeeded"
    assert restored_job["evidence"]["receipt"] == receipt
    replay = restored_service.confirm(
        actor=ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm-backup-replay",
    )
    assert replay == receipt
    assert len([job for job in restored.jobs() if job["job_type"] == "household.policy.desired-state.commit"]) == 1
    restored.close()
