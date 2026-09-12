from __future__ import annotations

from home_center.household_policy_desired_state import (
    POLICY_APPLY_REQUEST_SCHEMA,
    HouseholdPolicyDesiredStateService,
)
from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore


ACTOR = "parent@example.test"
AUDIT_KEY = b"r" * 32
CLUSTER_ID = "policy-restore-test"


def test_policy_desired_state_confirmation_and_apply_receipt_survive_backup_restore(tmp_path) -> None:
    source_path = tmp_path / "source.db"
    backup_path = tmp_path / "backup.db"
    store = StateStore(source_path, AUDIT_KEY, CLUSTER_ID)
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="bootstrap-backup",
    )
    member_id = household.actor_member_id(ACTOR)

    policy = HouseholdPolicyRuntimeService(store)
    proposal = policy.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id="policy-plan-backup",
    )
    confirmation = policy.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm-backup",
    )
    desired = HouseholdPolicyDesiredStateService(store)
    receipt = desired.apply(
        actor=ACTOR,
        request={
            "schema": POLICY_APPLY_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmation_id": confirmation["confirmation_id"],
        },
        correlation_id="policy-apply-backup",
    )
    assert receipt["outcome"] == "applied"
    assert store.integrity_check() is True
    source_audit_head = store.verify_audit_chain()
    store.backup_to(backup_path)
    store.close()

    restored = StateStore(backup_path, AUDIT_KEY, CLUSTER_ID)
    assert restored.integrity_check() is True
    assert restored.verify_audit_chain() == source_audit_head
    records = restored.desired_state()
    assert len(records) == 1
    assert records[0]["resource_key"] == proposal["bundle"]["desired_state_resource_key"]
    assert records[0]["generation"] == receipt["generation"]
    assert records[0]["value"] == proposal["bundle"]

    restored_household = HouseholdRuntimeService(restored)
    assert restored_household.actor_member_id(ACTOR) == member_id
    restored_policy = HouseholdPolicyDesiredStateService(restored)
    replay = restored_policy.apply(
        actor=ACTOR,
        request={
            "schema": POLICY_APPLY_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmation_id": confirmation["confirmation_id"],
        },
        correlation_id="policy-apply-after-restore",
    )
    assert replay["outcome"] == "already-applied"
    assert replay["generation"] == receipt["generation"]
    assert replay["bundle_id"] == receipt["bundle_id"]
    assert restored.desired_state()[0]["generation"] == receipt["generation"]
    restored.close()
