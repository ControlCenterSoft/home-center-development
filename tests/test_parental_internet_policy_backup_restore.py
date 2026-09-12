from __future__ import annotations

import hashlib
from pathlib import Path

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_policy_composer import build_policy_bundle, compose_policy
from home_center.household_policy_runtime import (
    DESIRED_KEY_PREFIX as BASE_POLICY_DESIRED_KEY_PREFIX,
    DESIRED_STATE_SCHEMA as BASE_DESIRED_SCHEMA,
)
from home_center.household_policy_verification_state import VERIFIED_KEY_PREFIX, VERIFIED_STATE_SCHEMA
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.parental_internet_policy_runtime import (
    ACTION,
    CONFIRM_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    ParentalInternetPolicyRuntimeService,
)
from home_center.store import StateStore
from home_center.util import canonical_json

PARENT_ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _seed(store: StateStore) -> None:
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
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=PARENT_ACTOR, member_id=PARENT),)),
    )
    base = effective_policy(household, CHILD)
    bundle = build_policy_bundle(
        role=HouseholdRole.CHILD,
        value={
            "internet_policy": "filtered",
            "vpn_allowed": False,
            "managed_device_required": True,
            "home_files_allowed": True,
            "smart_home_control_allowed": False,
            "administration_allowed": False,
            "external_publication_allowed": False,
        },
    )
    policy = compose_policy(base=base, bundle=bundle).to_dict()
    policy_sha = _digest(policy)
    desired = {
        "schema": BASE_DESIRED_SCHEMA,
        "household_id": "home",
        "member_id": CHILD,
        "generation": 1,
        "plan_id": "hpcp-" + "a" * 24,
        "policy": policy,
        "policy_sha256": policy_sha,
        "reason": "verified child base",
        "enforcement_verified": False,
        "reconciliation_required": True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    verified = {
        "schema": VERIFIED_STATE_SCHEMA,
        "household_id": "home",
        "member_id": CHILD,
        "desired_generation": 1,
        "desired_plan_id": desired["plan_id"],
        "policy_id": policy["policy_id"],
        "policy_sha256": policy_sha,
        "source_desired_state_sha256": _digest(desired),
        "request_id": "hprq-" + "b" * 24,
        "backend_id": "backup-test-backend",
        "evidence_id": "hpev-" + "c" * 24,
        "evidence_sha256": "d" * 64,
        "observed_at": "2026-09-13T00:00:00Z",
        "enforcement_verified": True,
        "reconciliation_required": False,
        "backend_mutation_performed": False,
        "infrastructure_mutation_performed": False,
        "external_publication_performed": False,
        "desired_state": desired,
    }
    store.set_meta(BASE_POLICY_DESIRED_KEY_PREFIX + "home." + CHILD, desired)
    store.set_meta(VERIFIED_KEY_PREFIX + "home." + CHILD, verified)


def _request():
    return {
        "schema": PLAN_REQUEST_SCHEMA,
        "subject_member_id": CHILD,
        "rule_source_id": "family-filter",
        "rule_source_version": "2026.09.13",
        "rule_source_sha256": "e" * 64,
        "allow_domains": ["school.example"],
        "deny_domains": ["blocked.example"],
        "allow_categories": ["education"],
        "deny_categories": ["adult"],
        "schedule": [{"weekday": 0, "start_minute": 480, "end_minute": 1200}],
        "daily_quota_minutes": 180,
        "weekly_quota_minutes": 900,
        "continuous_session_minutes": 60,
        "break_minutes": 15,
        "grace_minutes": 5,
        "bonus_minutes": 20,
        "reason": "backup qualification",
    }


def test_parental_desired_state_job_and_audit_survive_backup_restore(tmp_path: Path) -> None:
    source_path = tmp_path / "source.db"
    backup_path = tmp_path / "restored.db"
    store = StateStore(source_path, b"p" * 32, "cluster-test")
    _seed(store)
    service = ParentalInternetPolicyRuntimeService(store)
    plan = service.plan(actor=PARENT_ACTOR, request=_request(), correlation_id="plan")
    receipt = service.confirm(
        actor=PARENT_ACTOR,
        request={"schema": CONFIRM_REQUEST_SCHEMA, "plan_id": plan["plan_id"], "confirmed": True},
        correlation_id="confirm",
    )
    original_desired = service.desired_state(actor=PARENT_ACTOR, member_id=CHILD)
    original_job = store.job(receipt["job_id"])
    original_audit_head = store.verify_audit_chain()
    assert original_desired is not None
    assert original_job is not None and original_job["state"] == "succeeded"
    store.backup_to(backup_path)
    store.close()

    restored = StateStore(backup_path, b"p" * 32, "cluster-test")
    restored_service = ParentalInternetPolicyRuntimeService(restored)
    assert restored.verify_audit_chain() == original_audit_head
    assert restored_service.desired_state(actor=PARENT_ACTOR, member_id=CHILD) == original_desired
    restored_job = restored.job(receipt["job_id"])
    assert restored_job is not None
    assert restored_job["state"] == "succeeded"
    assert restored_job["evidence"] == original_job["evidence"]
    assert restored_job["evidence"]["receipt"] == receipt
    replay = restored_service.confirm(
        actor=PARENT_ACTOR,
        request={"schema": CONFIRM_REQUEST_SCHEMA, "plan_id": plan["plan_id"], "confirmed": True},
        correlation_id="confirm-replay",
    )
    assert replay == receipt
    assert len([item for item in restored.jobs() if item["job_type"] == ACTION]) == 1
    restored.close()
