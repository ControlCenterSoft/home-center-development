from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

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
    ParentalInternetPolicyRuntimeError,
)
from home_center.parental_internet_policy_runtime_safe import SafeParentalInternetPolicyRuntimeService
from home_center.step_up import StepUpError, StepUpGrantManager
from home_center.store import StateStore
from home_center.util import canonical_json

PARENT_ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
RULE_SHA = "a" * 64


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


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
        _persisted(snapshot, (ActorBinding(actor=PARENT_ACTOR, member_id=PARENT),)),
    )
    return store


def _install_verified_base(store: StateStore) -> None:
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id=PARENT, display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id=CHILD, display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
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
        "generation": 2,
        "plan_id": "hpcp-" + "b" * 24,
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
        "desired_generation": 2,
        "desired_plan_id": desired["plan_id"],
        "policy_id": policy["policy_id"],
        "policy_sha256": policy_sha,
        "source_desired_state_sha256": _digest(desired),
        "request_id": "hprq-" + "c" * 24,
        "backend_id": "verified-test-backend",
        "evidence_id": "hpev-" + "d" * 24,
        "evidence_sha256": "e" * 64,
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


def _request() -> dict[str, object]:
    return {
        "schema": PLAN_REQUEST_SCHEMA,
        "subject_member_id": CHILD,
        "rule_source_id": "family-filter",
        "rule_source_version": "2026.09.13",
        "rule_source_sha256": RULE_SHA,
        "allow_domains": ["school.example"],
        "deny_domains": ["blocked.example"],
        "allow_categories": ["education"],
        "deny_categories": ["adult", "gambling"],
        "schedule": [{"weekday": 0, "start_minute": 480, "end_minute": 1200}],
        "daily_quota_minutes": 180,
        "weekly_quota_minutes": 900,
        "continuous_session_minutes": 60,
        "break_minutes": 15,
        "grace_minutes": 5,
        "bonus_minutes": 20,
        "reason": "семейные правила интернета",
    }


def _confirm(plan_id: str) -> dict[str, object]:
    return {"schema": CONFIRM_REQUEST_SCHEMA, "plan_id": plan_id, "confirmed": True}


def test_new_commit_requires_actor_plan_bound_single_use_grant(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    grants = StepUpGrantManager()
    service = SafeParentalInternetPolicyRuntimeService(store, grants)
    plan = service.plan(actor=PARENT_ACTOR, request=_request(), correlation_id="plan")
    plan_id = str(plan["plan_id"])
    scope = service.confirmation_scope(actor=PARENT_ACTOR, plan_id=plan_id)
    assert scope == service.step_up_scope(plan_id)

    with pytest.raises(ParentalInternetPolicyRuntimeError, match="step_up_required"):
        service.confirm(
            actor=PARENT_ACTOR,
            request=_confirm(plan_id),
            step_up_token=None,
            correlation_id="no-grant",
        )
    assert service.desired_state(actor=PARENT_ACTOR, member_id=CHILD) is None
    assert not [item for item in store.jobs() if item["job_type"] == ACTION]

    token, _ = grants.issue(actor=PARENT_ACTOR, scope=scope)
    receipt = service.confirm(
        actor=PARENT_ACTOR,
        request=_confirm(plan_id),
        step_up_token=token,
        correlation_id="commit",
    )
    assert receipt["state"] == "desired-state-committed"
    assert receipt["enforcement_verified"] is False
    assert receipt["dns_policy_applied"] is False
    assert receipt["proxy_policy_applied"] is False
    with pytest.raises(StepUpError, match="step_up_required"):
        grants.consume(actor=PARENT_ACTOR, scope=scope, token=token)
    store.close()


def test_wrong_scope_token_is_consumed_but_cannot_commit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    grants = StepUpGrantManager()
    service = SafeParentalInternetPolicyRuntimeService(store, grants)
    plan = service.plan(actor=PARENT_ACTOR, request=_request(), correlation_id="plan")
    plan_id = str(plan["plan_id"])
    token, _ = grants.issue(actor=PARENT_ACTOR, scope="household.parental-internet.policy:hpip-" + "f" * 24)

    with pytest.raises(ParentalInternetPolicyRuntimeError, match="step_up_binding_mismatch"):
        service.confirm(
            actor=PARENT_ACTOR,
            request=_confirm(plan_id),
            step_up_token=token,
            correlation_id="wrong-scope",
        )
    assert service.desired_state(actor=PARENT_ACTOR, member_id=CHILD) is None
    store.close()


def test_verified_base_drift_fails_before_grant_is_consumed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    grants = StepUpGrantManager()
    service = SafeParentalInternetPolicyRuntimeService(store, grants)
    plan = service.plan(actor=PARENT_ACTOR, request=_request(), correlation_id="plan")
    plan_id = str(plan["plan_id"])
    scope = service.step_up_scope(plan_id)
    token, _ = grants.issue(actor=PARENT_ACTOR, scope=scope)

    base_key = BASE_POLICY_DESIRED_KEY_PREFIX + "home." + CHILD
    raw = store.get_meta(base_key)
    assert isinstance(raw, dict)
    drifted = dict(raw)
    drifted["reason"] = "base drift after planning"
    store.set_meta(base_key, drifted)

    with pytest.raises(ParentalInternetPolicyRuntimeError, match="parental_internet_verified_base_stale"):
        service.confirm(
            actor=PARENT_ACTOR,
            request=_confirm(plan_id),
            step_up_token=token,
            correlation_id="stale",
        )

    grants.consume(actor=PARENT_ACTOR, scope=scope, token=token)
    store.close()


def test_committed_replay_revalidates_authority_without_new_grant(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    grants = StepUpGrantManager()
    service = SafeParentalInternetPolicyRuntimeService(store, grants)
    plan = service.plan(actor=PARENT_ACTOR, request=_request(), correlation_id="plan")
    plan_id = str(plan["plan_id"])
    scope = service.step_up_scope(plan_id)
    token, _ = grants.issue(actor=PARENT_ACTOR, scope=scope)
    receipt = service.confirm(
        actor=PARENT_ACTOR,
        request=_confirm(plan_id),
        step_up_token=token,
        correlation_id="commit",
    )

    assert service.confirmation_scope(actor=PARENT_ACTOR, plan_id=plan_id) is None
    replay = service.confirm(
        actor=PARENT_ACTOR,
        request=_confirm(plan_id),
        step_up_token=None,
        correlation_id="replay",
    )
    assert replay == receipt
    assert len([item for item in store.jobs() if item["job_type"] == ACTION]) == 1
    store.close()
