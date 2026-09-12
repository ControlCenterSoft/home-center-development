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
    DESIRED_KEY_PREFIX,
    PLAN_REQUEST_SCHEMA,
    ParentalInternetPolicyRuntimeError,
    ParentalInternetPolicyRuntimeService,
)
from home_center.store import StateStore
from home_center.util import canonical_json

PARENT_ACTOR = "local-admin:admin"
CHILD_ACTOR = "member-session:child"
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
    store = StateStore(tmp_path / "state.db", b"p" * 32, "cluster-test")
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


def _install_verified_base(store: StateStore) -> dict[str, object]:
    raw_state = store.get_meta(HOUSEHOLD_STATE_KEY)
    snapshot = raw_state["snapshot"]
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
        "reason": "base child policy",
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
    assert snapshot["household_id"] == "home"
    return verified


def _request(**overrides):
    request = {
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
    request.update(overrides)
    return request


def _confirm(service: ParentalInternetPolicyRuntimeService, plan):
    return service.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="parental-confirm",
    )


def test_parent_commits_only_non_enforcing_parental_desired_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    service = ParentalInternetPolicyRuntimeService(store)
    plan = service.plan(
        actor=PARENT_ACTOR,
        request=_request(),
        correlation_id="parental-plan",
    )
    assert plan["observed_desired_generation"] == 0
    assert plan["expected_desired_generation"] == 1
    assert plan["desired_state_write_authorized"] is False
    assert plan["enforcement_authorized"] is False
    assert plan["infrastructure_mutation_authorized"] is False
    assert plan["external_publication_authorized"] is False

    receipt = _confirm(service, plan)
    assert receipt["state"] == "desired-state-committed"
    assert receipt["enforcement_verified"] is False
    assert receipt["reconciliation_required"] is True
    assert receipt["dns_policy_applied"] is False
    assert receipt["proxy_policy_applied"] is False
    assert receipt["infrastructure_mutation_performed"] is False
    assert receipt["external_publication_performed"] is False

    desired = service.desired_state(actor=PARENT_ACTOR, member_id=CHILD)
    assert desired is not None
    assert desired["generation"] == 1
    assert desired["policy"]["default_decision"] == "deny"
    assert desired["enforcement_verified"] is False
    assert desired["reconciliation_required"] is True
    assert desired["dns_policy_applied"] is False
    assert desired["proxy_policy_applied"] is False

    job = store.job(receipt["job_id"])
    assert job is not None and job["state"] == "succeeded"
    assert job["evidence"]["receipt"] == receipt
    replay = _confirm(service, plan)
    assert replay == receipt
    assert len([item for item in store.jobs() if item["job_type"] == ACTION]) == 1
    store.close()


def test_verified_059_base_is_mandatory(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = ParentalInternetPolicyRuntimeService(store)
    with pytest.raises(
        ParentalInternetPolicyRuntimeError,
        match="parental_internet_verified_base_missing",
    ):
        service.plan(
            actor=PARENT_ACTOR,
            request=_request(),
            correlation_id="parental-no-base",
        )
    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) is None
    store.close()


def test_child_actor_cannot_plan_parental_policy(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    service = ParentalInternetPolicyRuntimeService(store)
    with pytest.raises(
        ParentalInternetPolicyRuntimeError,
        match="parental_internet_change_not_authorized",
    ):
        service.plan(
            actor=CHILD_ACTOR,
            request=_request(),
            correlation_id="parental-child-denied",
        )
    assert not [item for item in store.jobs() if item["job_type"] == ACTION]
    store.close()


def test_verified_base_drift_blocks_confirmation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    verified = _install_verified_base(store)
    service = ParentalInternetPolicyRuntimeService(store)
    plan = service.plan(
        actor=PARENT_ACTOR,
        request=_request(),
        correlation_id="parental-plan",
    )
    verified["evidence_sha256"] = "f" * 64
    store.set_meta(VERIFIED_KEY_PREFIX + "home." + CHILD, verified)
    with pytest.raises(
        ParentalInternetPolicyRuntimeError,
        match="parental_internet_verified_base_stale",
    ):
        _confirm(service, plan)
    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) is None
    store.close()


def test_newer_unverified_059_desired_state_invalidates_old_verified_base(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    service = ParentalInternetPolicyRuntimeService(store)
    plan = service.plan(
        actor=PARENT_ACTOR,
        request=_request(),
        correlation_id="parental-plan",
    )
    current = store.get_meta(BASE_POLICY_DESIRED_KEY_PREFIX + "home." + CHILD)
    current["reason"] = "new unverified base policy write"
    store.set_meta(BASE_POLICY_DESIRED_KEY_PREFIX + "home." + CHILD, current)
    with pytest.raises(
        ParentalInternetPolicyRuntimeError,
        match="parental_internet_verified_base_stale",
    ):
        _confirm(service, plan)
    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) is None
    store.close()


def test_competing_parental_write_blocks_stale_plan(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    service = ParentalInternetPolicyRuntimeService(store)
    first = service.plan(
        actor=PARENT_ACTOR,
        request=_request(reason="first"),
        correlation_id="parental-first-plan",
    )
    second = service.plan(
        actor=PARENT_ACTOR,
        request=_request(reason="second", bonus_minutes=10),
        correlation_id="parental-second-plan",
    )
    _confirm(service, first)
    with pytest.raises(
        ParentalInternetPolicyRuntimeError,
        match="parental_internet_desired_generation_stale",
    ):
        _confirm(service, second)
    desired = service.desired_state(actor=PARENT_ACTOR, member_id=CHILD)
    assert desired is not None and desired["plan_id"] == first["plan_id"]
    store.close()
