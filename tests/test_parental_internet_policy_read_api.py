from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
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
from home_center.parental_internet_policy_read_api import (
    DESIRED_READ_SCHEMA,
    PREVIEW_REQUEST_SCHEMA,
    PREVIEW_RESULT_SCHEMA,
    ParentalInternetPolicyReadAPIError,
    ParentalInternetPolicyReadAPIService,
    parse_parental_internet_preview_request,
)
from home_center.parental_internet_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    ParentalInternetPolicyRuntimeService,
)
from home_center.store import StateStore
from home_center.util import canonical_json

ROOT = Path(__file__).resolve().parents[1]
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
    store = StateStore(tmp_path / "state.db", b"r" * 32, "cluster-test")
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


def _install_parental_desired(store: StateStore) -> dict[str, object]:
    runtime = ParentalInternetPolicyRuntimeService(store)
    plan = runtime.plan(
        actor=PARENT_ACTOR,
        request={
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
        },
        correlation_id="read-api-plan",
    )
    runtime.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="read-api-confirm",
    )
    desired = runtime.desired_state(actor=PARENT_ACTOR, member_id=CHILD)
    assert desired is not None
    return desired


def _preview(**overrides):
    request = {
        "schema": PREVIEW_REQUEST_SCHEMA,
        "member_id": CHILD,
        "domain": "learn.example",
        "category": "education",
        "weekday": 0,
        "minute_of_day": 600,
        "daily_used_minutes": 20,
        "weekly_used_minutes": 100,
        "continuous_used_minutes": 10,
        "view": "cozy",
    }
    request.update(overrides)
    return request


def test_read_and_preview_use_current_server_side_policy_identity(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    desired = _install_parental_desired(store)
    service = ParentalInternetPolicyReadAPIService(store)

    saved = service.read_desired(actor=PARENT_ACTOR, member_id=CHILD, view="cozy")
    assert saved["schema"] == DESIRED_READ_SCHEMA
    assert saved["state"] == "present"
    assert saved["value"]["status"] == "Ожидают применения и проверки"
    assert saved["provider_execution_authorized"] is False
    assert saved["infrastructure_mutation_authorized"] is False
    assert saved["external_publication_authorized"] is False

    preview = service.preview(actor=PARENT_ACTOR, request=_preview())
    assert preview["schema"] == PREVIEW_RESULT_SCHEMA
    assert preview["policy_id"] == desired["policy"]["policy_id"]
    assert preview["policy_sha256"] == desired["policy_sha256"]
    assert preview["decision"]["decision"] == "allow"
    assert preview["decision"]["reason"] == "category_allowed"
    assert preview["preview_only"] is True
    assert preview["enforcement_verified"] is False
    assert preview["provider_execution_authorized"] is False

    jsonschema.Draft202012Validator(
        json.loads((ROOT / "contracts/household/parental-internet-policy-desired-read.v1.schema.json").read_text())
    ).validate(saved)
    jsonschema.Draft202012Validator(
        json.loads((ROOT / "contracts/household/parental-internet-decision-preview-result.v1.schema.json").read_text())
    ).validate(preview)
    store.close()


def test_preview_does_not_accept_policy_or_rule_source_identity_from_client(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    _install_parental_desired(store)
    service = ParentalInternetPolicyReadAPIService(store)

    request = _preview()
    request["policy_id"] = "hcip-" + "f" * 24
    with pytest.raises(ParentalInternetPolicyReadAPIError, match="invalid_parental_internet_preview_request"):
        service.preview(actor=PARENT_ACTOR, request=request)

    request = _preview()
    request["rule_source_sha256"] = "0" * 64
    with pytest.raises(ParentalInternetPolicyReadAPIError, match="invalid_parental_internet_preview_request"):
        service.preview(actor=PARENT_ACTOR, request=request)
    store.close()


def test_child_actor_cannot_read_or_preview_parental_policy(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    _install_parental_desired(store)
    service = ParentalInternetPolicyReadAPIService(store)

    with pytest.raises(ParentalInternetPolicyReadAPIError, match="parental_internet_change_not_authorized"):
        service.read_desired(actor=CHILD_ACTOR, member_id=CHILD, view="cozy")
    with pytest.raises(ParentalInternetPolicyReadAPIError, match="parental_internet_change_not_authorized"):
        service.preview(actor=CHILD_ACTOR, request=_preview())
    store.close()


def test_preview_fails_closed_when_verified_059_base_drifts(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _install_verified_base(store)
    _install_parental_desired(store)
    service = ParentalInternetPolicyReadAPIService(store)

    base_key = BASE_POLICY_DESIRED_KEY_PREFIX + "home." + CHILD
    base_desired = store.get_meta(base_key)
    assert isinstance(base_desired, dict)
    tampered = dict(base_desired)
    tampered["reason"] = "drifted after verification"
    store.set_meta(base_key, tampered)

    with pytest.raises(ParentalInternetPolicyReadAPIError, match="parental_internet_verified_base_stale"):
        service.preview(actor=PARENT_ACTOR, request=_preview())
    store.close()


def test_preview_request_is_closed_and_bounded() -> None:
    request = _preview()
    assert parse_parental_internet_preview_request(request) == request
    schema = json.loads(
        (ROOT / "contracts/household/parental-internet-decision-preview-request.v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(request)

    with pytest.raises(ParentalInternetPolicyReadAPIError):
        parse_parental_internet_preview_request({**request, "policy_id": "client-selected"})
    with pytest.raises(ParentalInternetPolicyReadAPIError):
        parse_parental_internet_preview_request({**request, "weekday": True})
    with pytest.raises(ParentalInternetPolicyReadAPIError):
        parse_parental_internet_preview_request({**request, "view": "raw"})
