from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from home_center.household import FamilyMember, Household, HouseholdRole
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
    store = StateStore(tmp_path / "state.db", b"e" * 32, "cluster-test")
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


def _desired(store: StateStore) -> None:
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
            "reason": "Семейный режим",
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


class QualifiedAdapter:
    policy_mutation_capable = True
    policy_backend_qualified = True
    adapter_id = BACKEND
    adapter_version = "1.0.0"
    adapter_artifact_sha256 = ARTIFACT_SHA
    qualification_evidence_sha256 = QUALIFICATION_SHA

    def __init__(self, *, accepted: bool = True, fail: bool = False) -> None:
        self.accepted = accepted
        self.fail = fail
        self.calls = 0
        self.requests: list[dict[str, object]] = []

    def apply_policy(self, request: dict[str, object]) -> object:
        self.calls += 1
        self.requests.append(dict(request))
        if self.fail:
            raise RuntimeError("ambiguous backend failure")
        return {"accepted": self.accepted}


class UnqualifiedAdapter(QualifiedAdapter):
    policy_backend_qualified = False


def _service(
    store: StateStore,
    adapter: QualifiedAdapter | None = None,
) -> HouseholdPolicyEnforcementRuntimeService:
    service = HouseholdPolicyEnforcementRuntimeService(store)
    if adapter is not None:
        service.register_adapter(BACKEND, adapter)
    return service


def _planned_and_confirmed(
    service: HouseholdPolicyEnforcementRuntimeService,
) -> dict[str, object]:
    plan = service.plan(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        correlation_id="enforcement-plan",
    )
    confirmation = service.confirm(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        confirmed=True,
        correlation_id="enforcement-confirm",
    )
    assert confirmation["backend_mutation_authorized"] is True
    assert confirmation["automatic_retry_authorized"] is False
    assert confirmation["enforcement_success_claim_authorized"] is False
    return plan


def test_unqualified_backend_registration_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = _service(store)
    with pytest.raises(
        HouseholdPolicyEnforcementError,
        match="invalid_household_policy_enforcement_adapter_registration",
    ):
        service.register_adapter(BACKEND, UnqualifiedAdapter())
    store.close()


def test_execute_requires_separate_confirmation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    adapter = QualifiedAdapter()
    service = _service(store, adapter)
    plan = service.plan(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        correlation_id="enforcement-plan",
    )
    with pytest.raises(
        HouseholdPolicyEnforcementError,
        match="household_policy_enforcement_confirmation_required",
    ):
        service.execute(
            actor=PARENT_ACTOR,
            plan_id=str(plan["plan_id"]),
            correlation_id="enforcement-execute",
        )
    assert adapter.calls == 0
    store.close()


def test_backend_acceptance_is_not_enforcement_success_and_replay_is_safe(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _desired(store)
    adapter = QualifiedAdapter()
    service = _service(store, adapter)
    plan = _planned_and_confirmed(service)
    first = service.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute",
    )
    replay = service.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-replay",
    )
    assert replay == first
    assert adapter.calls == 1
    assert first["backend_command_accepted"] is True
    assert first["enforcement_verified"] is False
    assert first["reconciliation_required"] is True
    assert first["automatic_retry_authorized"] is False
    assert first["enforcement_success_claim_authorized"] is False
    assert adapter.requests[0]["secret_values_present"] is False
    assert adapter.requests[0]["infrastructure_mutation_authorized"] is False
    assert adapter.requests[0]["external_publication_authorized"] is False
    store.close()


def test_ambiguous_backend_outcome_never_auto_retries(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    adapter = QualifiedAdapter(fail=True)
    service = _service(store, adapter)
    plan = _planned_and_confirmed(service)
    with pytest.raises(
        HouseholdPolicyEnforcementError,
        match="household_policy_enforcement_backend_outcome_ambiguous",
    ):
        service.execute(
            actor=PARENT_ACTOR,
            plan_id=str(plan["plan_id"]),
            correlation_id="enforcement-execute",
        )
    with pytest.raises(
        HouseholdPolicyEnforcementError,
        match="household_policy_enforcement_reconciliation_required",
    ):
        service.execute(
            actor=PARENT_ACTOR,
            plan_id=str(plan["plan_id"]),
            correlation_id="enforcement-replay",
        )
    assert adapter.calls == 1
    store.close()


def test_stale_desired_state_rejected_before_backend_invocation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    adapter = QualifiedAdapter()
    service = _service(store, adapter)
    plan = _planned_and_confirmed(service)
    policy = HouseholdPolicyRuntimeService(store)
    next_plan = policy.plan(
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
            "reason": "Новая версия правил",
        },
        correlation_id="policy-plan-next",
    )
    policy.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": next_plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm-next",
    )
    with pytest.raises(
        HouseholdPolicyEnforcementError,
        match="household_policy_enforcement_desired_state_stale",
    ):
        service.execute(
            actor=PARENT_ACTOR,
            plan_id=str(plan["plan_id"]),
            correlation_id="enforcement-stale",
        )
    assert adapter.calls == 0
    store.close()


def test_non_parent_cannot_plan_enforcement(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    service = _service(store, QualifiedAdapter())
    with pytest.raises(
        HouseholdPolicyEnforcementError,
        match="household_policy_enforcement_not_authorized",
    ):
        service.plan(
            actor=CHILD_ACTOR,
            member_id=CHILD,
            backend_id=BACKEND,
            correlation_id="enforcement-child",
        )
    store.close()


@pytest.mark.parametrize(
    "name",
    [
        "household-policy-enforcement-plan.v1.schema.json",
        "household-policy-enforcement-confirmation.v1.schema.json",
        "household-policy-enforcement-receipt.v1.schema.json",
        "household-policy-backend-apply-request.v1.schema.json",
    ],
)
def test_enforcement_contracts_are_valid_draft_2020_12(name: str) -> None:
    path = Path(__file__).resolve().parents[1] / "contracts" / "household" / name
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


def test_plan_confirmation_receipt_and_apply_request_match_contracts(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _desired(store)
    adapter = QualifiedAdapter()
    service = _service(store, adapter)
    plan = service.plan(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        correlation_id="enforcement-plan-contract",
    )
    confirmation = service.confirm(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        confirmed=True,
        correlation_id="enforcement-confirm-contract",
    )
    receipt = service.execute(
        actor=PARENT_ACTOR,
        plan_id=str(plan["plan_id"]),
        correlation_id="enforcement-execute-contract",
    )
    root = Path(__file__).resolve().parents[1] / "contracts" / "household"
    cases = [
        ("household-policy-enforcement-plan.v1.schema.json", plan),
        ("household-policy-enforcement-confirmation.v1.schema.json", confirmation),
        ("household-policy-enforcement-receipt.v1.schema.json", receipt),
        ("household-policy-backend-apply-request.v1.schema.json", adapter.requests[0]),
    ]
    for name, value in cases:
        schema = json.loads((root / name).read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(value)
    store.close()
