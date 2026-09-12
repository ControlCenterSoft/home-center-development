from __future__ import annotations

from copy import deepcopy

import pytest

from home_center.household_policy_evidence import (
    HouseholdPolicyEvidenceError,
    validate_policy_bundle_evidence,
)
from home_center.household_policy_runtime import POLICY_PLAN_REQUEST_SCHEMA, HouseholdPolicyRuntimeService
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore


ACTOR = "parent@example.test"


def _bundle(tmp_path):
    store = StateStore(tmp_path / "state.db", b"e" * 32, "policy-evidence-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-evidence-bootstrap",
    )
    policy = HouseholdPolicyRuntimeService(store)
    proposal = policy.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": household.actor_member_id(ACTOR),
        },
        correlation_id="policy-evidence-plan",
    )
    return store, proposal["bundle"]


def test_semantic_policy_evidence_accepts_exact_role_preset_bundle(tmp_path) -> None:
    store, bundle = _bundle(tmp_path)
    assert validate_policy_bundle_evidence(
        bundle,
        expected_resource_key=bundle["desired_state_resource_key"],
    ) == bundle
    store.close()


@pytest.mark.parametrize(
    "mutator",
    [
        lambda bundle: bundle.update({"bundle_id": "hpb-" + "f" * 24}),
        lambda bundle: bundle.update({"explanation": ["Подменённое бытовое объяснение."]}),
        lambda bundle: bundle.update({"infrastructure_mutation_authorized": True}),
        lambda bundle: bundle["technical_policy"].update({"vpn_allowed": False}),
        lambda bundle: bundle["technical_policy"].update({"administration_allowed": False}),
        lambda bundle: bundle.update({"policy_id": "hpol-" + "f" * 24}),
    ],
)
def test_semantic_policy_evidence_rejects_forged_or_drifted_bundle(tmp_path, mutator) -> None:
    store, bundle = _bundle(tmp_path)
    tampered = deepcopy(bundle)
    mutator(tampered)
    with pytest.raises(HouseholdPolicyEvidenceError, match="household_policy_history_evidence_mismatch"):
        validate_policy_bundle_evidence(
            tampered,
            expected_resource_key=bundle["desired_state_resource_key"],
        )
    store.close()


def test_semantic_policy_evidence_rejects_resource_scope_substitution(tmp_path) -> None:
    store, bundle = _bundle(tmp_path)
    with pytest.raises(HouseholdPolicyEvidenceError, match="household_policy_history_evidence_mismatch"):
        validate_policy_bundle_evidence(
            bundle,
            expected_resource_key="household-policy:other:member",
        )
    store.close()
