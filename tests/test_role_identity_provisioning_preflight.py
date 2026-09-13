from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import HouseholdRole
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    RoleIdentityProvisioningPlan,
    StorageMode,
)
from home_center.role_identity_provisioning_preflight import (
    AccountObservationState,
    AccountPreflightObservation,
    IdentityProvisioningPreflightError,
    evaluate_account_preflight,
    observation_from_dict,
)

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_DIGEST = "a" * 64
OBSERVATION_DIGEST = "b" * 64


def _provider(*, digest: str = PROVIDER_DIGEST) -> IdentityProviderCapability:
    return IdentityProviderCapability(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=True,
        evidence_sha256=digest,
    )


def _plan(*, digest: str = PROVIDER_DIGEST) -> RoleIdentityProvisioningPlan:
    return RoleIdentityProvisioningPlan(
        plan_id="hcidp-" + "c" * 24,
        household_id="household-1",
        member_id="member-1",
        role=HouseholdRole.CHILD,
        household_snapshot_id="snapshot-1",
        household_resource_version="rv-1",
        household_generation=5,
        policy_id="policy-1",
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=digest,
        account_name="artemiy",
        home_directory_mode=StorageMode.LOCAL,
        profile_mode=StorageMode.LOCAL,
    )


def _observation(
    state: AccountObservationState = AccountObservationState.ABSENT,
    *,
    provider_digest: str = PROVIDER_DIGEST,
    account_name: str = "artemiy",
    observed_at: str = "2026-09-13T03:50:00Z",
    valid_until: str = "2026-09-13T04:20:00Z",
) -> AccountPreflightObservation:
    return AccountPreflightObservation(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=provider_digest,
        account_name=account_name,
        state=state,
        observed_at=observed_at,
        valid_until=valid_until,
        evidence_sha256=OBSERVATION_DIGEST,
    )


def test_exact_fresh_absent_observation_is_ready_but_never_authorizes_execution() -> None:
    decision = evaluate_account_preflight(
        plan=_plan(),
        provider=_provider(),
        observation=_observation(),
        now="2026-09-13T04:00:00Z",
    ).to_dict()
    assert decision["ready"] is True
    assert decision["blockers"] == []
    assert decision["state"] == "absent"
    assert decision["execution_authorized"] is False
    assert decision["external_publication_authorized"] is False


@pytest.mark.parametrize(
    ("state", "blocker"),
    [
        (AccountObservationState.EXISTS, "account_already_exists"),
        (AccountObservationState.CONFLICT, "account_name_conflict"),
        (AccountObservationState.UNKNOWN, "account_state_unknown"),
    ],
)
def test_non_absent_states_fail_closed(state: AccountObservationState, blocker: str) -> None:
    decision = evaluate_account_preflight(
        plan=_plan(),
        provider=_provider(),
        observation=_observation(state),
        now="2026-09-13T04:00:00Z",
    )
    assert decision.ready is False
    assert decision.blockers == (blocker,)


def test_stale_or_future_observation_cannot_authorize_preflight() -> None:
    expired = evaluate_account_preflight(
        plan=_plan(),
        provider=_provider(),
        observation=_observation(valid_until="2026-09-13T03:59:59Z"),
        now="2026-09-13T04:00:00Z",
    )
    assert expired.ready is False
    assert expired.blockers == ("observation_expired",)

    future = evaluate_account_preflight(
        plan=_plan(),
        provider=_provider(),
        observation=_observation(
            observed_at="2026-09-13T04:01:00Z",
            valid_until="2026-09-13T04:20:00Z",
        ),
        now="2026-09-13T04:00:00Z",
    )
    assert future.ready is False
    assert future.blockers == ("observation_from_future",)


def test_provider_and_account_binding_mismatch_is_rejected_before_decision() -> None:
    with pytest.raises(IdentityProvisioningPreflightError, match="identity_preflight_provider_binding_mismatch"):
        evaluate_account_preflight(
            plan=_plan(),
            provider=_provider(digest="d" * 64),
            observation=_observation(),
            now="2026-09-13T04:00:00Z",
        )

    with pytest.raises(IdentityProvisioningPreflightError, match="identity_preflight_observation_binding_mismatch"):
        evaluate_account_preflight(
            plan=_plan(),
            provider=_provider(),
            observation=_observation(account_name="kirill"),
            now="2026-09-13T04:00:00Z",
        )


def test_observation_transport_is_closed_and_read_only() -> None:
    payload = _observation().to_dict()
    assert observation_from_dict(payload).to_dict() == payload

    escalated = dict(payload)
    escalated["execution_authorized"] = True
    with pytest.raises(IdentityProvisioningPreflightError, match="identity_preflight_observation_rejected"):
        observation_from_dict(escalated)

    unknown = dict(payload)
    unknown["provider_payload"] = {"private": "not accepted"}
    with pytest.raises(IdentityProvisioningPreflightError, match="identity_preflight_observation_rejected"):
        observation_from_dict(unknown)


def test_preflight_contracts_validate_against_closed_json_schemas() -> None:
    observation_schema = json.loads(
        (ROOT / "contracts/household/role-identity-account-preflight-observation.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    decision_schema = json.loads(
        (ROOT / "contracts/household/role-identity-provisioning-preflight-decision.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    observation = _observation().to_dict()
    decision = evaluate_account_preflight(
        plan=_plan(),
        provider=_provider(),
        observation=_observation(),
        now="2026-09-13T04:00:00Z",
    ).to_dict()
    jsonschema.Draft202012Validator(observation_schema).validate(observation)
    jsonschema.Draft202012Validator(decision_schema).validate(decision)
