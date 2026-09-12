from __future__ import annotations

from home_center import household_policy_guarded_workflow as guarded
from home_center.household_policy_workflow import HouseholdPolicyWorkflowService


def test_guarded_rollback_validates_exact_audit_binding_before_return(monkeypatch) -> None:
    history = object()
    service = object.__new__(guarded.GuardedHouseholdPolicyWorkflowService)
    service.history = history
    expected = {
        "rollback_id": "hprb-test",
        "resource_key": "household-policy:test:member",
        "generation": 3,
        "bundle_id": "hpb-" + "1" * 24,
        "target_history_generation": 1,
        "target_history_bundle_id": "hpb-" + "1" * 24,
        "changed": True,
        "recovered": False,
        "audit_event_id": "audit-test",
    }
    request = {
        "schema": "home-center.household-policy-rollback-request.v1",
        "resource_key": "household-policy:test:member",
        "expected_generation": 2,
        "expected_bundle_id": "hpb-" + "2" * 24,
        "target_generation": 1,
        "confirmed": True,
    }
    observed = {}

    def fake_base_rollback(self, *, actor, request, correlation_id):
        observed["base"] = (self, actor, request, correlation_id)
        return expected

    def fake_validate(history_service, *, actor, request, receipt):
        observed["audit"] = (history_service, actor, request, receipt)

    monkeypatch.setattr(HouseholdPolicyWorkflowService, "rollback", fake_base_rollback)
    monkeypatch.setattr(guarded, "validate_rollback_audit_binding", fake_validate)

    result = service.rollback(
        actor="parent@example.test",
        request=request,
        correlation_id="rollback-audit-wiring",
    )

    assert result is expected
    assert observed["base"] == (
        service,
        "parent@example.test",
        request,
        "rollback-audit-wiring",
    )
    assert observed["audit"] == (
        history,
        "parent@example.test",
        request,
        expected,
    )
