from __future__ import annotations

import unittest

from home_center.operation_commands import (
    ACTION_ID,
    SYSTEMCTL,
    OperationCommandAdmission,
    OperationCommandError,
    OperationCommandRequest,
    OperationJobState,
    ServiceStateSnapshot,
    validate_job_transition,
)


class OperationCommandAdmissionTests(unittest.TestCase):
    def snapshot(self, active_state: str = "active") -> ServiceStateSnapshot:
        return ServiceStateSnapshot(
            target_node_id="home-node-a",
            service="home-center.service",
            load_state="loaded",
            active_state=active_state,
            sub_state="running" if active_state == "active" else "dead",
            unit_file_state="enabled",
        )

    def request(self, **values: str) -> OperationCommandRequest:
        return OperationCommandRequest(
            authorization_id=values.pop("authorization_id", "opauth-0123456789abcdef01234567"),
            idempotency_key=values.pop("idempotency_key", "restart-operation-001"),
            target_node_id=values.pop("target_node_id", "home-node-a"),
            service=values.pop("service", "home-center.service"),
            reason=values.pop("reason", "recover supervised service"),
            correlation_id=values.pop("correlation_id", "correlation-001"),
            action_id=values.pop("action_id", ACTION_ID),
        )

    def test_plan_is_deterministic_bounded_and_non_authoritative(self) -> None:
        admission = OperationCommandAdmission()
        first = admission.prepare(self.snapshot(), self.request())
        second = admission.prepare(self.snapshot(), self.request())
        self.assertEqual(first, second)
        value = first.to_dict()
        self.assertEqual([SYSTEMCTL, "restart", "home-center.service"], value["execution"]["argv"])
        self.assertIs(value["execution"]["shell"], False)
        self.assertIs(value["accepts_caller_argv"], False)
        self.assertIs(value["accepts_shell"], False)
        self.assertIs(value["execution_authorized"], False)
        self.assertIs(value["production_mutation_enabled"], False)
        self.assertTrue(value["audit"]["required"])

    def test_rollback_restores_observed_active_state(self) -> None:
        admission = OperationCommandAdmission()
        active = admission.prepare(self.snapshot("active"), self.request())
        inactive = admission.prepare(self.snapshot("inactive"), self.request())
        self.assertEqual((SYSTEMCTL, "start", "home-center.service"), active.rollback_argv)
        self.assertEqual((SYSTEMCTL, "stop", "home-center.service"), inactive.rollback_argv)
        self.assertEqual("active", active.rollback_expected_active_state)
        self.assertEqual("inactive", inactive.rollback_expected_active_state)

    def test_unknown_service_and_caller_action_are_rejected(self) -> None:
        with self.assertRaisesRegex(OperationCommandError, "service_not_allowlisted"):
            self.request(service="ssh.service")
        with self.assertRaisesRegex(OperationCommandError, "unsupported_action"):
            self.request(action_id="shell.exec.v1")

    def test_snapshot_and_target_must_match_exactly(self) -> None:
        admission = OperationCommandAdmission()
        with self.assertRaisesRegex(OperationCommandError, "target_snapshot_mismatch"):
            admission.prepare(self.snapshot(), self.request(target_node_id="home-node-b"))

    def test_unsafe_or_unloaded_snapshot_fails_closed(self) -> None:
        admission = OperationCommandAdmission()
        with self.assertRaisesRegex(OperationCommandError, "unsafe_active_state"):
            admission.prepare(self.snapshot("activating"), self.request())
        unloaded = ServiceStateSnapshot(
            target_node_id="home-node-a",
            service="home-center.service",
            load_state="not-found",
            active_state="inactive",
            sub_state="dead",
            unit_file_state="disabled",
        )
        with self.assertRaisesRegex(OperationCommandError, "service_not_loaded"):
            admission.prepare(unloaded, self.request())

    def test_authorization_and_idempotency_material_are_required(self) -> None:
        with self.assertRaisesRegex(OperationCommandError, "invalid_authorization"):
            self.request(authorization_id="owner-said-ok")
        with self.assertRaisesRegex(OperationCommandError, "invalid_idempotency_key"):
            self.request(idempotency_key="short")

    def test_state_machine_requires_rollback_after_possible_mutation(self) -> None:
        validate_job_transition(OperationJobState.PREPARED, OperationJobState.RUNNING)
        validate_job_transition(OperationJobState.RUNNING, OperationJobState.VERIFYING)
        validate_job_transition(OperationJobState.VERIFYING, OperationJobState.SUCCEEDED)
        validate_job_transition(
            OperationJobState.RUNNING,
            OperationJobState.ROLLING_BACK,
            mutation_may_have_occurred=True,
        )
        validate_job_transition(
            OperationJobState.ROLLING_BACK,
            OperationJobState.ROLLED_BACK,
            mutation_may_have_occurred=True,
        )
        with self.assertRaisesRegex(OperationCommandError, "rollback_required"):
            validate_job_transition(
                OperationJobState.RUNNING,
                OperationJobState.FAILED,
                mutation_may_have_occurred=True,
            )
        with self.assertRaisesRegex(OperationCommandError, "rollback_without_possible_mutation"):
            validate_job_transition(
                OperationJobState.RUNNING,
                OperationJobState.ROLLING_BACK,
                mutation_may_have_occurred=False,
            )

    def test_terminal_states_cannot_be_reopened(self) -> None:
        for terminal in (
            OperationJobState.SUCCEEDED,
            OperationJobState.ROLLED_BACK,
            OperationJobState.FAILED,
        ):
            with self.assertRaisesRegex(OperationCommandError, "invalid_job_transition"):
                validate_job_transition(terminal, OperationJobState.RUNNING)


if __name__ == "__main__":
    unittest.main()
