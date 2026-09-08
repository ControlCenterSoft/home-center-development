from __future__ import annotations

import unittest

from home_center.automation_runbook import RunbookStep, plan_runbook


class AutomationRunbookTests(unittest.TestCase):
    def test_dependencies_are_respected(self) -> None:
        plan = plan_runbook(
            [
                RunbookStep("configure", "ansible.apply", ("discover",)),
                RunbookStep("verify", "health.verify", ("configure",)),
                RunbookStep("discover", "inventory.refresh"),
            ]
        )
        self.assertEqual(
            ["discover", "configure", "verify"],
            [step.step_id for step in plan.ordered_steps],
        )

    def test_independent_steps_have_stable_order(self) -> None:
        plan = plan_runbook(
            [
                RunbookStep("zeta", "noop"),
                RunbookStep("alpha", "noop"),
            ]
        )
        self.assertEqual(["alpha", "zeta"], [s.step_id for s in plan.ordered_steps])

    def test_unknown_dependency_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown step"):
            plan_runbook([RunbookStep("configure", "apply", ("missing",))])

    def test_cycle_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "cycle"):
            plan_runbook(
                [
                    RunbookStep("a", "noop", ("b",)),
                    RunbookStep("b", "noop", ("a",)),
                ]
            )


if __name__ == "__main__":
    unittest.main()
