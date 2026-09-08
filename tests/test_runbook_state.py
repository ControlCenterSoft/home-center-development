from __future__ import annotations

import unittest

from home_center.runbook_state import StepState, evaluate_runbook


class RunbookStateTests(unittest.TestCase):
    def test_marks_dependency_free_step_ready(self) -> None:
        evaluation = evaluate_runbook(
            [
                StepState("prepare"),
                StepState("deploy", dependencies=("prepare",)),
            ]
        )
        self.assertEqual(evaluation.ready, ("prepare",))
        self.assertEqual(evaluation.blocked, ())
        self.assertFalse(evaluation.complete)

    def test_unlocks_step_after_dependency_success(self) -> None:
        evaluation = evaluate_runbook(
            [
                StepState("prepare", status="succeeded"),
                StepState("deploy", dependencies=("prepare",)),
            ]
        )
        self.assertEqual(evaluation.ready, ("deploy",))

    def test_blocks_step_after_dependency_failure(self) -> None:
        evaluation = evaluate_runbook(
            [
                StepState("prepare", status="failed"),
                StepState("deploy", dependencies=("prepare",)),
            ]
        )
        self.assertEqual(evaluation.blocked, ("deploy",))
        self.assertTrue(evaluation.failed)

    def test_detects_complete_runbook(self) -> None:
        evaluation = evaluate_runbook(
            [
                StepState("prepare", status="succeeded"),
                StepState("deploy", dependencies=("prepare",), status="succeeded"),
            ]
        )
        self.assertTrue(evaluation.complete)
        self.assertFalse(evaluation.failed)


if __name__ == "__main__":
    unittest.main()
