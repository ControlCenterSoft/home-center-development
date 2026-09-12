from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "product" / "control-plane" / "src" / "home_center" / "runtime.py"


def test_runtime_composition_root_selects_guarded_policy_workflow() -> None:
    runtime = RUNTIME.read_text(encoding="utf-8")

    assert "from .household_policy_guarded_workflow import (" in runtime
    assert "GuardedHouseholdPolicyWorkflowService as HouseholdPolicyWorkflowService" in runtime
    assert "from .household_policy_workflow import HouseholdPolicyWorkflowService" not in runtime
