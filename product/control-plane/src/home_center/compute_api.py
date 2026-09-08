"""Public plan-only API boundary for compute capacity decisions."""

from __future__ import annotations

from typing import Any, Mapping

from .core.compute_framework import ComputeCapacityPlanningRequest, ComputePlanner


class ComputeCapacityPlanningApi:
    """Validate an external payload and return one canonical planning result."""

    def __init__(self, planner: ComputePlanner | None = None) -> None:
        self._planner = planner or ComputePlanner()

    def plan(self, payload: Mapping[str, Any]) -> dict[str, object]:
        request = ComputeCapacityPlanningRequest.from_mapping(payload)
        return self._planner.plan_capacity(request).to_dict()
