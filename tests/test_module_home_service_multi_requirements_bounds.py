from __future__ import annotations

import pytest

from home_center.module_home_service_multi_requirements import (
    ModuleHomeServiceMultiRequirementError,
    build_module_home_service_multi_requirement_set,
)


def test_oversized_lazy_input_is_bounded_before_validation() -> None:
    consumed = 0

    def oversized():
        nonlocal consumed
        while True:
            consumed += 1
            if consumed > 65:
                raise AssertionError("multi-requirement input was consumed past bound")
            yield object()

    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="service_requirement_sets_rejected",
    ):
        build_module_home_service_multi_requirement_set(oversized())

    assert consumed == 65


def test_non_iterable_input_has_stable_rejection_code() -> None:
    with pytest.raises(
        ModuleHomeServiceMultiRequirementError,
        match="service_requirement_sets_rejected",
    ):
        build_module_home_service_multi_requirement_set(None)  # type: ignore[arg-type]
