from __future__ import annotations

import unittest

from home_center.module_home_service_multi_requirements import (
    ModuleHomeServiceMultiRequirementError,
    build_module_home_service_multi_requirement_set,
)


class ModuleHomeServiceMultiRequirementBoundsTests(unittest.TestCase):
    def test_oversized_lazy_input_is_bounded_before_validation(self) -> None:
        consumed = 0

        def oversized():
            nonlocal consumed
            while True:
                consumed += 1
                if consumed > 65:
                    raise AssertionError(
                        "multi-requirement input was consumed past bound"
                    )
                yield object()

        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_sets_rejected",
        ):
            build_module_home_service_multi_requirement_set(oversized())

        self.assertEqual(consumed, 65)

    def test_non_iterable_input_has_stable_rejection_code(self) -> None:
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_sets_rejected",
        ):
            build_module_home_service_multi_requirement_set(None)  # type: ignore[arg-type]

    def test_mapping_input_is_rejected_before_key_iteration(self) -> None:
        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_sets_rejected",
        ):
            build_module_home_service_multi_requirement_set({"a": "b"})

    def test_iterator_failure_is_normalized_to_stable_rejection_code(self) -> None:
        class BrokenIterable:
            def __iter__(self):
                yield object()
                raise RuntimeError("provider iterator failed")

        with self.assertRaisesRegex(
            ModuleHomeServiceMultiRequirementError,
            "service_requirement_sets_rejected",
        ):
            build_module_home_service_multi_requirement_set(BrokenIterable())


if __name__ == "__main__":
    unittest.main()
