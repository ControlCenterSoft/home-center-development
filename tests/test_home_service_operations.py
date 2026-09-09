from __future__ import annotations

import unittest

from home_center.home_service_operations import (
    HomeServiceInstanceSnapshot,
    HomeServiceInstanceState,
    HomeServiceOperation,
    HomeServiceOperationPlanner,
    HomeServiceOperationRequest,
)
from home_center.home_services import HomeServiceCatalogError


class HomeServiceOperationPlannerTests(unittest.TestCase):
    def snapshot(
        self,
        state: HomeServiceInstanceState = HomeServiceInstanceState.READY,
        service_id: str = "minecraft-server",
    ) -> HomeServiceInstanceSnapshot:
        return HomeServiceInstanceSnapshot(
            "minecraft-main",
            service_id,
            "home-node-a",
            state,
            7,
            "rv:instance:7",
        )

    def request(
        self,
        operation: HomeServiceOperation,
        **values: object,
    ) -> HomeServiceOperationRequest:
        return HomeServiceOperationRequest(
            operation,
            7,
            "rv:instance:7",
            str(values.pop("idempotency_key", "operation-001")),
            **values,
        )

    def test_plan_is_deterministic_secret_free_and_non_authoritative(self) -> None:
        snapshot = self.snapshot(HomeServiceInstanceState.INSTALLED)
        request = self.request(
            HomeServiceOperation.CONFIGURE,
            configuration_revision_id="config:12",
            secret_references=("secret:yandex", "secret:admin"),
        )
        first = HomeServiceOperationPlanner().plan(snapshot, request)
        second = HomeServiceOperationPlanner().plan(snapshot, request)
        self.assertEqual(first, second)
        value = first.to_dict()
        self.assertEqual(["secret:admin", "secret:yandex"], value["secret_references"])
        self.assertIn("secret-references.resolve-at-execution", value["steps"])
        self.assertNotIn("password", repr(value).lower())
        self.assertIs(value["approval_required"], True)
        self.assertIs(value["durable_job_required"], True)
        self.assertIs(value["audit_required"], True)
        self.assertIs(value["execution_authorized"], False)
        self.assertIs(value["production_mutation_enabled"], False)
        self.assertIs(value["accepts_secret_values"], False)

    def test_lifecycle_operations_enforce_state_and_backup_boundaries(self) -> None:
        planner = HomeServiceOperationPlanner()
        install = planner.plan(
            self.snapshot(HomeServiceInstanceState.PLANNED),
            self.request(HomeServiceOperation.INSTALL),
        )
        self.assertEqual(HomeServiceInstanceState.INSTALLED, install.target_state)

        update = planner.plan(
            self.snapshot(HomeServiceInstanceState.READY),
            self.request(HomeServiceOperation.UPDATE),
        )
        self.assertEqual("backup.pre-update", update.steps[0])

        restore = planner.plan(
            self.snapshot(HomeServiceInstanceState.DEGRADED),
            self.request(HomeServiceOperation.RESTORE, restore_point_id="backup:42"),
        )
        self.assertIn("service.quiesce", restore.steps)

        with self.assertRaisesRegex(HomeServiceCatalogError, "invalid_operation_state"):
            planner.plan(
                self.snapshot(HomeServiceInstanceState.PLANNED),
                self.request(HomeServiceOperation.UPDATE),
            )

    def test_compare_and_swap_preconditions_fail_closed(self) -> None:
        planner = HomeServiceOperationPlanner()
        with self.assertRaisesRegex(HomeServiceCatalogError, "operation_precondition_failed"):
            planner.plan(
                self.snapshot(),
                HomeServiceOperationRequest(
                    HomeServiceOperation.HEALTH,
                    6,
                    "rv:instance:7",
                    "operation-stale",
                ),
            )
        with self.assertRaisesRegex(HomeServiceCatalogError, "operation_precondition_failed"):
            planner.plan(
                self.snapshot(),
                HomeServiceOperationRequest(
                    HomeServiceOperation.HEALTH,
                    7,
                    "rv:stale",
                    "operation-stale",
                ),
            )

    def test_remove_disables_publication_before_service_removal(self) -> None:
        plan = HomeServiceOperationPlanner().plan(
            self.snapshot(),
            self.request(HomeServiceOperation.REMOVE),
        )
        self.assertEqual(HomeServiceInstanceState.REMOVED, plan.target_state)
        self.assertEqual("external-publication.disable", plan.steps[0])
        self.assertLess(plan.steps.index("external-publication.disable"), plan.steps.index("service.remove"))

    def test_invalid_secret_and_restore_inputs_are_rejected(self) -> None:
        with self.assertRaisesRegex(HomeServiceCatalogError, "duplicate_secret_reference"):
            self.request(
                HomeServiceOperation.CONFIGURE,
                configuration_revision_id="config:12",
                secret_references=("secret:one", "secret:one"),
            )
        with self.assertRaisesRegex(HomeServiceCatalogError, "restore_point_required"):
            HomeServiceOperationPlanner().plan(
                self.snapshot(),
                self.request(HomeServiceOperation.RESTORE),
            )


if __name__ == "__main__":
    unittest.main()
