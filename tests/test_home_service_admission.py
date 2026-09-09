from __future__ import annotations

import unittest

from home_center.home_service_admission import ApprovalEvidence, DurableJobBinding, admit_operation
from home_center.home_service_operations import HomeServiceInstanceSnapshot, HomeServiceInstanceState, HomeServiceOperation, HomeServiceOperationPlanner, HomeServiceOperationRequest
from home_center.home_services import HomeServiceCatalogError


class HomeServiceAdmissionTests(unittest.TestCase):
    def inputs(self):
        snapshot = HomeServiceInstanceSnapshot("minecraft-main", "minecraft-server", "home-node-a", HomeServiceInstanceState.READY, 7, "rv:instance:7")
        plan = HomeServiceOperationPlanner().plan(snapshot, HomeServiceOperationRequest(HomeServiceOperation.UPDATE, 7, "rv:instance:7", "update-001"))
        approval = ApprovalEvidence("approval-001", plan.plan_id, "local-admin", "Apply verified update")
        job = DurableJobBinding("job-001", plan.plan_id, "preflight")
        return snapshot, plan, approval, job

    def test_admission_binds_plan_approval_job_audit_and_cas(self) -> None:
        snapshot, plan, approval, job = self.inputs()
        first = admit_operation(plan, snapshot, approval, job, audit_correlation_id="audit-001")
        second = admit_operation(plan, snapshot, approval, job, audit_correlation_id="audit-001")
        self.assertEqual(first, second)
        value = first.to_dict()
        self.assertTrue(value["admitted"])
        self.assertTrue(value["worker_claim_authorized"])
        self.assertTrue(value["revalidate_before_claim"])
        self.assertFalse(value["direct_execution"])
        self.assertFalse(value["production_mutation_enabled"])
        self.assertFalse(value["accepts_secret_values"])

    def test_mismatched_approval_or_job_fails_closed(self) -> None:
        snapshot, plan, _, _ = self.inputs()
        with self.assertRaisesRegex(HomeServiceCatalogError, "plan_binding_mismatch"):
            admit_operation(plan, snapshot, ApprovalEvidence("approval-001", "hsop-wrong", "local-admin", "Approved"), DurableJobBinding("job-001", plan.plan_id, "preflight"), audit_correlation_id="audit-001")

    def test_stale_instance_snapshot_fails_closed(self) -> None:
        snapshot, plan, approval, job = self.inputs()
        stale = HomeServiceInstanceSnapshot(snapshot.instance_id, snapshot.service_id, snapshot.target_node_id, snapshot.state, 8, "rv:instance:8")
        with self.assertRaisesRegex(HomeServiceCatalogError, "admission_precondition_failed"):
            admit_operation(plan, stale, approval, job, audit_correlation_id="audit-001")

    def test_secret_references_are_preserved_without_values(self) -> None:
        snapshot = HomeServiceInstanceSnapshot("zigbee-main", "zigbee-bridge", "home-node-a", HomeServiceInstanceState.INSTALLED, 3, "rv:instance:3")
        plan = HomeServiceOperationPlanner().plan(snapshot, HomeServiceOperationRequest(HomeServiceOperation.CONFIGURE, 3, "rv:instance:3", "configure-001", configuration_revision_id="config:3", secret_references=("secret:zigbee",)))
        admission = admit_operation(plan, snapshot, ApprovalEvidence("approval-002", plan.plan_id, "local-admin", "Configure bridge"), DurableJobBinding("job-002", plan.plan_id, "preflight"), audit_correlation_id="audit-002")
        self.assertEqual(["secret:zigbee"], admission.to_dict()["secret_references"])
        self.assertNotIn("secret_values", admission.to_dict())


if __name__ == "__main__":
    unittest.main()
