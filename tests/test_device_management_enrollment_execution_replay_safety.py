from __future__ import annotations

import pytest

from home_center.device_management_enrollment_execution_runtime import (
    CANCEL_ACTION,
    RETRY_ACTION,
    START_ACTION,
    DeviceManagementEnrollmentExecutionRuntimeError,
)
from home_center.device_management_enrollment_execution_runtime_safe import (
    SafeDeviceManagementEnrollmentExecutionRuntimeService,
)


class FakeStore:
    def __init__(self, jobs):
        self._jobs = list(jobs)

    def jobs(self, _limit=100):
        return list(self._jobs)

    def job(self, job_id):
        return next((job for job in self._jobs if job.get("job_id") == job_id), None)


class Harness(SafeDeviceManagementEnrollmentExecutionRuntimeService):
    def __init__(self, envelope, jobs):
        self.store = FakeStore(jobs)
        self.envelope = envelope

    def _load(self, plan_id):
        assert plan_id == "dmpexec-0123456789abcdef01234567"
        return "key", self.envelope, object()


PLAN_ID = "dmpexec-0123456789abcdef01234567"


def test_success_receipt_replays_only_with_original_idempotency_key() -> None:
    receipt = {"job_id": "job-start", "state": "provider-accepted"}
    jobs = [{
        "job_id": "job-start", "job_type": START_ACTION, "state": "succeeded",
        "idempotency_key": "same-key", "preflight": {"plan_id": PLAN_ID},
    }]
    service = Harness({"receipt": receipt, "cancel_receipt": None}, jobs)
    replay = service.start(
        actor="local-admin:admin",
        request={"plan_id": PLAN_ID, "idempotency_key": "same-key"},
        correlation_id="replay",
    )
    assert replay == receipt
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="already_started"):
        service.start(
            actor="local-admin:admin",
            request={"plan_id": PLAN_ID, "idempotency_key": "different-key"},
            correlation_id="duplicate",
        )


def test_failed_start_cannot_be_bypassed_with_fresh_start_key() -> None:
    jobs = [{
        "job_id": "job-failed", "job_type": START_ACTION, "state": "failed",
        "idempotency_key": "first-key", "preflight": {"plan_id": PLAN_ID},
        "result": {"retry_safe": False},
    }]
    service = Harness({"receipt": None, "cancel_receipt": None}, jobs)
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="retry_required"):
        service.start(
            actor="local-admin:admin",
            request={"plan_id": PLAN_ID, "idempotency_key": "fresh-key"},
            correlation_id="fresh-start",
        )


def test_retry_cannot_select_older_safe_failure_after_newer_ambiguous_failure() -> None:
    jobs = [
        {
            "job_id": "job-newer", "job_type": RETRY_ACTION, "state": "failed",
            "idempotency_key": "retry-1", "preflight": {"plan_id": PLAN_ID},
            "result": {"retry_safe": False},
        },
        {
            "job_id": "job-older", "job_type": START_ACTION, "state": "failed",
            "idempotency_key": "start-1", "preflight": {"plan_id": PLAN_ID},
            "result": {"retry_safe": True},
        },
    ]
    service = Harness({"receipt": None, "cancel_receipt": None}, jobs)
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="retry_not_allowed"):
        service.retry(
            actor="local-admin:admin",
            request={"plan_id": PLAN_ID, "failed_job_id": "job-older", "idempotency_key": "retry-2"},
            correlation_id="unsafe-old-retry",
        )
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="retry_not_safe"):
        service.retry(
            actor="local-admin:admin",
            request={"plan_id": PLAN_ID, "failed_job_id": "job-newer", "idempotency_key": "retry-2"},
            correlation_id="ambiguous-new-retry",
        )


def test_ambiguous_cancel_cannot_be_reissued_automatically() -> None:
    receipt = {"job_id": "job-start", "state": "provider-accepted"}
    jobs = [
        {"job_id": "job-start", "job_type": START_ACTION, "state": "succeeded", "idempotency_key": "start-key", "preflight": {"plan_id": PLAN_ID}},
        {"job_id": "job-cancel", "job_type": CANCEL_ACTION, "state": "failed", "idempotency_key": "cancel-key", "preflight": {"plan_id": PLAN_ID}},
    ]
    service = Harness({"receipt": receipt, "cancel_receipt": None}, jobs)
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="cancel_retry_not_safe"):
        service.cancel(
            actor="local-admin:admin",
            request={"plan_id": PLAN_ID, "start_job_id": "job-start", "idempotency_key": "cancel-fresh"},
            correlation_id="cancel-retry",
        )
