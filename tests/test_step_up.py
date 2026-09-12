from __future__ import annotations

import pytest

from home_center.step_up import StepUpError, StepUpGrantManager


def test_step_up_grant_is_actor_scope_bound_and_single_use() -> None:
    now = [100.0]
    manager = StepUpGrantManager(lifetime_seconds=60, clock=lambda: now[0])
    scope = "household.device.management.enrollment.verify:dmpverify-" + "a" * 24
    token, ttl = manager.issue(actor="local-admin:admin", scope=scope)

    assert ttl == 60
    with pytest.raises(StepUpError, match="step_up_binding_mismatch"):
        manager.consume(actor="local-admin:other", scope=scope, token=token)
    with pytest.raises(StepUpError, match="step_up_required"):
        manager.consume(actor="local-admin:admin", scope=scope, token=token)


def test_step_up_grant_succeeds_once_and_expires_fail_closed() -> None:
    now = [100.0]
    manager = StepUpGrantManager(lifetime_seconds=60, clock=lambda: now[0])
    scope = "household.device.management.enrollment.verify:dmpverify-" + "b" * 24
    token, _ = manager.issue(actor="local-admin:admin", scope=scope)
    manager.consume(actor="local-admin:admin", scope=scope, token=token)
    with pytest.raises(StepUpError, match="step_up_required"):
        manager.consume(actor="local-admin:admin", scope=scope, token=token)

    token2, _ = manager.issue(actor="local-admin:admin", scope=scope)
    now[0] = 161.0
    with pytest.raises(StepUpError, match="step_up_required"):
        manager.consume(actor="local-admin:admin", scope=scope, token=token2)
