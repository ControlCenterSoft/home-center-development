from home_center.api_v5 import RuntimeRequestHandlerV5
from home_center.api_v6 import RuntimeRequestHandlerV6


def test_policy_reconciliation_route_is_explicitly_read_only_scope() -> None:
    assert RuntimeRequestHandlerV6.POLICY_RECONCILIATION_POSTS == {
        "/api/v1/household/policy/reconciliation"
    }
    assert issubclass(RuntimeRequestHandlerV6, RuntimeRequestHandlerV5)
    assert RuntimeRequestHandlerV6.POLICY_RECONCILIATION_POSTS.isdisjoint(
        RuntimeRequestHandlerV5.DEENROLLMENT_EXECUTION_POSTS
        | RuntimeRequestHandlerV5.FAILED_ENROLLMENT_CLEANUP_EXECUTION_POSTS
    )
