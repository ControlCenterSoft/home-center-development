from home_center.api_v5 import RuntimeRequestHandlerV5
from home_center.api_v6 import RuntimeRequestHandlerV6
from home_center.api_v7 import RuntimeRequestHandlerV7


def test_policy_reconciliation_route_is_explicitly_read_only_scope() -> None:
    assert RuntimeRequestHandlerV7.POLICY_RECONCILIATION_POSTS == {
        "/api/v1/household/policy/reconciliation"
    }
    assert issubclass(RuntimeRequestHandlerV7, RuntimeRequestHandlerV6)
    assert issubclass(RuntimeRequestHandlerV6, RuntimeRequestHandlerV5)
    assert RuntimeRequestHandlerV7.do_GET is RuntimeRequestHandlerV6.do_GET
    assert RuntimeRequestHandlerV7.POLICY_RECONCILIATION_POSTS.isdisjoint(
        RuntimeRequestHandlerV5.DEENROLLMENT_EXECUTION_POSTS
        | RuntimeRequestHandlerV5.FAILED_ENROLLMENT_CLEANUP_EXECUTION_POSTS
    )
