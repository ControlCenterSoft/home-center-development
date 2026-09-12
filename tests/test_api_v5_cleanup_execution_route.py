from home_center.api_v5 import RuntimeRequestHandlerV5


def test_failed_enrollment_cleanup_execution_route_is_explicitly_scoped() -> None:
    assert RuntimeRequestHandlerV5.FAILED_ENROLLMENT_CLEANUP_EXECUTION_POSTS == {
        "/api/v1/household/devices/enrollment/cleanup/execute"
    }
    assert RuntimeRequestHandlerV5.FAILED_ENROLLMENT_CLEANUP_EXECUTION_POSTS.isdisjoint(
        RuntimeRequestHandlerV5.DEENROLLMENT_EXECUTION_POSTS
    )
