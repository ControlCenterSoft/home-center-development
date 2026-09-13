from __future__ import annotations

from pathlib import Path

import pytest

from home_center.api_v8 import RuntimeRequestHandlerV8
from home_center.api_v9 import (
    DESIRED_PATH,
    PREVIEW_PATH,
    RuntimeRequestHandlerV9,
    _desired_query,
)

ROOT = Path(__file__).resolve().parents[1]


def test_parental_read_routes_extend_v8_without_exposing_mutation() -> None:
    assert DESIRED_PATH == "/api/v1/household/parental-internet/desired"
    assert PREVIEW_PATH == "/api/v1/household/parental-internet/decision-preview"
    assert issubclass(RuntimeRequestHandlerV9, RuntimeRequestHandlerV8)
    source = (ROOT / "product/control-plane/src/home_center/api_v9.py").read_text(encoding="utf-8")
    assert "/plan" not in source
    assert "/confirm" not in source
    assert "/execute" not in source
    assert "ParentalInternetPolicyReadAPIService" in source
    assert "_same_origin_post_allowed" in source
    assert "_require_actor" in source
    assert "max_bytes=4096" in source


def test_saved_policy_query_is_strict_and_view_bounded() -> None:
    assert _desired_query(
        DESIRED_PATH + "?member_id=member-child&view=cozy"
    ) == ("member-child", "cozy")
    assert _desired_query(
        DESIRED_PATH + "?view=full&member_id=member-child"
    ) == ("member-child", "full")

    with pytest.raises(ValueError):
        _desired_query(DESIRED_PATH + "?member_id=member-child")
    with pytest.raises(ValueError):
        _desired_query(DESIRED_PATH + "?member_id=member-child&view=raw")
    with pytest.raises(ValueError):
        _desired_query(DESIRED_PATH + "?member_id=member-child&view=cozy&extra=1")
    with pytest.raises(ValueError):
        _desired_query(DESIRED_PATH + "?member_id=a&member_id=b&view=cozy")


def test_server_uses_latest_parental_read_handler() -> None:
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    assert "from .api_v9 import RuntimeRequestHandlerV9" in server
    assert "HomeCenterServer(config.web_bind, RuntimeRequestHandlerV9, runtime)" in server
    assert "RuntimeRequestHandlerV8, runtime" not in server


def test_release_wheel_requires_parental_read_runtime() -> None:
    qualifier = (ROOT / "scripts/qualify_release_artifact.py").read_text(encoding="utf-8")
    assert '"home_center/api_v9.py"' in qualifier
    assert '"home_center/parental_internet_policy_read_api.py"' in qualifier
