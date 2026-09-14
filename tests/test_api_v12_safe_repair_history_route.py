from __future__ import annotations

from pathlib import Path

import pytest

from home_center.api_v11 import RuntimeRequestHandlerV11
from home_center.api_v12 import RuntimeRequestHandlerV12
from home_center.safe_auto_repair_read_api import SafeRepairHistoryReadError

ROOT = Path(__file__).resolve().parents[1]


def test_safe_repair_history_route_extends_v11_without_mutation_routes() -> None:
    assert issubclass(RuntimeRequestHandlerV12, RuntimeRequestHandlerV11)
    assert RuntimeRequestHandlerV12.SAFE_REPAIR_HISTORY_GET == "/api/v1/household/safe-repair/history"
    source = (ROOT / "product/control-plane/src/home_center/api_v12.py").read_text(encoding="utf-8")
    assert "def do_POST" not in source
    assert "SafeRepairWorkerService" not in source
    assert "adapter.execute" not in source


def test_history_query_is_closed_and_bounded() -> None:
    assert RuntimeRequestHandlerV12._history_query("") == (None, 50)
    assert RuntimeRequestHandlerV12._history_query("resource_id=derived-index-1&limit=25") == (
        "derived-index-1",
        25,
    )
    for query in (
        "unknown=x",
        "limit=0",
        "limit=101",
        "limit=-1",
        "limit=1&limit=2",
        "resource_id=",
        "resource_id=a&resource_id=b",
    ):
        with pytest.raises(SafeRepairHistoryReadError, match="safe_repair_history_http_query_invalid"):
            RuntimeRequestHandlerV12._history_query(query)


def test_server_wiring_uses_read_only_v12_handler() -> None:
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    assert "from .api_v12 import RuntimeRequestHandlerV12" in server
    assert "HomeCenterServer(config.web_bind, RuntimeRequestHandlerV12, runtime)" in server
