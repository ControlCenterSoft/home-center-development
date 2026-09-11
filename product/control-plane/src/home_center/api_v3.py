from __future__ import annotations

from http import HTTPStatus
from urllib.parse import urlsplit

from .api_v2 import RuntimeRequestHandlerV2
from .household_device_management import (
    HouseholdDeviceManagementError,
    management_report_from_runtime_status,
)
from .household_runtime import HouseholdRuntimeError


class RuntimeRequestHandlerV3(RuntimeRequestHandlerV2):
    """0.52 API extension for read-only Household device-management necessity."""

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != "/api/v1/household/devices/management":
            super().do_GET()
            return

        correlation_id = self._correlation_id()
        context = self._classify_request(correlation_id)
        if context is None:
            return
        if self._blocked_for_external(path, context):
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Ресурс не найден", correlation_id)
            return
        if not self._require_actor(correlation_id):
            return
        try:
            value = management_report_from_runtime_status(self.runtime.household.status())
        except (HouseholdRuntimeError, HouseholdDeviceManagementError) as exc:
            code = exc.code
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                code,
                "Статус необходимости управления устройствами временно недоступен",
                correlation_id,
            )
            return
        self._json(HTTPStatus.OK, value)
