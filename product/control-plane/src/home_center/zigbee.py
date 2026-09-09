"""Provider-neutral Zigbee discovery and pairing planning boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
MAX_CAPABILITIES = 128
MAX_DEVICES = 4096


class ZigbeeError(ValueError):
    """Stable public rejection for malformed provider or pairing facts."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ProviderHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise ZigbeeError(code)
    return value


def _bounded_identifiers(value: object, *, limit: int, code: str) -> tuple[str, ...]:
    if (
        not isinstance(value, tuple)
        or len(value) > limit
        or any(not isinstance(item, str) or ID.fullmatch(item) is None for item in value)
        or len(value) != len(set(value))
    ):
        raise ZigbeeError(code)
    return tuple(sorted(value))


@dataclass(frozen=True, slots=True)
class ZigbeeProviderSnapshot:
    provider_id: str
    coordinator_id: str
    health: ProviderHealth
    permit_join: bool
    capabilities: tuple[str, ...]
    known_devices: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.provider_id, "invalid_provider_identity")
        _identifier(self.coordinator_id, "invalid_provider_identity")
        if not isinstance(self.health, ProviderHealth) or not isinstance(self.permit_join, bool):
            raise ZigbeeError("invalid_provider_state")
        if (
            not isinstance(self.capabilities, tuple)
            or len(self.capabilities) > MAX_CAPABILITIES
            or any(
                not isinstance(capability, str)
                or CAPABILITY.fullmatch(capability) is None
                for capability in self.capabilities
            )
            or len(self.capabilities) != len(set(self.capabilities))
        ):
            raise ZigbeeError("invalid_capability")
        object.__setattr__(self, "capabilities", tuple(sorted(self.capabilities)))
        object.__setattr__(
            self,
            "known_devices",
            _bounded_identifiers(
                self.known_devices,
                limit=MAX_DEVICES,
                code="invalid_device_id",
            ),
        )


@dataclass(frozen=True, slots=True)
class PairingRequest:
    operation_id: str
    provider_id: str
    requested_device_id: str | None = None
    timeout_seconds: int = 120

    def __post_init__(self) -> None:
        _identifier(self.operation_id, "invalid_request_identity")
        _identifier(self.provider_id, "invalid_request_identity")
        if self.requested_device_id is not None:
            _identifier(self.requested_device_id, "invalid_device_id")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 10 <= self.timeout_seconds <= 900
        ):
            raise ZigbeeError("invalid_timeout")


@dataclass(frozen=True, slots=True)
class PairingPlan:
    operation_id: str
    provider_id: str
    state: str
    steps: tuple[str, ...]
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    schema: str = field(default="home-center.zigbee-pairing-plan.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "operation_id": self.operation_id,
            "provider_id": self.provider_id,
            "state": self.state,
            "steps": list(self.steps),
            "blockers": list(self.blockers),
            "production_mutation_enabled": False,
            "execution_authorized": False,
        }


class ZigbeePlanner:
    REQUIRED_CAPABILITY = "zigbee.pairing.v1"
    REQUIRED = REQUIRED_CAPABILITY

    def plan_pairing(
        self,
        request: PairingRequest,
        snapshot: ZigbeeProviderSnapshot,
    ) -> PairingPlan:
        if not isinstance(request, PairingRequest) or not isinstance(
            snapshot, ZigbeeProviderSnapshot
        ):
            raise ZigbeeError("invalid_planning_input")

        blockers: list[str] = []
        if request.provider_id != snapshot.provider_id:
            blockers.append("provider_identity_mismatch")
        if snapshot.health is not ProviderHealth.HEALTHY:
            blockers.append("provider_not_healthy")
        if self.REQUIRED_CAPABILITY not in snapshot.capabilities:
            blockers.append("pairing_capability_missing")
        if (
            request.requested_device_id is not None
            and request.requested_device_id in snapshot.known_devices
        ):
            blockers.append("device_already_registered")

        permit_join_step = (
            "confirm-permit-join" if snapshot.permit_join else "request-permit-join"
        )
        steps = (
            "validate-provider",
            permit_join_step,
            "observe-device",
            "validate-capabilities",
            "register-device",
            "close-permit-join",
        )
        return PairingPlan(
            request.operation_id,
            request.provider_id,
            "blocked" if blockers else "planned",
            steps if not blockers else (),
            tuple(blockers),
        )
