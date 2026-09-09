"""Typed, secret-free Home Center 0.19 home-service catalog."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Iterable, Mapping


SCHEMA = "home-center.home-service-catalog.v1"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
MAX_CAPABILITIES = 128
BLOCKER = re.compile(r"^[a-z0-9][a-z0-9_.:-]{1,191}$")
MAX_BLOCKERS = 128


class HomeServiceCatalogError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class HomeServiceKind(StrEnum):
    YANDEX_SMART_HOME = "yandex-smart-home"
    TORRSERVER = "torrserver"
    TORRENT_CLIENT = "torrent-client"
    ZIGBEE_BRIDGE = "zigbee-bridge"
    MINECRAFT_SERVER = "minecraft-server"
    ANDROID_MDM = "android-mdm"


class PublicationPolicy(StrEnum):
    LOCAL_ONLY = "local-only"
    EXPLICIT = "explicit"


class BackupPolicy(StrEnum):
    NONE = "none"
    CONFIGURATION = "configuration"
    STATE = "state"


class DeploymentPlanState(StrEnum):
    PLANNED = "planned"
    BLOCKED = "blocked"


REQUIRED_LIFECYCLE = (
    "install",
    "configure",
    "health",
    "update",
    "backup",
    "restore",
    "remove",
)


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise HomeServiceCatalogError(code)
    return value


def _capabilities(values: Iterable[str], code: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise HomeServiceCatalogError(code)
    try:
        result = tuple(values)
    except TypeError as exc:
        raise HomeServiceCatalogError(code) from exc
    if (
        len(result) > MAX_CAPABILITIES
        or len(result) != len(set(result))
        or any(not isinstance(value, str) or CAPABILITY.fullmatch(value) is None for value in result)
    ):
        raise HomeServiceCatalogError(code)
    return tuple(sorted(result))


@dataclass(frozen=True, slots=True)
class HomeServiceProfile:
    service_id: str
    kind: HomeServiceKind
    name: str
    required_capabilities: tuple[str, ...]
    provided_capabilities: tuple[str, ...]
    minimum_storage_gib: int
    publication_policy: PublicationPolicy
    backup_policy: BackupPolicy
    lifecycle: tuple[str, ...] = field(default=REQUIRED_LIFECYCLE)

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_id", _identifier(self.service_id, "invalid_service_id"))
        if not isinstance(self.kind, HomeServiceKind):
            raise HomeServiceCatalogError("invalid_service_kind")
        if not isinstance(self.name, str) or not 1 <= len(self.name.strip()) <= 80:
            raise HomeServiceCatalogError("invalid_service_name")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(
            self,
            "required_capabilities",
            _capabilities(self.required_capabilities, "invalid_required_capabilities"),
        )
        object.__setattr__(
            self,
            "provided_capabilities",
            _capabilities(self.provided_capabilities, "invalid_provided_capabilities"),
        )
        if (
            not isinstance(self.minimum_storage_gib, int)
            or isinstance(self.minimum_storage_gib, bool)
            or not 1 <= self.minimum_storage_gib <= 1_048_576
        ):
            raise HomeServiceCatalogError("invalid_minimum_storage")
        if not isinstance(self.publication_policy, PublicationPolicy):
            raise HomeServiceCatalogError("invalid_publication_policy")
        if not isinstance(self.backup_policy, BackupPolicy):
            raise HomeServiceCatalogError("invalid_backup_policy")
        if self.lifecycle != REQUIRED_LIFECYCLE:
            raise HomeServiceCatalogError("invalid_lifecycle")

    def to_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "kind": self.kind.value,
            "name": self.name,
            "required_capabilities": list(self.required_capabilities),
            "provided_capabilities": list(self.provided_capabilities),
            "minimum_storage_gib": self.minimum_storage_gib,
            "publication_policy": self.publication_policy.value,
            "backup_policy": self.backup_policy.value,
            "lifecycle": list(self.lifecycle),
        }


@dataclass(frozen=True, slots=True)
class HomeServiceCatalog:
    profiles: tuple[HomeServiceProfile, ...]
    schema: str = field(default=SCHEMA, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.profiles, tuple) or len(self.profiles) > 128:
            raise HomeServiceCatalogError("invalid_profiles")
        if any(not isinstance(profile, HomeServiceProfile) for profile in self.profiles):
            raise HomeServiceCatalogError("invalid_profiles")
        identities = [profile.service_id for profile in self.profiles]
        kinds = [profile.kind for profile in self.profiles]
        if len(identities) != len(set(identities)):
            raise HomeServiceCatalogError("duplicate_service_id")
        if len(kinds) != len(set(kinds)):
            raise HomeServiceCatalogError("duplicate_service_kind")
        if tuple(sorted(identities)) != tuple(identities):
            raise HomeServiceCatalogError("noncanonical_profile_order")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "production_mutation_enabled": False,
            "profiles": [profile.to_dict() for profile in self.profiles],
        }


def _profile(
    service_id: str,
    kind: HomeServiceKind,
    name: str,
    *,
    required: tuple[str, ...],
    provided: tuple[str, ...],
    storage_gib: int,
    publication: PublicationPolicy = PublicationPolicy.EXPLICIT,
    backup: BackupPolicy = BackupPolicy.STATE,
) -> HomeServiceProfile:
    return HomeServiceProfile(
        service_id,
        kind,
        name,
        required,
        provided,
        storage_gib,
        publication,
        backup,
    )


BUILTIN_HOME_SERVICES = HomeServiceCatalog(
    tuple(
        sorted(
            (
                _profile(
                    "android-mdm",
                    HomeServiceKind.ANDROID_MDM,
                    "Android Device Management",
                    required=("runtime.container.v1", "network.lan.v1", "certificates.lifecycle.v1"),
                    provided=("android.enrollment.v1", "android.policy.v1"),
                    storage_gib=8,
                ),
                _profile(
                    "minecraft-server",
                    HomeServiceKind.MINECRAFT_SERVER,
                    "Minecraft Server",
                    required=("runtime.container.v1", "network.lan.v1"),
                    provided=("games.minecraft.v1",),
                    storage_gib=16,
                ),
                _profile(
                    "torrent-client",
                    HomeServiceKind.TORRENT_CLIENT,
                    "Torrent Client",
                    required=("runtime.container.v1", "storage.bulk.v1", "network.lan.v1"),
                    provided=("downloads.torrent.v1",),
                    storage_gib=8,
                    publication=PublicationPolicy.LOCAL_ONLY,
                ),
                _profile(
                    "torrserver",
                    HomeServiceKind.TORRSERVER,
                    "TorrServer",
                    required=("runtime.container.v1", "storage.bulk.v1", "network.lan.v1"),
                    provided=("media.torrent-stream.v1",),
                    storage_gib=8,
                ),
                _profile(
                    "yandex-smart-home",
                    HomeServiceKind.YANDEX_SMART_HOME,
                    "Yandex Smart Home Bridge",
                    required=("runtime.container.v1", "devices.registry.v1", "network.outbound.v1"),
                    provided=("smart-home.yandex.v1",),
                    storage_gib=4,
                    backup=BackupPolicy.CONFIGURATION,
                ),
                _profile(
                    "zigbee-bridge",
                    HomeServiceKind.ZIGBEE_BRIDGE,
                    "ZigBee Bridge",
                    required=("runtime.container.v1", "devices.usb.v1", "network.lan.v1"),
                    provided=("devices.zigbee.v1",),
                    storage_gib=4,
                    publication=PublicationPolicy.LOCAL_ONLY,
                    backup=BackupPolicy.CONFIGURATION,
                ),
            ),
            key=lambda item: item.service_id,
        )
    )
)


HOME_SERVICE_BY_ID: Mapping[str, HomeServiceProfile] = MappingProxyType(
    {profile.service_id: profile for profile in BUILTIN_HOME_SERVICES.profiles}
)


@dataclass(frozen=True, slots=True)
class NodeCapabilitySnapshot:
    node_id: str
    capabilities: tuple[str, ...]
    free_storage_gib: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _identifier(self.node_id, "invalid_node_id"))
        object.__setattr__(
            self,
            "capabilities",
            _capabilities(self.capabilities, "invalid_node_capabilities"),
        )
        if (
            not isinstance(self.free_storage_gib, int)
            or isinstance(self.free_storage_gib, bool)
            or not 0 <= self.free_storage_gib <= 1_048_576
        ):
            raise HomeServiceCatalogError("invalid_free_storage")


@dataclass(frozen=True, slots=True)
class HomeServiceDeploymentRequest:
    service_id: str
    target_node_id: str
    external_publication_requested: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_id", _identifier(self.service_id, "invalid_service_id"))
        object.__setattr__(self, "target_node_id", _identifier(self.target_node_id, "invalid_node_id"))
        if not isinstance(self.external_publication_requested, bool):
            raise HomeServiceCatalogError("invalid_publication_request")


@dataclass(frozen=True, slots=True)
class HomeServiceDeploymentPlan:
    service_id: str
    target_node_id: str
    state: DeploymentPlanState
    blockers: tuple[str, ...]
    external_publication_enabled: bool
    approval_required: bool = field(default=True, init=False)
    execution_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)
    schema: str = field(default="home-center.home-service-deployment-plan.v1", init=False)

    def __post_init__(self) -> None:
        _identifier(self.service_id, "invalid_service_id")
        _identifier(self.target_node_id, "invalid_node_id")
        if not isinstance(self.state, DeploymentPlanState):
            raise HomeServiceCatalogError("invalid_deployment_state")
        if (
            not isinstance(self.blockers, tuple)
            or len(self.blockers) > MAX_BLOCKERS
            or len(self.blockers) != len(set(self.blockers))
            or tuple(sorted(self.blockers)) != self.blockers
            or any(not isinstance(item, str) or BLOCKER.fullmatch(item) is None for item in self.blockers)
        ):
            raise HomeServiceCatalogError("invalid_deployment_blockers")
        if (self.state is DeploymentPlanState.PLANNED) == bool(self.blockers):
            raise HomeServiceCatalogError("inconsistent_deployment_plan")
        if not isinstance(self.external_publication_enabled, bool):
            raise HomeServiceCatalogError("invalid_publication_state")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "service_id": self.service_id,
            "target_node_id": self.target_node_id,
            "state": self.state.value,
            "blockers": list(self.blockers),
            "external_publication_enabled": self.external_publication_enabled,
            "approval_required": True,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }


class HomeServiceDeploymentPlanner:
    """Build a deterministic deployment preflight without executing actions."""

    def __init__(self, profiles: Mapping[str, HomeServiceProfile] = HOME_SERVICE_BY_ID) -> None:
        if not isinstance(profiles, Mapping):
            raise HomeServiceCatalogError("invalid_catalog")
        self._profiles = MappingProxyType(dict(profiles))

    def plan(
        self,
        request: HomeServiceDeploymentRequest,
        node: NodeCapabilitySnapshot,
    ) -> HomeServiceDeploymentPlan:
        if not isinstance(request, HomeServiceDeploymentRequest):
            raise HomeServiceCatalogError("invalid_deployment_request")
        if not isinstance(node, NodeCapabilitySnapshot):
            raise HomeServiceCatalogError("invalid_node_snapshot")

        blockers: set[str] = set()
        if request.target_node_id != node.node_id:
            blockers.add("target_node_mismatch")
        profile = self._profiles.get(request.service_id)
        if profile is None:
            blockers.add("unknown_service")
        else:
            for capability in set(profile.required_capabilities).difference(node.capabilities):
                blockers.add(f"missing_capability:{capability}")
            if node.free_storage_gib < profile.minimum_storage_gib:
                blockers.add("insufficient_storage")
            if request.external_publication_requested:
                if profile.publication_policy is PublicationPolicy.LOCAL_ONLY:
                    blockers.add("publication_forbidden")
                elif "network.external-publication.v1" not in node.capabilities:
                    blockers.add("missing_capability:network.external-publication.v1")

        canonical = tuple(sorted(blockers))
        return HomeServiceDeploymentPlan(
            service_id=request.service_id,
            target_node_id=request.target_node_id,
            state=DeploymentPlanState.BLOCKED if canonical else DeploymentPlanState.PLANNED,
            blockers=canonical,
            external_publication_enabled=request.external_publication_requested and not canonical,
        )
