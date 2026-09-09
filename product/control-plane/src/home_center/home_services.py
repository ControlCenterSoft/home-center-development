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
