"""Fail-closed trusted reverse-proxy boundary for optional external access.

The Home Center listeners remain bound to their configured management address.
This module only classifies requests that have already arrived through an
explicitly trusted HTTPS gateway. It never opens ports, configures NAT/DDNS,
or grants authority to ambient forwarding headers.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Protocol


FORWARDED_HEADERS = ("Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host")
X_FORWARDED_HEADERS = ("X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TRUSTED_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)
TRUSTED_IPV6_NETWORKS = tuple(ipaddress.ip_network(value) for value in ("fc00::/7", "::1/128"))


class HeaderValues(Protocol):
    def get_all(self, name: str, failobj: object = ...) -> list[str] | None: ...


class ExternalAccessRejected(ValueError):
    """A proxy-shaped request did not satisfy the configured trust boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def normalize_public_hostname(value: str) -> str:
    """Return a canonical, port-free ASCII FQDN for exact comparisons."""

    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= 253:
        raise ValueError("external_public_hostname_rejected")
    try:
        hostname = value.encode("ascii", errors="strict").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("external_public_hostname_rejected") from exc
    if "." not in hostname or hostname.endswith("."):
        raise ValueError("external_public_hostname_rejected")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("external_public_hostname_rejected")
    if any(DNS_LABEL.fullmatch(label) is None for label in hostname.split(".")):
        raise ValueError("external_public_hostname_rejected")
    return hostname


def normalize_trusted_proxy_addresses(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Validate an exact bounded allowlist of private/loopback gateway IPs."""

    if not isinstance(values, (tuple, list)) or len(values) > 16:
        raise ValueError("external_trusted_proxy_addresses_rejected")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or value != value.strip() or "%" in value:
            raise ValueError("external_trusted_proxy_address_rejected")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("external_trusted_proxy_address_rejected") from exc
        networks = TRUSTED_IPV4_NETWORKS if address.version == 4 else TRUSTED_IPV6_NETWORKS
        if not any(address in network for network in networks):
            raise ValueError("external_trusted_proxy_address_rejected")
        canonical = str(address)
        if canonical in normalized:
            raise ValueError("external_trusted_proxy_addresses_rejected")
        normalized.append(canonical)
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class ExternalRequestContext:
    external: bool
    client_address: str
    proxy_address: str | None = None
    public_hostname: str | None = None

    @property
    def limiter_key(self) -> str:
        if self.proxy_address is None:
            return self.client_address
        return f"{self.proxy_address}/{self.client_address}"


@dataclass(frozen=True, slots=True)
class ExternalAccessPolicy:
    configured_enabled: bool
    public_hostname: str | None
    trusted_proxy_addresses: tuple[str, ...]
    authentication_ready: bool

    def __post_init__(self) -> None:
        if type(self.configured_enabled) is not bool or type(self.authentication_ready) is not bool:
            raise ValueError("external_access_boolean_rejected")
        if self.public_hostname is not None:
            object.__setattr__(self, "public_hostname", normalize_public_hostname(self.public_hostname))
        object.__setattr__(
            self,
            "trusted_proxy_addresses",
            normalize_trusted_proxy_addresses(self.trusted_proxy_addresses),
        )

    @property
    def effective_enabled(self) -> bool:
        return bool(
            self.configured_enabled
            and self.authentication_ready
            and self.public_hostname
            and self.trusted_proxy_addresses
        )

    @property
    def blockers(self) -> tuple[str, ...]:
        reasons: list[str] = []
        if not self.configured_enabled:
            reasons.append("disabled_by_configuration")
        if not self.public_hostname:
            reasons.append("public_hostname_missing")
        if not self.trusted_proxy_addresses:
            reasons.append("trusted_proxy_missing")
        if not self.authentication_ready:
            reasons.append("authentication_not_ready")
        return tuple(reasons)

    def status(self) -> dict[str, object]:
        return {
            "schema": "home-center.external-access-status.v1",
            "configured_enabled": self.configured_enabled,
            "effective_enabled": self.effective_enabled,
            "mode": "trusted-reverse-proxy",
            "public_hostname": self.public_hostname,
            "trusted_proxy_count": len(self.trusted_proxy_addresses),
            "gateway_configuration": "operator-managed",
            "health_path": "/external/healthz",
            "blockers": list(self.blockers),
        }

    def classify(self, socket_peer: str, headers: HeaderValues) -> ExternalRequestContext:
        try:
            if not isinstance(socket_peer, str) or "%" in socket_peer:
                raise ValueError("scoped socket peer")
            peer_address = ipaddress.ip_address(socket_peer)
            peer = str(peer_address)
        except ValueError as exc:
            raise ExternalAccessRejected("socket_peer_rejected") from exc

        values = {name: headers.get_all(name, []) or [] for name in FORWARDED_HEADERS}
        has_forwarded = any(values.values())
        trusted_peer = peer in self.trusted_proxy_addresses
        if not trusted_peer and has_forwarded:
            raise ExternalAccessRejected("untrusted_forwarded_headers")
        if trusted_peer and not has_forwarded:
            raise ExternalAccessRejected("forwarded_headers_missing")
        if not trusted_peer:
            if peer_address.is_global:
                raise ExternalAccessRejected("direct_external_peer_rejected")
            return ExternalRequestContext(external=False, client_address=peer)
        if not self.effective_enabled:
            raise ExternalAccessRejected("external_access_disabled")
        if values["Forwarded"]:
            raise ExternalAccessRejected("forwarded_header_unsupported")
        if any(len(values[name]) != 1 for name in X_FORWARDED_HEADERS):
            raise ExternalAccessRejected("forwarded_header_cardinality_rejected")

        forwarded_for = values["X-Forwarded-For"][0]
        forwarded_proto = values["X-Forwarded-Proto"][0]
        forwarded_host = values["X-Forwarded-Host"][0]
        forwarded_values = (forwarded_for, forwarded_proto, forwarded_host)
        if (
            not all(isinstance(value, str) for value in forwarded_values)
            or len(forwarded_for) > 45
            or len(forwarded_proto) > 5
            or len(forwarded_host) > 253
            or "%" in forwarded_for
            or any("," in value or value != value.strip() for value in forwarded_values)
        ):
            raise ExternalAccessRejected("forwarded_header_value_rejected")
        try:
            client = ipaddress.ip_address(forwarded_for)
        except ValueError as exc:
            raise ExternalAccessRejected("forwarded_client_rejected") from exc
        if client.is_unspecified or client.is_multicast:
            raise ExternalAccessRejected("forwarded_client_rejected")
        if forwarded_proto.casefold() != "https":
            raise ExternalAccessRejected("forwarded_proto_rejected")
        if forwarded_host.casefold() != self.public_hostname:
            raise ExternalAccessRejected("forwarded_host_rejected")
        return ExternalRequestContext(
            external=True,
            client_address=str(client),
            proxy_address=peer,
            public_hostname=self.public_hostname,
        )


class ExternalRequestRateLimiter:
    """Two-level in-memory limiter that also bounds a misconfigured proxy."""

    def __init__(self, *, client_requests: int = 240, proxy_requests: int = 1200, window_seconds: int = 60) -> None:
        if min(client_requests, proxy_requests, window_seconds) < 1 or client_requests > proxy_requests:
            raise ValueError("external_rate_limit_rejected")
        self._client_requests = client_requests
        self._proxy_requests = proxy_requests
        self._window = window_seconds
        self._clients: dict[str, deque[float]] = defaultdict(deque)
        self._proxies: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, context: ExternalRequestContext) -> bool:
        if not context.external or context.proxy_address is None:
            return True
        now = time.monotonic()
        with self._lock:
            client = self._clients[context.limiter_key]
            proxy = self._proxies[context.proxy_address]
            for entries in (client, proxy):
                while entries and entries[0] < now - self._window:
                    entries.popleft()
            if len(client) >= self._client_requests or len(proxy) >= self._proxy_requests:
                return False
            client.append(now)
            proxy.append(now)
            return True
