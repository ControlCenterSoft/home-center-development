"""Strict infrastructure-neutral runtime configuration."""
from __future__ import annotations
import ipaddress, json, os, re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from .ad_auth import AdAuthConfig
from .external_access import normalize_public_hostname, normalize_trusted_proxy_addresses
from .util import secure_file

CONFIG_SCHEMAS = frozenset({"home-center.config.v4", "home-center.config.v5"})
IDENTIFIER = re.compile(r"^[a-z][a-z0-9._:-]{1,127}$", re.I)

@dataclass(frozen=True, slots=True)
class Peer:
    node_id: str
    name: str
    address: str
    url: str
    certificate_name: str

@dataclass(frozen=True, slots=True)
class ExternalAccessConfig:
    enabled: bool = False
    mode: str = "trusted-reverse-proxy"
    public_hostname: str | None = None
    trusted_proxy_addresses: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class Config:
    cluster_id: str
    node_id: str
    node_name: str
    role: str
    management_address: str
    web_port: int
    peer_port: int
    state_db: Path
    backup_dir: Path
    web_root: Path
    local_admin_credentials_file: Path
    session_key_file: Path
    audit_key_file: Path
    tls_certificate: Path
    tls_private_key: Path
    cluster_ca: Path
    web_ca: Path
    deployment_profile: Path
    peers: tuple[Peer, ...]
    reconcile_interval_seconds: int
    peer_timeout_seconds: int
    ad_auth: AdAuthConfig = field(default_factory=AdAuthConfig.disabled)
    external_access: ExternalAccessConfig = field(default_factory=ExternalAccessConfig)

    @property
    def web_bind(self) -> tuple[str, int]:
        return self.management_address, self.web_port

    @property
    def peer_bind(self) -> tuple[str, int]:
        return self.management_address, self.peer_port

def _required(raw: dict[str, Any], name: str, expected: type) -> Any:
    value = raw.get(name)
    if not isinstance(value, expected) or (expected is str and not value.strip()):
        raise ValueError(f"invalid or missing config field: {name}")
    return value

def _path(raw: dict[str, Any], name: str) -> Path:
    value = Path(_required(raw, name, str))
    if not value.is_absolute():
        raise ValueError(f"config path must be absolute: {name}")
    return value

def _ad_auth(raw: dict[str, Any]) -> AdAuthConfig:
    value = _required(raw, "ad_auth", dict)
    required = {"enabled", "realm", "kdc_hosts", "allowed_admin_groups", "timeout_seconds", "cache_root"}
    if set(value) != required:
        raise ValueError("ad_auth config shape rejected")
    enabled = value.get("enabled")
    if not isinstance(enabled, bool):
        raise ValueError("ad_auth enabled must be boolean")
    realm = _required(value, "realm", str).upper()
    if re.fullmatch(r"[A-Z0-9][A-Z0-9.-]{2,254}", realm) is None:
        raise ValueError("ad_auth realm rejected")
    hosts = value.get("kdc_hosts")
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 16 or any(not isinstance(item, str) for item in hosts):
        raise ValueError("ad_auth kdc_hosts rejected")
    normalized_hosts = tuple(item.lower() for item in hosts)
    realm_suffix = "." + realm.lower()
    if any(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", item) is None or not item.endswith(realm_suffix) for item in normalized_hosts):
        raise ValueError("ad_auth kdc_hosts rejected")
    groups = value.get("allowed_admin_groups")
    if not isinstance(groups, list) or not 1 <= len(groups) <= 64 or any(not isinstance(item, str) or item != item.strip() or not 1 <= len(item) <= 128 for item in groups):
        raise ValueError("ad_auth allowed_admin_groups rejected")
    timeout = value.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 10:
        raise ValueError("ad_auth timeout rejected")
    cache_root = Path(_required(value, "cache_root", str))
    if not cache_root.is_absolute():
        raise ValueError("ad_auth cache_root must be absolute")
    return AdAuthConfig(enabled=enabled, realm=realm, kdc_hosts=normalized_hosts, allowed_admin_groups=tuple(groups), timeout_seconds=timeout, cache_root=cache_root)

def _external_access(raw: dict[str, Any]) -> ExternalAccessConfig:
    value = _required(raw, "external_access", dict)
    required = {"enabled", "mode", "public_hostname", "trusted_proxy_addresses"}
    if set(value) != required:
        raise ValueError("external_access config shape rejected")
    enabled = value.get("enabled")
    if type(enabled) is not bool or value.get("mode") != "trusted-reverse-proxy":
        raise ValueError("external_access config rejected")
    hostname_value = value.get("public_hostname")
    if hostname_value is not None and not isinstance(hostname_value, str):
        raise ValueError("external_access public_hostname rejected")
    hostname = normalize_public_hostname(hostname_value) if hostname_value is not None else None
    proxies_value = value.get("trusted_proxy_addresses")
    if not isinstance(proxies_value, list):
        raise ValueError("external_access trusted_proxy_addresses rejected")
    proxies = normalize_trusted_proxy_addresses(proxies_value)
    if enabled and (hostname is None or not proxies):
        raise ValueError("enabled external_access requires public hostname and trusted proxy")
    return ExternalAccessConfig(enabled=enabled, public_hostname=hostname, trusted_proxy_addresses=proxies)

def _peer(raw: dict[str, Any], peer_port: int) -> Peer:
    node_id = _required(raw, "node_id", str)
    name = _required(raw, "name", str)
    if IDENTIFIER.fullmatch(node_id) is None or IDENTIFIER.fullmatch(name) is None:
        raise ValueError("peer identity rejected")
    address = _required(raw, "address", str)
    parsed = ipaddress.ip_address(address)
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        raise ValueError("peer address rejected")
    url = _required(raw, "url", str)
    if url != f"https://{address}:{peer_port}":
        raise ValueError("peer URL must match peer address and configured peer port")
    certificate_name = _required(raw, "certificate_name", str)
    if not 1 <= len(certificate_name) <= 253:
        raise ValueError("peer certificate name rejected")
    return Peer(node_id, name, address, url, certificate_name)

def load_config(path: str | Path | None = None) -> Config:
    config_path = Path(path or os.environ.get("HOME_CENTER_CONFIG", "/etc/home-center/config.json"))
    with config_path.open("r", encoding="utf-8") as stream:
        raw = json.load(stream)
    if not isinstance(raw, dict) or raw.get("schema") not in CONFIG_SCHEMAS:
        raise ValueError(f"unsupported config schema in {config_path}")
    if config_path.stat().st_mode & 0o002:
        raise PermissionError(f"world-writable config rejected: {config_path}")
    role = _required(raw, "role", str)
    if IDENTIFIER.fullmatch(role) is None:
        raise ValueError("role rejected")
    address = _required(raw, "management_address", str)
    parsed_address = ipaddress.ip_address(address)
    if parsed_address.is_unspecified or parsed_address.is_loopback or parsed_address.is_multicast:
        raise ValueError("management_address must be a concrete address")
    ports = (int(raw.get("web_port", 8443)), int(raw.get("peer_port", 9443)))
    if any(port < 1024 or port > 65535 for port in ports) or ports[0] == ports[1]:
        raise ValueError("web/peer ports must be distinct unprivileged ports")
    peers_raw = raw.get("peers")
    if peers_raw is None and "peer" in raw:
        peers_raw = [raw["peer"]]
    if peers_raw is None:
        peers_raw = []
    if not isinstance(peers_raw, list) or len(peers_raw) > 63 or any(not isinstance(item, dict) for item in peers_raw):
        raise ValueError("peers config rejected")
    peers = tuple(_peer(item, ports[1]) for item in peers_raw)
    peer_ids = [item.node_id for item in peers]
    peer_names = [item.name.casefold() for item in peers]
    if len(peer_ids) != len(set(peer_ids)) or len(peer_names) != len(set(peer_names)):
        raise ValueError("duplicate peer identity")
    cfg = Config(
        cluster_id=_required(raw, "cluster_id", str), node_id=_required(raw, "node_id", str), node_name=_required(raw, "node_name", str), role=role,
        management_address=address, web_port=ports[0], peer_port=ports[1], state_db=_path(raw, "state_db"), backup_dir=_path(raw, "backup_dir"), web_root=_path(raw, "web_root"),
        local_admin_credentials_file=_path(raw, "local_admin_credentials_file"), session_key_file=_path(raw, "session_key_file"), audit_key_file=_path(raw, "audit_key_file"),
        tls_certificate=_path(raw, "tls_certificate"), tls_private_key=_path(raw, "tls_private_key"), cluster_ca=_path(raw, "cluster_ca"), web_ca=_path(raw, "web_ca"),
        deployment_profile=_path(raw, "deployment_profile"), peers=peers, reconcile_interval_seconds=max(5, min(int(raw.get("reconcile_interval_seconds", 15)), 300)),
        peer_timeout_seconds=max(1, min(int(raw.get("peer_timeout_seconds", 3)), 15)), ad_auth=_ad_auth(raw), external_access=_external_access(raw),
    )
    if IDENTIFIER.fullmatch(cfg.node_id) is None or IDENTIFIER.fullmatch(cfg.node_name) is None:
        raise ValueError("local node identity rejected")
    if any(peer.node_id == cfg.node_id or peer.name.casefold() == cfg.node_name.casefold() for peer in cfg.peers):
        raise ValueError("peer identity must differ from local node identity")
    if cfg.web_ca.resolve() == cfg.cluster_ca.resolve():
        raise ValueError("web_ca must be independent from cluster_ca")
    for secret in (cfg.local_admin_credentials_file, cfg.session_key_file, cfg.audit_key_file, cfg.tls_private_key):
        secure_file(secret, allow_group_read=True)
    for public_file in (cfg.tls_certificate, cfg.cluster_ca, cfg.web_ca, cfg.deployment_profile):
        if not public_file.is_file():
            raise FileNotFoundError(public_file)
    if not cfg.web_root.is_dir():
        raise FileNotFoundError(cfg.web_root)
    return cfg
