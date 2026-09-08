"""Ограниченное обнаружение локальных возможностей без привилегированного shell-интерфейса."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from .util import utc_now


SERVICE_ALLOWLIST = (
    "samba-ad-dc.service",
    "unbound.service",
    "chrony.service",
    "ssh.service",
    "home-center.service",
)


def _text(path: str, default: str = "unknown") -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return default


def _memory_bytes() -> int:
    for line in _text("/proc/meminfo", "").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    return 0


def _service_state(unit: str) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "is-active", unit],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        value = result.stdout.strip()
        return value if value in {"active", "inactive", "failed", "activating", "deactivating"} else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def _machine_identity() -> str:
    raw = _text("/etc/machine-id", socket.gethostname())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def collect(node_id: str, node_name: str, role: str, address: str) -> dict[str, Any]:
    root = shutil.disk_usage("/")
    return {
        "schema": "home-center.node-capability.v1",
        "observed_at": utc_now(),
        "node": {
            "id": node_id,
            "name": node_name,
            "role": role,
            "address": address,
            "machine_identity_hash": _machine_identity(),
        },
        "operating_system": {
            "id": _os_release().get("ID", "unknown"),
            "version": _os_release().get("VERSION_ID", "unknown"),
            "kernel": platform.release(),
            "architecture": platform.machine(),
        },
        "hardware": {
            "cpu_count": os.cpu_count() or 0,
            "memory_bytes": _memory_bytes(),
        },
        "storage": {
            "root": {"total_bytes": root.total, "used_bytes": root.used, "free_bytes": root.free},
        },
        "services": {unit: _service_state(unit) for unit in SERVICE_ALLOWLIST},
        "capabilities": [
            "inventory.v1",
            "health.v1",
            "audit.v1",
            "backup.sqlite.v1",
            "cluster.peer-mtls.v1",
        ],
    }


def _os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in _text("/etc/os-release", "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip('"')
    return result
