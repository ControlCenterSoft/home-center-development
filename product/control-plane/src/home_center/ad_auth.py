"""Опциональная аутентификация Active Directory по принципу fail-closed через ограниченные инструменты Kerberos.

Пароли передаются только в stdin kinit и никогда не попадают в argv, окружение, журналы,
детали аудита, сохраняемую конфигурацию или возвращаемые результаты. Авторизация по группам
выполняется только на чтение и лишь после успешной аутентификации Kerberos.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


KINIT = "/usr/bin/kinit"
ID = "/usr/bin/id"
PRINCIPAL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
REALM = re.compile(r"^[A-Z0-9][A-Z0-9.-]{2,254}$")
KDC_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
MAX_PASSWORD_BYTES = 256
MAX_GROUP_OUTPUT_BYTES = 16 * 1024


class AdAuthError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AdAuthConfig:
    enabled: bool
    realm: str
    kdc_hosts: tuple[str, ...]
    allowed_admin_groups: tuple[str, ...]
    timeout_seconds: int
    cache_root: Path

    @classmethod
    def disabled(cls) -> "AdAuthConfig":
        return cls(
            enabled=False,
            realm="EXAMPLE.INTERNAL",
            kdc_hosts=(),
            allowed_admin_groups=(),
            timeout_seconds=5,
            cache_root=Path("/var/lib/home-center/ad-auth"),
        )


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _principal(value: str, realm: str) -> str | None:
    if not isinstance(value, str) or value != value.strip() or not value:
        return None
    name = value
    if "\\" in value:
        domain, separator, name = value.partition("\\")
        if not separator or domain.upper() != realm.split(".", 1)[0]:
            return None
    elif "@" in value:
        name, separator, supplied_realm = value.rpartition("@")
        if not separator or supplied_realm.upper() != realm:
            return None
    if PRINCIPAL_NAME.fullmatch(name) is None:
        return None
    return f"{name.lower()}@{realm}"


def _password(value: str) -> bytes | None:
    if not isinstance(value, str) or any(marker in value for marker in ("\x00", "\r", "\n")):
        return None
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    return encoded if 1 <= len(encoded) <= MAX_PASSWORD_BYTES else None


class AdAuthenticator:
    def __init__(self, config: AdAuthConfig, *, runner: Runner = subprocess.run) -> None:
        self.config = config
        self._runner = runner

    def _validated_cache_root(self) -> Path:
        path = self.config.cache_root
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise AdAuthError("external_authentication_unavailable") from exc
        try:
            info = path.lstat()
        except OSError as exc:
            raise AdAuthError("external_authentication_unavailable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise AdAuthError("external_authentication_unavailable")
        return path

    def _krb5_config(self) -> str:
        kdcs = "\n".join(f"  kdc = {host}:88" for host in self.config.kdc_hosts)
        return (
            "[libdefaults]\n"
            f" default_realm = {self.config.realm}\n"
            " dns_lookup_kdc = false\n"
            " dns_lookup_realm = false\n"
            " rdns = false\n"
            " dns_canonicalize_hostname = false\n"
            " udp_preference_limit = 1\n"
            " forwardable = false\n"
            " proxiable = false\n"
            " ticket_lifetime = 5m\n"
            "[realms]\n"
            f" {self.config.realm} = {{\n{kdcs}\n }}\n"
        )

    def authenticate(self, username: str, password: str) -> str | None:
        if not self.config.enabled:
            return None
        principal = _principal(username, self.config.realm)
        secret = _password(password)
        if principal is None or secret is None:
            return None

        root = self._validated_cache_root()
        working = Path(tempfile.mkdtemp(prefix=".attempt-", dir=root))
        os.chmod(working, 0o700)
        krb5_config = working / "krb5.conf"
        cache = working / "ccache"
        try:
            krb5_config.write_text(self._krb5_config(), encoding="ascii", newline="\n")
            os.chmod(krb5_config, 0o600)
            environment = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "KRB5_CONFIG": str(krb5_config),
                "KRB5CCNAME": f"FILE:{cache}",
                "KRB5RCACHETYPE": "none",
            }
            try:
                authenticated = self._runner(
                    [KINIT, "-V", "-l", "5m", principal],
                    check=False,
                    input=secret + b"\n",
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.config.timeout_seconds,
                    env=environment,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise AdAuthError("external_authentication_unavailable") from exc
            if authenticated.returncode != 0:
                return None

            try:
                membership = self._runner(
                    [ID, "-Gn", "-z", principal],
                    check=False,
                    input=None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=self.config.timeout_seconds,
                    env=environment,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise AdAuthError("external_authentication_unavailable") from exc
            output = membership.stdout
            if membership.returncode != 0 or not isinstance(output, bytes) or len(output) > MAX_GROUP_OUTPUT_BYTES:
                raise AdAuthError("external_authentication_unavailable")
            try:
                groups = {
                    item.decode("utf-8", errors="strict").casefold()
                    for item in output.split(b"\x00")
                    if item
                }
            except UnicodeDecodeError as exc:
                raise AdAuthError("external_authentication_unavailable") from exc
            allowed = {item.casefold() for item in self.config.allowed_admin_groups}
            return principal if groups & allowed else None
        finally:
            try:
                shutil.rmtree(working)
            except OSError as exc:
                raise AdAuthError("external_authentication_unavailable") from exc
