"""Read-only local administrator credential verification.

The credential file contains a scrypt verifier only. This module never creates,
changes, logs, returns, or persists a plaintext password.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CREDENTIAL_SCHEMA = "home-center.local-admin-credential.v1"
KDF_NAME = "scrypt"
KDF_N = 1 << 15
KDF_R = 8
KDF_P = 1
KDF_DKLEN = 32
KDF_MAXMEM = 64 * 1024 * 1024
SALT_BYTES = 32
MAX_CREDENTIAL_FILE_BYTES = 16 * 1024
MIN_PASSWORD_BYTES = 12
MAX_PASSWORD_BYTES = 256
USERNAME = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")


class LocalAdminAuthError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class LocalAdminCredential:
    username: str
    salt: bytes
    verifier: bytes


def normalize_username(value: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise LocalAdminAuthError("username_rejected")
    normalized = value.lower()
    if USERNAME.fullmatch(normalized) is None:
        raise LocalAdminAuthError("username_rejected")
    return normalized


def _password_bytes(value: str) -> bytes:
    if not isinstance(value, str) or "\x00" in value or "\r" in value or "\n" in value:
        raise LocalAdminAuthError("password_rejected")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise LocalAdminAuthError("password_rejected") from exc
    if not MIN_PASSWORD_BYTES <= len(encoded) <= MAX_PASSWORD_BYTES:
        raise LocalAdminAuthError("password_rejected")
    return encoded


def _material(value: Any, size: int, code: str) -> bytes:
    if not isinstance(value, str) or len(value) > size * 2:
        raise LocalAdminAuthError(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LocalAdminAuthError(code) from exc
    if len(decoded) != size:
        raise LocalAdminAuthError(code)
    return decoded


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LocalAdminAuthError("credential_duplicate_json_key")
        result[key] = value
    return result


def _parse(document: Any) -> LocalAdminCredential:
    required = {"schema", "username", "kdf", "n", "r", "p", "dklen", "salt_b64", "verifier_b64"}
    if not isinstance(document, dict) or set(document) != required:
        raise LocalAdminAuthError("credential_shape_rejected")
    if document["schema"] != CREDENTIAL_SCHEMA or document["kdf"] != KDF_NAME:
        raise LocalAdminAuthError("credential_schema_rejected")
    for key, expected in (("n", KDF_N), ("r", KDF_R), ("p", KDF_P), ("dklen", KDF_DKLEN)):
        value = document[key]
        if isinstance(value, bool) or not isinstance(value, int) or value != expected:
            raise LocalAdminAuthError("credential_kdf_parameters_rejected")
    return LocalAdminCredential(
        username=normalize_username(document["username"]),
        salt=_material(document["salt_b64"], SALT_BYTES, "credential_salt_rejected"),
        verifier=_material(document["verifier_b64"], KDF_DKLEN, "credential_verifier_rejected"),
    )


def _derive(password: bytes, salt: bytes) -> bytes:
    try:
        return hashlib.scrypt(
            password,
            salt=salt,
            n=KDF_N,
            r=KDF_R,
            p=KDF_P,
            maxmem=KDF_MAXMEM,
            dklen=KDF_DKLEN,
        )
    except (TypeError, ValueError) as exc:
        raise LocalAdminAuthError("credential_kdf_unavailable") from exc


class LocalAdminCredentialStore:
    """Immutable credential verifier loaded from a root-controlled regular file."""

    def __init__(
        self,
        path: Path,
        *,
        expected_uid: int = 0,
        expected_gid: int = 0,
        expected_mode: int = 0o600,
    ) -> None:
        self.path = Path(path)
        self.expected_uid = expected_uid
        self.expected_gid = expected_gid
        self.expected_mode = expected_mode
        self._credential = self._load()

    @property
    def username(self) -> str:
        return self._credential.username

    def _load(self) -> LocalAdminCredential:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.path, flags)
        except OSError as exc:
            raise LocalAdminAuthError("credential_file_unavailable") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != self.expected_uid
                or info.st_gid != self.expected_gid
                or stat.S_IMODE(info.st_mode) != self.expected_mode
                or info.st_size < 1
                or info.st_size > MAX_CREDENTIAL_FILE_BYTES
            ):
                raise LocalAdminAuthError("credential_file_metadata_rejected")
            data = os.read(fd, MAX_CREDENTIAL_FILE_BYTES + 1)
            if len(data) != info.st_size or len(data) > MAX_CREDENTIAL_FILE_BYTES:
                raise LocalAdminAuthError("credential_file_read_rejected")
        finally:
            os.close(fd)
        try:
            document = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_strict_object)
        except LocalAdminAuthError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise LocalAdminAuthError("credential_file_json_rejected") from exc
        return _parse(document)

    def authenticate(self, username: str, password: str) -> str | None:
        """Return the canonical username on success, otherwise None.

        Invalid candidate shape still executes the configured scrypt work factor so
        malformed and unknown credentials do not gain a cheap authentication path.
        """

        candidate_username = "invalid"
        candidate_password = b"0" * MIN_PASSWORD_BYTES
        input_ok = True
        try:
            candidate_username = normalize_username(username)
        except LocalAdminAuthError:
            input_ok = False
        try:
            candidate_password = _password_bytes(password)
        except LocalAdminAuthError:
            input_ok = False

        candidate = _derive(candidate_password, self._credential.salt)
        username_ok = hmac.compare_digest(
            candidate_username.encode("ascii"), self._credential.username.encode("ascii")
        )
        password_ok = hmac.compare_digest(candidate, self._credential.verifier)
        if input_ok and username_ok and password_ok:
            return self._credential.username
        return None

    def verify(self, username: str, password: str) -> bool:
        return self.authenticate(username, password) is not None
