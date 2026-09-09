"""Privileged local-administrator credential provisioning primitives.

This module creates only a salted scrypt verifier. It never logs, returns, or
persists the plaintext password and never overwrites an existing credential.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from .local_admin_auth import (
    CREDENTIAL_SCHEMA_V2,
    KDF_DKLEN,
    KDF_N,
    KDF_NAME,
    KDF_P,
    KDF_R,
    MAX_CREDENTIAL_FILE_BYTES,
    SALT_BYTES,
    LocalAdminAuthError,
    LocalAdminCredentialStore,
    _derive,
    _password_bytes,
    normalize_username,
)


class LocalAdminProvisionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _bootstrap_password_bytes(username: str, password: str, password_change_required: bool) -> bytes:
    """Admit only the product's exact one-time bootstrap credential."""

    canonical_username = normalize_username(username)
    if canonical_username != "admin" or password != "admin" or not password_change_required:
        return _password_bytes(password)
    return b"admin"


def credential_document(
    username: str,
    password: str,
    *,
    salt: bytes | None = None,
    password_change_required: bool = False,
    allow_default_bootstrap: bool = False,
) -> dict[str, Any]:
    """Build a verifier document without retaining plaintext password material."""

    canonical_username = normalize_username(username)
    password_bytes = (
        _bootstrap_password_bytes(canonical_username, password, password_change_required)
        if allow_default_bootstrap
        else _password_bytes(password)
    )
    credential_salt = secrets.token_bytes(SALT_BYTES) if salt is None else bytes(salt)
    if len(credential_salt) != SALT_BYTES:
        raise LocalAdminProvisionError("credential_salt_rejected")
    verifier = _derive(password_bytes, credential_salt)
    return {
        "schema": CREDENTIAL_SCHEMA_V2,
        "username": canonical_username,
        "kdf": KDF_NAME,
        "n": KDF_N,
        "r": KDF_R,
        "p": KDF_P,
        "dklen": KDF_DKLEN,
        "salt_b64": base64.b64encode(credential_salt).decode("ascii"),
        "verifier_b64": base64.b64encode(verifier).decode("ascii"),
        "password_change_required": password_change_required,
    }


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise LocalAdminProvisionError("credential_file_write_rejected")
        offset += written


def provision_credential_file(
    path: Path,
    username: str,
    password: str,
    *,
    expected_directory_uid: int = 0,
    expected_directory_gid: int,
    expected_directory_mode: int = 0o750,
    file_uid: int = 0,
    file_gid: int,
    file_mode: int = 0o640,
    password_change_required: bool = False,
    allow_default_bootstrap: bool = False,
) -> str:
    """Create a credential exactly once using a no-follow, no-overwrite publication.

    The parent directory must already exist with the exact expected ownership and
    mode. A hard-link publication is used instead of rename so an attacker cannot
    win a destination-replacement race by creating the target between validation
    and publication.
    """

    target = Path(path)
    if not target.is_absolute() or target.name in {"", ".", ".."}:
        raise LocalAdminProvisionError("credential_path_rejected")

    try:
        document = credential_document(
            username,
            password,
            password_change_required=password_change_required,
            allow_default_bootstrap=allow_default_bootstrap,
        )
    except LocalAdminAuthError as exc:
        raise LocalAdminProvisionError(exc.code) from exc
    data = (json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if not 1 <= len(data) <= MAX_CREDENTIAL_FILE_BYTES:
        raise LocalAdminProvisionError("credential_document_size_rejected")

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        directory_fd = os.open(target.parent, directory_flags)
    except OSError as exc:
        raise LocalAdminProvisionError("credential_directory_unavailable") from exc

    temporary_name: str | None = None
    published = False
    try:
        directory_info = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != expected_directory_uid
            or directory_info.st_gid != expected_directory_gid
            or stat.S_IMODE(directory_info.st_mode) != expected_directory_mode
        ):
            raise LocalAdminProvisionError("credential_directory_metadata_rejected")

        try:
            os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise LocalAdminProvisionError("credential_file_exists")

        temporary_name = f".local-admin.{secrets.token_hex(12)}.tmp"
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(temporary_name, file_flags, 0o600, dir_fd=directory_fd)
        try:
            initial_info = os.fstat(fd)
            if initial_info.st_uid != file_uid or initial_info.st_gid != file_gid:
                os.fchown(fd, file_uid, file_gid)
            os.fchmod(fd, file_mode)
            _write_all(fd, data)
            os.fsync(fd)
            temporary_info = os.fstat(fd)
            if (
                not stat.S_ISREG(temporary_info.st_mode)
                or temporary_info.st_nlink != 1
                or temporary_info.st_uid != file_uid
                or temporary_info.st_gid != file_gid
                or stat.S_IMODE(temporary_info.st_mode) != file_mode
                or temporary_info.st_size != len(data)
            ):
                raise LocalAdminProvisionError("credential_file_metadata_rejected")
        finally:
            os.close(fd)

        try:
            os.link(
                temporary_name,
                target.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise LocalAdminProvisionError("credential_file_exists") from exc
        published = True
        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_name = None
        os.fsync(directory_fd)

        final_info = os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(final_info.st_mode)
            or final_info.st_nlink != 1
            or final_info.st_uid != file_uid
            or final_info.st_gid != file_gid
            or stat.S_IMODE(final_info.st_mode) != file_mode
            or final_info.st_size != len(data)
        ):
            raise LocalAdminProvisionError("credential_file_metadata_rejected")
        return document["username"]
    except Exception:
        if published:
            try:
                os.unlink(target.name, dir_fd=directory_fd)
            except OSError:
                pass
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(directory_fd)


def ensure_default_admin_credential_file(
    path: Path,
    *,
    expected_directory_uid: int = 0,
    expected_directory_gid: int,
    expected_directory_mode: int = 0o750,
    file_uid: int = 0,
    file_gid: int,
    file_mode: int = 0o640,
) -> tuple[str, bool]:
    """Create the one-time admin/admin credential or preserve an existing verifier.

    Returning ``created=False`` is the upgrade path: the existing verifier is
    validated and never rewritten, so neither a custom password nor its
    password-change state can be reset by package installation.
    """

    target = Path(path)
    try:
        existing = LocalAdminCredentialStore(
            target,
            expected_uid=file_uid,
            expected_gid=file_gid,
            expected_mode=file_mode,
        )
    except LocalAdminAuthError as exc:
        if exc.code != "credential_file_unavailable":
            raise LocalAdminProvisionError(exc.code) from exc
    else:
        return existing.username, False

    try:
        username = provision_credential_file(
            target,
            "admin",
            "admin",
            expected_directory_uid=expected_directory_uid,
            expected_directory_gid=expected_directory_gid,
            expected_directory_mode=expected_directory_mode,
            file_uid=file_uid,
            file_gid=file_gid,
            file_mode=file_mode,
            password_change_required=True,
            allow_default_bootstrap=True,
        )
        return username, True
    except LocalAdminProvisionError as exc:
        if exc.code != "credential_file_exists":
            raise
        try:
            existing = LocalAdminCredentialStore(
                target,
                expected_uid=file_uid,
                expected_gid=file_gid,
                expected_mode=file_mode,
            )
        except LocalAdminAuthError as load_exc:
            raise LocalAdminProvisionError(load_exc.code) from load_exc
        return existing.username, False
