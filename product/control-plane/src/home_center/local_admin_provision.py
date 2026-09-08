"""Примитивы привилегированного provisioning учётных данных локального администратора.

Этот модуль создаёт только salted verifier scrypt. Он никогда не журналирует, не возвращает
и не сохраняет пароль в открытом виде и никогда не перезаписывает существующие учётные данные.
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
    CREDENTIAL_SCHEMA,
    KDF_DKLEN,
    KDF_N,
    KDF_NAME,
    KDF_P,
    KDF_R,
    MAX_CREDENTIAL_FILE_BYTES,
    SALT_BYTES,
    LocalAdminAuthError,
    _derive,
    _password_bytes,
    normalize_username,
)


class LocalAdminProvisionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def credential_document(username: str, password: str, *, salt: bytes | None = None) -> dict[str, Any]:
    """Формирует документ verifier без сохранения материала пароля в открытом виде."""

    canonical_username = normalize_username(username)
    password_bytes = _password_bytes(password)
    credential_salt = secrets.token_bytes(SALT_BYTES) if salt is None else bytes(salt)
    if len(credential_salt) != SALT_BYTES:
        raise LocalAdminProvisionError("credential_salt_rejected")
    verifier = _derive(password_bytes, credential_salt)
    return {
        "schema": CREDENTIAL_SCHEMA,
        "username": canonical_username,
        "kdf": KDF_NAME,
        "n": KDF_N,
        "r": KDF_R,
        "p": KDF_P,
        "dklen": KDF_DKLEN,
        "salt_b64": base64.b64encode(credential_salt).decode("ascii"),
        "verifier_b64": base64.b64encode(verifier).decode("ascii"),
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
) -> str:
    """Однократно создаёт учётные данные с публикацией без follow и без перезаписи.

    Родительский каталог должен уже существовать с точно ожидаемыми владельцем и режимом.
    Вместо rename используется публикация через hard link, чтобы атакующий не мог выиграть
    гонку замены назначения, создав целевой файл между проверкой и публикацией.
    """

    target = Path(path)
    if not target.is_absolute() or target.name in {"", ".", ".."}:
        raise LocalAdminProvisionError("credential_path_rejected")

    try:
        document = credential_document(username, password)
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
