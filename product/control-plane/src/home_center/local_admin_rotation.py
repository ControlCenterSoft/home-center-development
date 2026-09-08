"""Crash-safe rotation of the node-local administrator verifier.

Only the fixed credential path and fixed transaction files are touched. The
new password exists in memory for the duration of the request and is never
placed in logs, audit metadata, environment variables, command arguments, or
the state database.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import threading
from pathlib import Path
from typing import Callable

from .local_admin_auth import LocalAdminAuthError, LocalAdminCredentialStore
from .local_admin_provision import LocalAdminProvisionError, credential_document


LOCK_NAME = ".local-admin.rotation.lock"
NEXT_NAME = ".local-admin.rotation.next"
ROLLBACK_NAME = ".local-admin.rotation.rollback"


class LocalAdminRotationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LocalAdminCredentialRotator:
    """Serialize, recover and atomically commit one node-local credential."""

    def __init__(
        self,
        path: Path,
        *,
        expected_uid: int = 0,
        expected_gid: int = 0,
        expected_mode: int = 0o640,
        expected_directory_uid: int = 0,
        expected_directory_gid: int = 0,
        expected_directory_mode: int = 0o750,
    ) -> None:
        self.path = Path(path)
        if not self.path.is_absolute() or self.path.name in {"", ".", ".."}:
            raise LocalAdminRotationError("credential_path_rejected")
        self.expected_uid = expected_uid
        self.expected_gid = expected_gid
        self.expected_mode = expected_mode
        self.expected_directory_uid = expected_directory_uid
        self.expected_directory_gid = expected_directory_gid
        self.expected_directory_mode = expected_directory_mode
        self._thread_lock = threading.Lock()

    def _store(self, path: Path | None = None) -> LocalAdminCredentialStore:
        return LocalAdminCredentialStore(
            path or self.path,
            expected_uid=self.expected_uid,
            expected_gid=self.expected_gid,
            expected_mode=self.expected_mode,
        )

    def _open_directory(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self.path.parent, flags)
        except OSError as exc:
            raise LocalAdminRotationError("credential_directory_unavailable") from exc
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.expected_directory_uid
            or info.st_gid != self.expected_directory_gid
            or stat.S_IMODE(info.st_mode) != self.expected_directory_mode
        ):
            os.close(descriptor)
            raise LocalAdminRotationError("credential_directory_metadata_rejected")
        return descriptor

    def _open_lock(self, directory_fd: int) -> int:
        base_flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        created = False
        try:
            descriptor = os.open(LOCK_NAME, base_flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(LOCK_NAME, base_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise LocalAdminRotationError("credential_rotation_lock_unavailable") from exc
        except OSError as exc:
            raise LocalAdminRotationError("credential_rotation_lock_unavailable") from exc
        if created:
            try:
                os.fchown(descriptor, self.expected_uid, self.expected_gid)
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.fsync(directory_fd)
            except OSError as exc:
                os.close(descriptor)
                raise LocalAdminRotationError("credential_rotation_lock_unavailable") from exc
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != self.expected_uid
            or info.st_gid != self.expected_gid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise LocalAdminRotationError("credential_rotation_lock_rejected")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            os.close(descriptor)
            raise LocalAdminRotationError("credential_rotation_lock_unavailable") from exc
        return descriptor

    def _read_regular(self, directory_fd: int, name: str) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != self.expected_uid
                or info.st_gid != self.expected_gid
                or stat.S_IMODE(info.st_mode) != self.expected_mode
                or not 1 <= info.st_size <= 16 * 1024
            ):
                raise LocalAdminRotationError("credential_file_metadata_rejected")
            data = os.read(descriptor, 16 * 1024 + 1)
            if len(data) != info.st_size:
                raise LocalAdminRotationError("credential_file_read_rejected")
            return data
        finally:
            os.close(descriptor)

    def _write_regular(self, directory_fd: int, name: str, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != self.expected_uid or info.st_gid != self.expected_gid:
                os.fchown(descriptor, self.expected_uid, self.expected_gid)
            os.fchmod(descriptor, self.expected_mode)
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise LocalAdminRotationError("credential_file_write_rejected")
                offset += written
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != self.expected_uid
                or info.st_gid != self.expected_gid
                or stat.S_IMODE(info.st_mode) != self.expected_mode
                or info.st_size != len(data)
            ):
                raise LocalAdminRotationError("credential_file_metadata_rejected")
        finally:
            os.close(descriptor)

    @staticmethod
    def _exists(directory_fd: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _unlink_regular(self, directory_fd: int, name: str) -> None:
        if not self._exists(directory_fd, name):
            return
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != self.expected_uid
            or info.st_gid != self.expected_gid
            or stat.S_IMODE(info.st_mode) != self.expected_mode
        ):
            raise LocalAdminRotationError("credential_transaction_file_rejected")
        os.unlink(name, dir_fd=directory_fd)

    def _recover_locked(self, directory_fd: int) -> None:
        next_exists = self._exists(directory_fd, NEXT_NAME)
        rollback_exists = self._exists(directory_fd, ROLLBACK_NAME)
        if not next_exists and not rollback_exists:
            return
        try:
            self._store()
            target_valid = True
        except LocalAdminAuthError:
            target_valid = False
        if target_valid:
            self._unlink_regular(directory_fd, NEXT_NAME)
            self._unlink_regular(directory_fd, ROLLBACK_NAME)
            os.fsync(directory_fd)
            return
        if not rollback_exists:
            raise LocalAdminRotationError("credential_rotation_recovery_unavailable")
        self._store(self.path.parent / ROLLBACK_NAME)
        os.replace(ROLLBACK_NAME, self.path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        self._unlink_regular(directory_fd, NEXT_NAME)
        os.fsync(directory_fd)
        self._store()

    def recover(self) -> LocalAdminCredentialStore:
        """Resolve an interrupted local transaction without accepting caller paths."""

        with self._thread_lock:
            directory_fd = self._open_directory()
            lock_fd: int | None = None
            try:
                lock_fd = self._open_lock(directory_fd)
                self._recover_locked(directory_fd)
                return self._store()
            except LocalAdminRotationError:
                raise
            except (LocalAdminAuthError, OSError) as exc:
                raise LocalAdminRotationError("credential_rotation_recovery_failed") from exc
            finally:
                if lock_fd is not None:
                    os.close(lock_fd)
                os.close(directory_fd)

    def _change(
        self,
        new_password: str,
        *,
        username: str | None,
        current_password: str | None,
        commit_hook: Callable[[], None] | None,
    ) -> LocalAdminCredentialStore:
        with self._thread_lock:
            directory_fd = self._open_directory()
            lock_fd: int | None = None
            replaced = False
            committed = False
            try:
                lock_fd = self._open_lock(directory_fd)
                self._recover_locked(directory_fd)
                current_store = self._store()
                if current_password is not None and (
                    username is None or current_store.authenticate(username, current_password) is None
                ):
                    raise LocalAdminRotationError("current_password_invalid")
                try:
                    document = credential_document(current_store.username, new_password)
                except (LocalAdminAuthError, LocalAdminProvisionError) as exc:
                    raise LocalAdminRotationError(exc.code) from exc
                data = (json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
                old_data = self._read_regular(directory_fd, self.path.name)
                self._write_regular(directory_fd, NEXT_NAME, data)
                next_store = self._store(self.path.parent / NEXT_NAME)
                if next_store.authenticate(current_store.username, new_password) is None:
                    raise LocalAdminRotationError("credential_rotation_validation_failed")
                self._write_regular(directory_fd, ROLLBACK_NAME, old_data)
                # Make the rollback directory entry durable before the target
                # credential can be switched to the new verifier.
                os.fsync(directory_fd)
                os.replace(NEXT_NAME, self.path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                replaced = True
                os.fsync(directory_fd)
                committed_store = self._store()
                if committed_store.authenticate(current_store.username, new_password) is None:
                    raise LocalAdminRotationError("credential_rotation_validation_failed")
                if commit_hook is not None:
                    try:
                        commit_hook()
                    except LocalAdminRotationError:
                        raise
                    except Exception as exc:
                        raise LocalAdminRotationError("credential_commit_hook_failed") from exc
                committed = True
                # The credential switch and optional external evidence are now
                # committed. Cleanup failure cannot be reported as rotation
                # failure because the new password is already authoritative;
                # the next recovery pass safely removes a retained rollback.
                try:
                    self._unlink_regular(directory_fd, ROLLBACK_NAME)
                    os.fsync(directory_fd)
                except (LocalAdminRotationError, OSError):
                    pass
                return committed_store
            except LocalAdminRotationError:
                if replaced and not committed and self._exists(directory_fd, ROLLBACK_NAME):
                    try:
                        os.replace(ROLLBACK_NAME, self.path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                        os.fsync(directory_fd)
                        self._store()
                    except (LocalAdminAuthError, LocalAdminRotationError, OSError) as exc:
                        raise LocalAdminRotationError("credential_rotation_rollback_failed") from exc
                try:
                    self._unlink_regular(directory_fd, NEXT_NAME)
                    self._unlink_regular(directory_fd, ROLLBACK_NAME)
                    os.fsync(directory_fd)
                except (LocalAdminRotationError, OSError):
                    pass
                raise
            except (LocalAdminAuthError, LocalAdminProvisionError, OSError) as exc:
                if replaced and not committed and self._exists(directory_fd, ROLLBACK_NAME):
                    try:
                        os.replace(ROLLBACK_NAME, self.path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                        os.fsync(directory_fd)
                    except OSError as rollback_exc:
                        raise LocalAdminRotationError("credential_rotation_rollback_failed") from rollback_exc
                try:
                    self._unlink_regular(directory_fd, NEXT_NAME)
                    self._unlink_regular(directory_fd, ROLLBACK_NAME)
                    os.fsync(directory_fd)
                except (LocalAdminRotationError, OSError):
                    pass
                raise LocalAdminRotationError("credential_rotation_failed") from exc
            finally:
                if lock_fd is not None:
                    os.close(lock_fd)
                os.close(directory_fd)

    def rotate(self, username: str, current_password: str, new_password: str) -> LocalAdminCredentialStore:
        """Atomically replace a verifier after checking the current password."""

        return self._change(
            new_password,
            username=username,
            current_password=current_password,
            commit_hook=None,
        )

    def reset(
        self,
        new_password: str,
        *,
        commit_hook: Callable[[], None] | None = None,
    ) -> LocalAdminCredentialStore:
        """Reset a verifier for an already authorized local-console recovery.

        This primitive deliberately implements no authorization surface. Only
        the packaged root/local-console recovery entry point may invoke it.
        """

        return self._change(
            new_password,
            username=None,
            current_password=None,
            commit_hook=commit_hook,
        )
