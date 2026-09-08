"""Read-only identity of the installed Home Center release."""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

from . import __version__


REVISION = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
MAX_IDENTITY_BYTES = 128


class ReleaseIdentityError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _read_identity_file(path: Path, pattern: re.Pattern[str], code: str) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseIdentityError(code) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_mode & 0o022
        or info.st_size < 1
        or info.st_size > MAX_IDENTITY_BYTES
    ):
        raise ReleaseIdentityError(code)
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseIdentityError(code) from exc
    if pattern.fullmatch(value) is None:
        raise ReleaseIdentityError(code)
    return value


def release_root() -> Path:
    """Return the artifact root when the package is installed from a release."""

    return Path(__file__).resolve().parent.parent


def current_release_identity(root: Path | None = None) -> dict[str, Any]:
    """Return bounded, non-secret release identity.

    A source-tree execution has no VERSION/REVISION pair and is reported as
    ``source``. If one identity file is present without the other, or either is
    malformed, the function fails closed rather than inventing a revision.
    """

    base = Path(root) if root is not None else release_root()
    version_path = base / "VERSION"
    revision_path = base / "REVISION"
    version_exists = version_path.exists() or version_path.is_symlink()
    revision_exists = revision_path.exists() or revision_path.is_symlink()

    if not version_exists and not revision_exists:
        return {
            "schema": "home-center.release-identity.v1",
            "version": __version__,
            "revision": None,
            "build": "source",
            "source": "source-tree",
        }
    if version_exists != revision_exists:
        raise ReleaseIdentityError("release_identity_incomplete")

    version = _read_identity_file(version_path, VERSION, "release_version_rejected")
    revision = _read_identity_file(revision_path, REVISION, "release_revision_rejected")
    if version != __version__:
        raise ReleaseIdentityError("release_version_runtime_mismatch")
    return {
        "schema": "home-center.release-identity.v1",
        "version": version,
        "revision": revision,
        "build": revision[:12],
        "source": "immutable-artifact",
    }
