from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from home_center.api import RuntimeRequestHandler
from home_center.local_admin_auth import (
    CREDENTIAL_SCHEMA,
    LocalAdminAuthError,
    LocalAdminCredentialStore,
)
from home_center.local_admin_provision import credential_document, ensure_default_admin_credential_file
from home_center.local_admin_rotation import LocalAdminCredentialRotator
from home_center.privileged_helper import _execute_secret_request, _validate_policy


class FirstLoginCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o750)
        self.path = self.directory / "local-admin.json"
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def ensure(self) -> tuple[str, bool]:
        return ensure_default_admin_credential_file(
            self.path,
            expected_directory_uid=self.uid,
            expected_directory_gid=self.gid,
            expected_directory_mode=0o750,
            file_uid=self.uid,
            file_gid=self.gid,
            file_mode=0o640,
        )

    def store(self) -> LocalAdminCredentialStore:
        return LocalAdminCredentialStore(
            self.path,
            expected_uid=self.uid,
            expected_gid=self.gid,
            expected_mode=0o640,
        )

    def test_clean_install_creates_one_time_admin_credential(self) -> None:
        self.assertEqual(self.ensure(), ("admin", True))
        credential = self.store()
        self.assertTrue(credential.verify("admin", "admin"))
        self.assertTrue(credential.password_change_required)

    def test_upgrade_preserves_rotated_password_and_state(self) -> None:
        self.ensure()
        rotator = LocalAdminCredentialRotator(
            self.path,
            expected_uid=self.uid,
            expected_gid=self.gid,
            expected_mode=0o640,
            expected_directory_uid=self.uid,
            expected_directory_gid=self.gid,
            expected_directory_mode=0o750,
        )
        rotator.rotate("admin", "admin", "a secure password 2026")
        before = self.path.read_bytes()

        self.assertEqual(self.ensure(), ("admin", False))
        self.assertEqual(self.path.read_bytes(), before)
        credential = self.store()
        self.assertFalse(credential.password_change_required)
        self.assertTrue(credential.verify("admin", "a secure password 2026"))
        self.assertFalse(credential.verify("admin", "admin"))

    def test_legacy_v1_credential_is_never_forced_or_rewritten(self) -> None:
        document = credential_document("admin", "a legacy password 2026", salt=b"s" * 32)
        document["schema"] = CREDENTIAL_SCHEMA
        document.pop("password_change_required")
        self.path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        self.path.chmod(0o640)
        before = self.path.read_bytes()

        self.assertEqual(self.ensure(), ("admin", False))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(self.store().password_change_required)

    def test_short_password_exception_is_limited_to_exact_bootstrap(self) -> None:
        with self.assertRaises(LocalAdminAuthError):
            credential_document(
                "admin",
                "admin",
                password_change_required=False,
                allow_default_bootstrap=True,
            )
        with self.assertRaises(LocalAdminAuthError):
            credential_document(
                "operator",
                "admin",
                password_change_required=True,
                allow_default_bootstrap=True,
            )


class _GateHarness(RuntimeRequestHandler):
    def __init__(self, actor: str, password_change_required: bool) -> None:
        self._test_actor = actor
        self.error: tuple[int, str] | None = None
        runtime = SimpleNamespace(
            actor_requires_password_change=lambda candidate: password_change_required and candidate == actor
        )
        self.server = SimpleNamespace(runtime=runtime)

    def _actor(self) -> str | None:
        return self._test_actor

    def _error(self, status: int, code: str, _message: str, _correlation_id: str, **_kwargs: object) -> None:
        self.error = (status, code)


class FirstLoginGateTests(unittest.TestCase):
    def test_ordinary_authenticated_work_is_blocked_until_rotation(self) -> None:
        handler = _GateHarness("local-admin:admin", True)
        self.assertIsNone(handler._require_actor("correlation"))
        self.assertEqual(handler.error, (403, "password_change_required"))

    def test_session_and_password_change_surfaces_remain_available(self) -> None:
        handler = _GateHarness("local-admin:admin", True)
        self.assertEqual(
            handler._require_actor("correlation", allow_password_change_required=True),
            "local-admin:admin",
        )
        self.assertIsNone(handler.error)

    def test_rotated_local_admin_is_fully_authorized(self) -> None:
        handler = _GateHarness("local-admin:admin", False)
        self.assertEqual(handler._require_actor("correlation"), "local-admin:admin")
        self.assertIsNone(handler.error)


class PasswordRotationHelperTests(unittest.TestCase):
    def test_policy_admits_only_the_typed_rotation_permission(self) -> None:
        policy = {
            "schema": "home-center.helper.policy.v1",
            "callers": {"home-center": ["local-admin.password.rotate"]},
            "enabled_actions": ["local-admin.password.rotate.v1"],
        }
        _validate_policy(policy)

    def test_secret_rotation_result_never_echoes_passwords(self) -> None:
        request = {
            "schema": "home-center.helper.secret-request.v1",
            "request_id": "password-01234567",
            "action": "local-admin.password.rotate.v1",
            "params": {
                "username": "admin",
                "current_password": "admin",
                "new_password": "a secure password 2026",
            },
            "nonce": "0" * 32,
        }
        policy = {
            "schema": "home-center.helper.policy.v1",
            "callers": {"home-center": ["local-admin.password.rotate"]},
            "enabled_actions": ["local-admin.password.rotate.v1"],
        }
        rotator = Mock()
        with (
            patch("home_center.privileged_helper.os.geteuid", return_value=0),
            patch("home_center.privileged_helper.pwd.getpwnam", return_value=SimpleNamespace(pw_gid=1000)),
            patch("home_center.privileged_helper.LocalAdminCredentialRotator", return_value=rotator),
        ):
            result = _execute_secret_request(
                request,
                caller_uid=1000,
                caller_name="home-center",
                policy=policy,
            )
        self.assertEqual(result["status"], "succeeded")
        serialized = json.dumps(result)
        self.assertNotIn("a secure password 2026", serialized)
        self.assertNotIn('"admin"', serialized)
        rotator.rotate.assert_called_once_with("admin", "admin", "a secure password 2026")

if __name__ == "__main__":
    unittest.main()
