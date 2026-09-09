#!/usr/bin/env python3
"""Provision the Home Center local administrator without exposing its password."""

from __future__ import annotations

import argparse
import getpass
import grp
import os
import sys
from pathlib import Path


HERE = Path(__file__).resolve()
for candidate in (HERE.parent, HERE.parents[2] / "product/control-plane/src"):
    if (candidate / "home_center").is_dir():
        sys.path.insert(0, str(candidate))
        break

from home_center.local_admin_provision import (  # noqa: E402
    LocalAdminProvisionError,
    ensure_default_admin_credential_file,
    provision_credential_file,
)


CREDENTIAL_PATH = Path("/etc/home-center/secrets/local-admin.json")
SERVICE_GROUP = "home-center"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Provision the Home Center local administrator credential")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--bootstrap-default", action="store_true", help="Create admin/admin once for a clean install")
    mode.add_argument("--username", help="Provision a custom local administrator interactively")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        print("LOCAL_ADMIN_PROVISION_REJECTED=ROOT_REQUIRED", file=sys.stderr)
        return 77
    try:
        service_gid = grp.getgrnam(SERVICE_GROUP).gr_gid
    except KeyError:
        print("LOCAL_ADMIN_PROVISION_REJECTED=SERVICE_GROUP_MISSING", file=sys.stderr)
        return 78

    if args.bootstrap_default:
        try:
            canonical_username, created = ensure_default_admin_credential_file(
                CREDENTIAL_PATH,
                expected_directory_uid=0,
                expected_directory_gid=service_gid,
                expected_directory_mode=0o750,
                file_uid=0,
                file_gid=service_gid,
                file_mode=0o640,
            )
        except LocalAdminProvisionError as exc:
            print(f"LOCAL_ADMIN_PROVISION_REJECTED={exc.code}", file=sys.stderr)
            return 66
        state = "created" if created else "preserved"
        print(f"LOCAL_ADMIN_BOOTSTRAP username={canonical_username} state={state}")
        return 0

    if not sys.stdin.isatty():
        print("LOCAL_ADMIN_PROVISION_REJECTED=INTERACTIVE_TTY_REQUIRED", file=sys.stderr)
        return 64

    password = getpass.getpass("Home Center local administrator password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        password = ""
        confirmation = ""
        print("LOCAL_ADMIN_PROVISION_REJECTED=PASSWORD_CONFIRMATION_MISMATCH", file=sys.stderr)
        return 65

    try:
        canonical_username = provision_credential_file(
            CREDENTIAL_PATH,
            args.username,
            password,
            expected_directory_uid=0,
            expected_directory_gid=service_gid,
            expected_directory_mode=0o750,
            file_uid=0,
            file_gid=service_gid,
            file_mode=0o640,
        )
    except LocalAdminProvisionError as exc:
        print(f"LOCAL_ADMIN_PROVISION_REJECTED={exc.code}", file=sys.stderr)
        return 66
    finally:
        password = ""
        confirmation = ""

    print(f"LOCAL_ADMIN_PROVISIONED username={canonical_username}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
