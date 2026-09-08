"""Infrastructure-neutral TLS status for the public distribution."""
from __future__ import annotations

import hashlib
import ssl
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config

OPENSSL = "/usr/bin/openssl"
RENEWAL_DAYS = 30
WEB_CURRENT = Path("/etc/home-center/pki/web/current")
WEB_CERTIFICATE = WEB_CURRENT / "tls.crt"


def _chain_valid(cert: Path, ca: Path) -> bool:
    try:
        result = subprocess.run(
            [OPENSSL, "verify", "-x509_strict", "-CAfile", str(ca), str(cert)],
            check=False,
            capture_output=True,
            text=False,
            timeout=5,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _certificate_profile(path: Path, *, scope: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [OPENSSL, "x509", "-in", str(path), "-noout", "-text"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        result = None
    text = result.stdout if result is not None and result.returncode == 0 else ""
    if "Public Key Algorithm: id-ecPublicKey" in text:
        algorithm = "ECDSA"
    elif "Public Key Algorithm: ED25519" in text:
        algorithm = "Ed25519"
    elif "Public Key Algorithm: rsaEncryption" in text:
        algorithm = "RSA"
    else:
        algorithm = "unknown"
    curve = "P-256" if "ASN1 OID: prime256v1" in text else None
    signature = "unknown"
    for line in text.splitlines():
        if "Signature Algorithm:" in line:
            signature = line.split("Signature Algorithm:", 1)[1].strip()
            break
    if scope == "browser-web-ca":
        valid = algorithm == "ECDSA" and curve == "P-256" and signature == "ecdsa-with-SHA256" and "CA:TRUE" in text
        profile = "ecdsa-p256-sha256-ca" if valid else "unsupported-for-browser-web-ca"
    elif scope == "peer-mtls":
        valid = algorithm == "Ed25519" and signature == "ED25519" and "CA:FALSE" in text
        profile = "ed25519-peer-mtls" if valid else "unexpected-peer-profile"
    else:
        valid = algorithm == "ECDSA" and curve == "P-256" and signature == "ecdsa-with-SHA256" and "CA:FALSE" in text
        profile = "ecdsa-p256-sha256" if valid else "unsupported-for-browser-web"
    return {
        "profile": profile,
        "profile_valid": valid,
        "public_key_algorithm": algorithm,
        "public_key_curve": curve,
        "signature_algorithm": signature,
    }


def _fingerprint(path: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(path.read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


def _certificate(
    path: Path,
    ca: Path,
    expected_hostname: str,
    *,
    scope: str,
    required_ip: str | None = None,
) -> dict[str, Any]:
    decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
    sans = decoded.get("subjectAltName", ())
    dns = sorted(value for kind, value in sans if kind == "DNS")
    ips = sorted(value for kind, value in sans if kind in {"IP Address", "IP"})
    not_after = decoded.get("notAfter")
    days = None
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
        days = int((expires - datetime.now(timezone.utc)).total_seconds() // 86400)
    hostname_match = expected_hostname in dns or (required_ip is not None and required_ip in ips)
    result = {
        "mode": "separate-web-identity" if scope == "browser-web" else "peer-mtls-identity",
        "fingerprint_sha256": _fingerprint(path),
        "not_after": not_after,
        "days_remaining": days,
        "san_dns": dns,
        "san_ip": ips,
        "expected_hostname": expected_hostname,
        "hostname_match": hostname_match,
        "chain_valid": _chain_valid(path, ca),
        "required_san_dns": [expected_hostname],
        "required_san_ip": [required_ip] if required_ip else [],
        "san_policy_valid": hostname_match,
    }
    result.update(_certificate_profile(path, scope=scope))
    return result


def status(config: Config) -> dict[str, Any]:
    web_hostname = config.external_access.public_hostname or config.node_name
    web_path = WEB_CERTIFICATE if WEB_CERTIFICATE.is_file() else config.tls_certificate
    web_ca = config.web_ca if WEB_CERTIFICATE.is_file() else config.cluster_ca
    web = _certificate(
        web_path,
        web_ca,
        web_hostname,
        scope="browser-web",
        required_ip=config.management_address,
    )
    peer = _certificate(
        config.tls_certificate,
        config.cluster_ca,
        f"home-center-{config.node_name}",
        scope="peer-mtls",
        required_ip=config.management_address,
    )
    web_ca_profile = _certificate_profile(config.web_ca, scope="browser-web-ca")
    try:
        web_ca_fingerprint = _fingerprint(config.web_ca)
    except Exception:
        web_ca_fingerprint = None
    days = web.get("days_remaining")
    renewal_due = (
        days is None
        or int(days) <= RENEWAL_DAYS
        or not bool(web.get("chain_valid"))
        or not bool(web.get("hostname_match"))
        or not bool(web.get("profile_valid"))
    )
    return {
        "schema": "home-center.tls-status.v1",
        "node_id": config.node_id,
        "node_name": config.node_name,
        "web_hostname": web_hostname,
        "canonical_web_hostname": web_hostname,
        "web_url": f"https://{web_hostname}:{config.web_port}",
        "web": web,
        "peer": peer,
        "web_ca": {"fingerprint_sha256": web_ca_fingerprint, **web_ca_profile},
        "trust_anchor": {"fingerprint_sha256": _fingerprint(config.cluster_ca)},
        "candidate": {
            "certificate_present": False,
            "private_key_present": False,
            "owner_marker_present": False,
            "complete": False,
            "partial": False,
            "invalid": False,
        },
        "operational": {"state": "ready", "healthy": True, "recovery_required": False, "reason": None},
        "renewal": {
            "threshold_days": RENEWAL_DAYS,
            "web_ca_threshold_days": None,
            "due": renewal_due,
            "last_maintenance": None,
        },
    }
