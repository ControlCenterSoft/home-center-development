"""Офлайн-проверка и content-addressed staging артефактов модулей.

В этом модуле намеренно отсутствуют сетевой клиент, распаковщик архивов, исполнитель lifecycle,
управление сервисами и поддержка закрытых ключей. Вызывающая сторона передаёт ограниченный
объём байтов; в object store может попасть только криптографически проверенный архив.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from home_center.module_manifest import ModuleManifestError, load_manifest, validate_manifest


OPENSSL = "/usr/bin/openssl"
PAYLOAD_TYPE = "application/vnd.home-center.module-provenance.v1+json"
MANIFEST_BINDING_ALGORITHM = "home-center-canonical-json-zero-statement-v1"
MEDIA_TYPE = "application/vnd.home-center.module.v1+tar+gzip"

MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_TRUST_POLICY_BYTES = 128 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_SIGNATURES = 16

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
MODULE_ID = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SOURCE_REF = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9._/-]{1,240}$")
WORKFLOW = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")


class ModuleArtifactError(ValueError):
    """Стабильная причина отказа без секретов, пригодная для вывода в аудит."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerifiedModuleArtifact:
    module_id: str
    version: str
    publisher: str
    manifest_binding_sha256: str
    statement_sha256: str
    artifact_sha256: str
    artifact_size_bytes: int
    signing_key_ids: tuple[str, ...]
    object_key: str


@dataclass(frozen=True)
class StagedModuleArtifact:
    verified: VerifiedModuleArtifact
    created: bool


def _reject(code: str) -> None:
    raise ModuleArtifactError(code)


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate_json_key")
        result[key] = value
    return result


def _reject_float(_: str) -> None:
    _reject("json_float_rejected")


def _reject_constant(_: str) -> None:
    _reject("json_constant_rejected")


def _strict_json(data: bytes, *, maximum: int, kind: str) -> Any:
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        _reject(f"{kind}_size_rejected")
    if data.startswith(b"\xef\xbb\xbf"):
        _reject(f"{kind}_bom_rejected")
    try:
        return json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ModuleArtifactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ModuleArtifactError(f"{kind}_json_rejected") from exc


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ModuleArtifactError("canonical_json_rejected") from exc


def _exact(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _reject(code)
    return value


def _string(value: Any, pattern: re.Pattern[str], code: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or pattern.fullmatch(value) is None:
        _reject(code)
    return value


def _integer(value: Any, code: str, *, minimum: int = 1, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _reject(code)
    return value


def _b64(value: Any, code: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _reject(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ModuleArtifactError(code) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        _reject(code)
    return decoded


def manifest_binding_sha256(manifest: dict[str, Any]) -> str:
    """Хеширует манифест с обнулённым digest statement, разрывая цикл хеширования."""

    normalized = copy.deepcopy(manifest)
    try:
        normalized["artifact"]["provenance"]["statement_sha256"] = "0" * 64
    except (KeyError, TypeError) as exc:
        raise ModuleArtifactError("manifest_binding_shape_rejected") from exc
    return hashlib.sha256(canonical_json(normalized)).hexdigest()


def _run_openssl(arguments: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            [OPENSSL, *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            close_fds=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ModuleArtifactError("openssl_unavailable") from exc


def _validate_policy(policy: Any, *, publisher: str, declared_key_ids: set[str]) -> tuple[int, dict[str, tuple[str, bytes]]]:
    value = _exact(
        policy,
        {"schema", "publisher", "payload_type", "threshold", "keys"},
        "trust_policy_shape_rejected",
    )
    if value["schema"] != "home-center.module-trust-policy.v1":
        _reject("trust_policy_schema_rejected")
    if value["publisher"] != publisher or value["payload_type"] != PAYLOAD_TYPE:
        _reject("trust_policy_scope_rejected")
    threshold = _integer(value["threshold"], "trust_policy_threshold_rejected", maximum=MAX_SIGNATURES)
    raw_keys = value["keys"]
    if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= MAX_SIGNATURES:
        _reject("trust_policy_keys_rejected")

    keys: dict[str, tuple[str, bytes]] = {}
    active_declared = 0
    with tempfile.TemporaryDirectory(prefix="home-center-module-key-") as temporary:
        for index, raw_key in enumerate(raw_keys):
            key = _exact(raw_key, {"keyid", "algorithm", "state", "public_key_pem"}, "trust_key_shape_rejected")
            keyid = _string(key["keyid"], KEY_ID, "trust_key_id_rejected", maximum=71)
            if keyid in keys:
                _reject("trust_key_duplicate")
            if key["algorithm"] != "ecdsa-p256-sha256" or key["state"] not in {"active", "retired", "revoked"}:
                _reject("trust_key_policy_rejected")
            pem = key["public_key_pem"]
            if (
                not isinstance(pem, str)
                or len(pem) > 4096
                or not pem.startswith("-----BEGIN PUBLIC KEY-----\n")
                or not pem.endswith("-----END PUBLIC KEY-----\n")
            ):
                _reject("trust_key_pem_rejected")
            try:
                pem_bytes = pem.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ModuleArtifactError("trust_key_pem_rejected") from exc
            public_path = Path(temporary) / f"key-{index}.pem"
            public_path.write_bytes(pem_bytes)
            public_path.chmod(0o600)
            der = _run_openssl(["pkey", "-pubin", "-in", str(public_path), "-outform", "DER"])
            description = _run_openssl(["pkey", "-pubin", "-in", str(public_path), "-text_pub", "-noout"])
            if der.returncode != 0 or description.returncode != 0:
                _reject("trust_key_parse_rejected")
            key_text = description.stdout.decode("ascii", errors="replace")
            if "Public-Key: (256 bit)" not in key_text or "ASN1 OID: prime256v1" not in key_text:
                _reject("trust_key_algorithm_rejected")
            if keyid != "sha256:" + hashlib.sha256(der.stdout).hexdigest():
                _reject("trust_key_id_mismatch")
            keys[keyid] = (key["state"], pem_bytes)
            if keyid in declared_key_ids and key["state"] == "active":
                active_declared += 1
    if not declared_key_ids.issubset(keys):
        _reject("manifest_signer_unknown")
    if threshold > active_declared:
        _reject("trust_policy_active_threshold_rejected")
    return threshold, keys


def _dsse_pae(payload: bytes) -> bytes:
    type_bytes = PAYLOAD_TYPE.encode("ascii")
    return b"DSSEv1 " + str(len(type_bytes)).encode() + b" " + type_bytes + b" " + str(len(payload)).encode() + b" " + payload


def _verify_signatures(
    envelope: dict[str, Any],
    policy: Any,
    payload: bytes,
    *,
    publisher: str,
    declared_key_ids: set[str],
    declared_threshold: int,
) -> tuple[str, ...]:
    policy_threshold, keys = _validate_policy(policy, publisher=publisher, declared_key_ids=declared_key_ids)
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= MAX_SIGNATURES:
        _reject("signature_count_rejected")
    pae = _dsse_pae(payload)
    seen: set[str] = set()
    active_signers: list[str] = []
    with tempfile.TemporaryDirectory(prefix="home-center-module-signature-") as temporary:
        for index, raw_signature in enumerate(signatures):
            signature = _exact(raw_signature, {"keyid", "sig"}, "signature_shape_rejected")
            keyid = _string(signature["keyid"], KEY_ID, "signature_key_id_rejected", maximum=71)
            if keyid in seen:
                _reject("signature_key_duplicate")
            seen.add(keyid)
            if keyid not in declared_key_ids:
                _reject("signature_undeclared_key")
            state, pem = keys[keyid]
            if state == "revoked":
                _reject("signature_revoked_key")
            signature_bytes = _b64(signature["sig"], "signature_base64_rejected", maximum=1024)
            if not 8 <= len(signature_bytes) <= 128:
                _reject("signature_encoding_rejected")
            public_path = Path(temporary) / f"key-{index}.pem"
            signature_path = Path(temporary) / f"signature-{index}.der"
            public_path.write_bytes(pem)
            signature_path.write_bytes(signature_bytes)
            public_path.chmod(0o600)
            signature_path.chmod(0o600)
            result = _run_openssl(
                ["dgst", "-sha256", "-verify", str(public_path), "-signature", str(signature_path)],
                input_bytes=pae,
            )
            if result.returncode != 0:
                _reject("signature_verification_failed")
            if state == "active":
                active_signers.append(keyid)
    if len(active_signers) < max(policy_threshold, declared_threshold):
        _reject("signature_threshold_not_met")
    return tuple(sorted(active_signers))


def _validate_statement(statement: Any, manifest: dict[str, Any], binding_sha256: str) -> None:
    value = _exact(statement, {"schema", "module", "manifest", "artifact", "source"}, "statement_shape_rejected")
    if value["schema"] != "home-center.module-provenance.v1":
        _reject("statement_schema_rejected")

    module = _exact(value["module"], {"id", "version", "publisher"}, "statement_module_shape_rejected")
    _string(module["id"], MODULE_ID, "statement_module_id_rejected", maximum=128)
    _string(module["version"], SEMVER, "statement_module_version_rejected", maximum=64)
    _string(module["publisher"], MODULE_ID, "statement_publisher_rejected", maximum=128)
    if module != {
        "id": manifest["module"]["id"],
        "version": manifest["module"]["version"],
        "publisher": manifest["module"]["publisher"],
    }:
        _reject("statement_module_mismatch")

    manifest_record = _exact(
        value["manifest"], {"schema", "binding_algorithm", "sha256"}, "statement_manifest_shape_rejected"
    )
    if (
        manifest_record["schema"] != "home-center.module-manifest.v2"
        or manifest_record["binding_algorithm"] != MANIFEST_BINDING_ALGORITHM
        or _string(manifest_record["sha256"], HEX64, "statement_manifest_sha256_rejected", maximum=64)
        != binding_sha256
    ):
        _reject("statement_manifest_mismatch")

    artifact = _exact(value["artifact"], {"sha256", "size_bytes", "media_type"}, "statement_artifact_shape_rejected")
    _string(artifact["sha256"], HEX64, "statement_artifact_sha256_rejected", maximum=64)
    _integer(artifact["size_bytes"], "statement_artifact_size_rejected", maximum=MAX_ARTIFACT_BYTES)
    if artifact != {
        "sha256": manifest["artifact"]["sha256"],
        "size_bytes": manifest["artifact"]["size_bytes"],
        "media_type": MEDIA_TYPE,
    }:
        _reject("statement_artifact_mismatch")

    source = _exact(
        value["source"], {"repository", "revision", "ref", "workflow", "run_id", "run_attempt"}, "statement_source_shape_rejected"
    )
    _string(source["repository"], REPOSITORY, "statement_repository_rejected")
    _string(source["revision"], HEX40, "statement_revision_rejected", maximum=40)
    _string(source["ref"], SOURCE_REF, "statement_ref_rejected")
    _string(source["workflow"], WORKFLOW, "statement_workflow_rejected")
    _integer(source["run_id"], "statement_run_id_rejected")
    _integer(source["run_attempt"], "statement_run_attempt_rejected", maximum=1024)


def _validate_archive(artifact: bytes) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(artifact), mode="r:gz") as archive:
            seen: set[str] = set()
            total = 0
            regular_files = 0
            for index, member in enumerate(archive):
                if index >= MAX_ARCHIVE_MEMBERS:
                    _reject("archive_member_count_rejected")
                name = member.name
                try:
                    name.encode("ascii")
                except (AttributeError, UnicodeEncodeError) as exc:
                    raise ModuleArtifactError("archive_member_name_rejected") from exc
                path = PurePosixPath(name)
                normalized = path.as_posix()
                if (
                    not name
                    or len(name) > 256
                    or "\\" in name
                    or path.is_absolute()
                    or normalized in {"", "."}
                    or name.rstrip("/") != normalized
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or any(ord(character) < 32 or ord(character) == 127 for character in name)
                ):
                    _reject("archive_member_name_rejected")
                if normalized in seen:
                    _reject("archive_member_duplicate_rejected")
                seen.add(normalized)
                if not (member.isfile() or member.isdir()):
                    _reject("archive_member_type_rejected")
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    _reject("archive_member_size_rejected")
                if member.mode & 0o7000:
                    _reject("archive_member_mode_rejected")
                total += member.size
                if total > MAX_ARTIFACT_BYTES:
                    _reject("archive_total_size_rejected")
                regular_files += member.isfile()
            if regular_files == 0:
                _reject("archive_empty_rejected")
    except ModuleArtifactError:
        raise
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ModuleArtifactError("archive_format_rejected") from exc


def verify_module_artifact(
    manifest_bytes: bytes,
    envelope_bytes: bytes,
    trust_policy_bytes: bytes,
    artifact_bytes: bytes,
) -> VerifiedModuleArtifact:
    """Проверяет манифест, подписи provenance и идентичность архива без staging."""

    try:
        manifest = load_manifest(manifest_bytes)
        identity = validate_manifest(manifest)
    except ModuleManifestError as exc:
        raise ModuleArtifactError(exc.code) from exc
    if not isinstance(artifact_bytes, bytes) or not artifact_bytes or len(artifact_bytes) > MAX_ARTIFACT_BYTES:
        _reject("artifact_size_limit_rejected")
    if len(artifact_bytes) != identity.artifact_size_bytes:
        _reject("artifact_size_mismatch")
    if hashlib.sha256(artifact_bytes).hexdigest() != identity.artifact_sha256:
        _reject("artifact_sha256_mismatch")

    envelope = _exact(
        _strict_json(envelope_bytes, maximum=MAX_ENVELOPE_BYTES, kind="envelope"),
        {"payloadType", "payload", "signatures"},
        "envelope_shape_rejected",
    )
    if envelope["payloadType"] != PAYLOAD_TYPE:
        _reject("envelope_payload_type_rejected")
    payload = _b64(envelope["payload"], "envelope_payload_rejected", maximum=MAX_PAYLOAD_BYTES * 2)
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        _reject("provenance_payload_size_rejected")
    statement = _strict_json(payload, maximum=MAX_PAYLOAD_BYTES, kind="provenance")
    if canonical_json(statement) != payload:
        _reject("provenance_payload_not_canonical")

    binding_sha256 = manifest_binding_sha256(manifest)
    _validate_statement(statement, manifest, binding_sha256)
    statement_sha256 = hashlib.sha256(payload).hexdigest()
    provenance = manifest["artifact"]["provenance"]
    if statement_sha256 != provenance["statement_sha256"]:
        _reject("provenance_statement_sha256_mismatch")
    declared_key_ids = set(provenance["signer_key_ids"])
    signing_key_ids = _verify_signatures(
        envelope,
        _strict_json(trust_policy_bytes, maximum=MAX_TRUST_POLICY_BYTES, kind="trust_policy"),
        payload,
        publisher=manifest["module"]["publisher"],
        declared_key_ids=declared_key_ids,
        declared_threshold=provenance["threshold"],
    )
    _validate_archive(artifact_bytes)
    object_key = f"sha256/{identity.artifact_sha256[:2]}/{identity.artifact_sha256}/artifact.tar.gz"
    return VerifiedModuleArtifact(
        module_id=identity.module_id,
        version=identity.version,
        publisher=manifest["module"]["publisher"],
        manifest_binding_sha256=binding_sha256,
        statement_sha256=statement_sha256,
        artifact_sha256=identity.artifact_sha256,
        artifact_size_bytes=identity.artifact_size_bytes,
        signing_key_ids=signing_key_ids,
        object_key=object_key,
    )


def _open_child_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        raise ModuleArtifactError("object_store_directory_rejected") from exc


def _verify_existing_object(directory_fd: int, artifact: bytes) -> None:
    try:
        descriptor = os.open("artifact.tar.gz", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    except OSError as exc:
        raise ModuleArtifactError("object_store_existing_rejected") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            _reject("object_store_existing_rejected")
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    finally:
        os.close(descriptor)
    if size != len(artifact) or digest.digest() != hashlib.sha256(artifact).digest():
        _reject("object_store_collision_rejected")


def _stage_verified_bytes(root: Path, verified: VerifiedModuleArtifact, artifact: bytes) -> bool:
    if not root.is_absolute():
        _reject("object_store_root_rejected")
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise ModuleArtifactError("object_store_root_rejected") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        _reject("object_store_root_rejected")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    temporary_name = f".artifact-{os.getpid()}-{os.urandom(8).hex()}.tmp"
    try:
        descriptors.append(os.open(root, flags))
        for component in ("sha256", verified.artifact_sha256[:2], verified.artifact_sha256):
            descriptors.append(_open_child_directory(descriptors[-1], component))
        leaf_fd = descriptors[-1]
        try:
            _verify_existing_object(leaf_fd, artifact)
            return False
        except ModuleArtifactError as exc:
            if exc.code != "object_store_existing_rejected":
                raise

        temporary_fd = -1
        try:
            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=leaf_fd,
            )
            view = memoryview(artifact)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    _reject("object_store_write_rejected")
                view = view[written:]
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            try:
                os.link(
                    temporary_name,
                    "artifact.tar.gz",
                    src_dir_fd=leaf_fd,
                    dst_dir_fd=leaf_fd,
                    follow_symlinks=False,
                )
                created = True
            except FileExistsError:
                _verify_existing_object(leaf_fd, artifact)
                created = False
            os.unlink(temporary_name, dir_fd=leaf_fd)
            os.fsync(leaf_fd)
            return created
        except ModuleArtifactError:
            raise
        except OSError as exc:
            raise ModuleArtifactError("object_store_write_rejected") from exc
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            try:
                os.unlink(temporary_name, dir_fd=leaf_fd)
            except FileNotFoundError:
                pass
    except ModuleArtifactError:
        raise
    except OSError as exc:
        raise ModuleArtifactError("object_store_root_rejected") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def stage_module_artifact(
    manifest_bytes: bytes,
    envelope_bytes: bytes,
    trust_policy_bytes: bytes,
    artifact_bytes: bytes,
    *,
    object_store_root: Path,
) -> StagedModuleArtifact:
    """Сначала проверяет, затем атомарно и идемпотентно размещает точные байты архива."""

    verified = verify_module_artifact(manifest_bytes, envelope_bytes, trust_policy_bytes, artifact_bytes)
    created = _stage_verified_bytes(object_store_root, verified, artifact_bytes)
    return StagedModuleArtifact(verified=verified, created=created)
