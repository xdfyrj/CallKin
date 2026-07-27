from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from build_profiles import BUILD_TARGET, RUSTC_EDITION, STRIP_FLAGS, compile_flags
from provenance import BuildProvenance


BUILD_MANIFEST_SCHEMA_VERSION = 2
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class VerifiedBuild:
    manifest_path: str
    build_id: str
    profile: str
    source: str
    non_stripped_binary: str
    stripped_binary: str
    provenance: BuildProvenance


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(manifest: dict[str, Any], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_and_verify_manifest(
    manifest_path: str | Path,
    *,
    expected_case: str,
    expected_build: str,
    expected_profile: str,
    expected_target: str = BUILD_TARGET,
) -> VerifiedBuild:
    path = Path(manifest_path)
    if not path.is_file():
        raise ValueError(
            f"build manifest not found: {path}. Run compile.py for this case/build first."
        )

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read build manifest {path}: {exc}") from exc

    manifest = _require_dict(raw, "manifest")
    schema_version = _require_int(manifest, "schema_version")
    if schema_version != BUILD_MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported build manifest schema_version {schema_version}: {path}"
        )

    case = _require_string(manifest, "case")
    build = _require_string(manifest, "build")
    profile = _require_string(manifest, "profile")
    target = _require_string(manifest, "target")
    build_id = _require_string(manifest, "build_id")

    if case != expected_case:
        raise ValueError(
            f"build manifest case mismatch: expected {expected_case!r}, got {case!r}"
        )
    if build != expected_build:
        raise ValueError(
            f"build manifest build mismatch: expected {expected_build!r}, got {build!r}"
        )
    if profile != expected_profile:
        raise ValueError(
            "build manifest profile mismatch: "
            f"expected {expected_profile!r}, got {profile!r}"
        )
    if target != expected_target:
        raise ValueError(
            f"build manifest target mismatch: expected {expected_target!r}, got {target!r}"
        )
    if _require_string(manifest, "crate_name") != case:
        raise ValueError("build manifest crate_name must equal case")
    edition = _require_string(manifest, "edition")
    if edition != RUSTC_EDITION:
        raise ValueError(
            f"build manifest edition mismatch: expected {RUSTC_EDITION!r}, got {edition!r}"
        )

    source_record = _require_dict(manifest.get("source"), "source")
    source = _verify_file_record("source", source_record)
    artifacts = _require_dict(manifest.get("artifacts"), "artifacts")
    non_stripped_record = _require_dict(
        artifacts.get("non_stripped"), "artifacts.non_stripped"
    )
    stripped_record = _require_dict(
        artifacts.get("stripped"), "artifacts.stripped"
    )
    non_stripped = _verify_file_record("non-stripped binary", non_stripped_record)
    stripped = _verify_file_record("stripped binary", stripped_record)

    non_stripped_sha256 = _require_sha256(non_stripped_record, "sha256")
    stripped_from_sha256 = _require_sha256(
        stripped_record, "stripped_from_sha256"
    )
    if stripped_from_sha256 != non_stripped_sha256:
        raise ValueError(
            "build manifest relation mismatch: stripped_from_sha256 does not "
            "equal non-stripped sha256"
        )

    compiler = _require_dict(manifest.get("compiler"), "compiler")
    strip = _require_dict(manifest.get("strip"), "strip")
    _require_string(compiler, "invoked_path")
    _require_string(compiler, "resolved_path")
    _require_string(compiler, "sysroot")
    _require_string(compiler, "compiler_binary_path")
    _require_string(compiler, "verbose_version")
    _require_string(strip, "invoked_path")
    _require_string(strip, "resolved_path")
    _require_string(strip, "version")
    _require_string_list(compiler, "command")
    compiler_flags = _require_string_list(compiler, "flags")
    expected_flags = compile_flags(profile, build)
    if compiler_flags != expected_flags:
        raise ValueError(
            "build manifest compiler flags do not match the canonical "
            f"{profile}/{build} profile: {compiler_flags!r} != {expected_flags!r}"
        )
    _require_string_list(strip, "command")
    strip_flags = _require_string_list(strip, "flags")
    if strip_flags != STRIP_FLAGS:
        raise ValueError(
            f"build manifest strip flags mismatch: {strip_flags!r} != {STRIP_FLAGS!r}"
        )

    return VerifiedBuild(
        manifest_path=str(path),
        build_id=build_id,
        profile=profile,
        source=source,
        non_stripped_binary=non_stripped,
        stripped_binary=stripped,
        provenance=BuildProvenance(
            build_id=build_id,
            source_sha256=_require_sha256(source_record, "sha256"),
            non_stripped_sha256=non_stripped_sha256,
            stripped_sha256=_require_sha256(stripped_record, "sha256"),
        ),
    )


def _verify_file_record(label: str, record: dict[str, Any]) -> str:
    path_text = _require_string(record, "path")
    expected_hash = _require_sha256(record, "sha256")
    path = Path(path_text)
    if not path.is_file():
        raise ValueError(f"{label} not found: {path}")
    actual_hash = sha256_file(path)
    if actual_hash != expected_hash:
        raise ValueError(
            f"{label} hash mismatch: expected {expected_hash}, got {actual_hash}: {path}"
        )
    return str(path)


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"build manifest {label} must be an object")
    return value


def _require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"build manifest field {key!r} must be a non-empty string")
    return value


def _require_int(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"build manifest field {key!r} must be an integer")
    return value


def _require_sha256(mapping: dict[str, Any], key: str) -> str:
    value = _require_string(mapping, key)
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"build manifest field {key!r} must be a SHA-256 digest")
    return value


def _require_string_list(mapping: dict[str, Any], key: str) -> list[str]:
    value = mapping.get(key)
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(
            f"build manifest field {key!r} must be a non-empty string array"
        )
    return value
