"""Run Oxidizer separately and retain only auditable FLIRT label evidence.

CallKin's angr environment and Oxidizer's angr fork have intentionally
different dependency pins. This module never imports Oxidizer; it invokes the
standalone oxidizer_probe.py process and validates its JSON result.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from build_manifest import load_and_verify_manifest, sha256_file
from graph_evidence import load_raw_graph, raw_graph_sha256
from gt_extractor import normalize_all_rust_origin, rust_symbol_owner
from paths import (
    BUILD_PROFILES,
    DEFAULT_BUILD,
    DEFAULT_PROFILE,
    build_manifest_for,
    oxidizer_labels_for,
    raw_graph_for,
    split_case_build,
)
from provenance import parse_provenance


LABEL_SCHEMA_VERSION = 1
ADAPTER_VERSION = "direct-flirt-adapter-v1"
DIRECT_FLIRT = "direct-flirt"
PROPAGATED_WRAPPER = "propagated-wrapper"
CLEANUP_HEURISTIC = "cleanup-heuristic"
EVIDENCE_STAGES = (DIRECT_FLIRT, PROPAGATED_WRAPPER, CLEANUP_HEURISTIC)
DEFAULT_OXIDIZER_DIR = "/mnt/c/users/sumyr/playground/oxidizer"


def _address(value: object, *, where: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{where} must be a hexadecimal string")
    try:
        return int(value, 0)
    except ValueError as exc:
        raise ValueError(f"invalid {where}: {value!r}") from exc


def _hex(address: int) -> str:
    return f"0x{address:x}"


def _require_string(value: object, *, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where} must be a non-empty string")
    return value


def _require_match(item: object, *, evidence: str, where: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"{where} must be an object")
    required = {
        "address", "mapped_address", "name", "canonical_origin", "owner", "evidence",
    }
    if set(item) != required:
        raise ValueError(f"{where} must contain exactly {sorted(required)}")
    _address(item["address"], where=f"{where}.address")
    _address(item["mapped_address"], where=f"{where}.mapped_address")
    for key in ("name", "canonical_origin", "owner", "evidence"):
        _require_string(item[key], where=f"{where}.{key}")
    if item["evidence"] != evidence:
        raise ValueError(
            f"{where}.evidence must be {evidence!r}, got {item['evidence']!r}"
        )
    return item


def validate_probe_output(
    probe: object,
    *,
    expected_case: str,
    expected_build: str,
    expected_profile: str,
    expected_stripped_sha256: str,
) -> dict[str, Any]:
    """Validate the stripped-only output produced by oxidizer_probe.py."""
    if not isinstance(probe, dict):
        raise ValueError("Oxidizer probe output must be an object")
    required = {
        "schema_version", "case", "build", "profile", "stripped_sha256",
        "analysis", "tool", "matches", "propagated_wrappers", "cleanup_heuristics",
    }
    if set(probe) != required or probe["schema_version"] != LABEL_SCHEMA_VERSION:
        raise ValueError("unsupported Oxidizer probe output schema")
    for key, expected in (
        ("case", expected_case),
        ("build", expected_build),
        ("profile", expected_profile),
        ("stripped_sha256", expected_stripped_sha256),
    ):
        if probe[key] != expected:
            raise ValueError(
                f"Oxidizer probe {key} mismatch: expected {expected!r}, "
                f"got {probe[key]!r}"
            )
    if not isinstance(probe["analysis"], dict) or probe["analysis"].get("input") != "stripped-only":
        raise ValueError("Oxidizer probe must declare stripped-only analysis")
    if not isinstance(probe["tool"], dict):
        raise ValueError("Oxidizer probe tool metadata must be an object")
    for key, evidence in (
        ("matches", DIRECT_FLIRT),
        ("propagated_wrappers", PROPAGATED_WRAPPER),
        ("cleanup_heuristics", CLEANUP_HEURISTIC),
    ):
        values = probe[key]
        if not isinstance(values, list):
            raise ValueError(f"Oxidizer probe {key} must be a list")
        addresses = set()
        for index, item in enumerate(values):
            match = _require_match(item, evidence=evidence, where=f"{key}[{index}]")
            address = _address(match["address"], where=f"{key}[{index}].address")
            if address in addresses:
                raise ValueError(f"duplicate Oxidizer {key} address: {_hex(address)}")
            addresses.add(address)
    return probe


def _normalized_match(item: dict[str, Any]) -> dict[str, str]:
    """Re-normalize labels with CallKin's GT normalization rules."""
    name = str(item["name"])
    address = _address(item["address"], where="Oxidizer match.address")
    mapped = _address(item["mapped_address"], where="Oxidizer match.mapped_address")
    return {
        "address": _hex(address),
        "mapped_address": _hex(mapped),
        "name": name,
        "canonical_origin": normalize_all_rust_origin(name),
        "owner": rust_symbol_owner(name) or "unknown",
        "evidence": str(item["evidence"]),
    }


def build_label_artifact(
    *,
    raw: dict[str, Any],
    probe: dict[str, Any],
    timeout_seconds: int | None = None,
    cache_reused: bool = False,
) -> dict[str, Any]:
    """Join a stripped-only probe to CallKin's symbol-boundary oracle.

    Direct FLIRT matches are the only entries exposed as `matches`. Propagated
    and cleanup results remain separately recorded evidence, and every address
    that cannot join to a CallKin known function is retained under
    `unmatched_addresses` instead of being discarded.
    """
    expected = raw["provenance"]
    validate_probe_output(
        probe,
        expected_case=raw["case"],
        expected_build=raw["build"],
        expected_profile=raw["profile"],
        expected_stripped_sha256=expected["stripped_sha256"],
    )
    known_addresses = {_address(item["address"], where="raw function.address") for item in raw["functions"]}

    joined: dict[str, list[dict[str, str]]] = {
        DIRECT_FLIRT: [],
        PROPAGATED_WRAPPER: [],
        CLEANUP_HEURISTIC: [],
    }
    unmatched: list[dict[str, str]] = []
    for probe_key, evidence in (
        ("matches", DIRECT_FLIRT),
        ("propagated_wrappers", PROPAGATED_WRAPPER),
        ("cleanup_heuristics", CLEANUP_HEURISTIC),
    ):
        for item in probe[probe_key]:
            match = _normalized_match(item)
            address = _address(match["address"], where="Oxidizer match.address")
            if address in known_addresses:
                joined[evidence].append(match)
            else:
                unmatched.append(match)

    for values in joined.values():
        values.sort(key=lambda item: _address(item["address"], where="label.address"))
    unmatched.sort(key=lambda item: (_address(item["address"], where="label.address"), item["evidence"]))

    if timeout_seconds is not None and timeout_seconds <= 0:
        raise ValueError("Oxidizer timeout must be positive")
    tool = dict(probe["tool"])
    tool["callkin_adapter_version"] = ADAPTER_VERSION
    return {
        "schema_version": LABEL_SCHEMA_VERSION,
        "case": raw["case"],
        "build": raw["build"],
        "profile": raw["profile"],
        "provenance": raw["provenance"],
        "stripped_sha256": expected["stripped_sha256"],
        "raw_graph_sha256": raw_graph_sha256(raw),
        "analysis": {
            "input": "stripped-only",
            "address_space": "ELF linked virtual address",
            "boundary_oracle": "CallKin raw graph symbol-boundary oracle",
            "seed_policy": "direct-flirt-only",
        },
        "tool": tool,
        "execution": {
            "timeout_seconds": timeout_seconds,
            "memory_limit_mb": None,
            "cache_reused": cache_reused,
        },
        "matches": joined[DIRECT_FLIRT],
        "propagated_wrappers": joined[PROPAGATED_WRAPPER],
        "cleanup_heuristics": joined[CLEANUP_HEURISTIC],
        "unmatched_addresses": unmatched,
    }


def validate_label_artifact(data: object) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("Oxidizer label artifact must be an object")
    required = {
        "schema_version", "case", "build", "profile", "provenance",
        "stripped_sha256", "raw_graph_sha256", "analysis", "tool", "matches",
        "execution", "propagated_wrappers", "cleanup_heuristics", "unmatched_addresses",
    }
    if set(data) != required or data["schema_version"] != LABEL_SCHEMA_VERSION:
        raise ValueError("unsupported Oxidizer label artifact schema")
    for key in ("case", "build", "profile", "stripped_sha256", "raw_graph_sha256"):
        _require_string(data[key], where=f"labels.{key}")
    provenance = parse_provenance(data["provenance"], where="labels.provenance")
    if data["stripped_sha256"] != provenance.stripped_sha256:
        raise ValueError("Oxidizer label stripped hash does not match provenance")
    analysis = data["analysis"]
    if not isinstance(analysis, dict) or set(analysis) != {
        "input", "address_space", "boundary_oracle", "seed_policy",
    }:
        raise ValueError("Oxidizer label analysis has an invalid field set")
    if analysis["input"] != "stripped-only" or analysis["seed_policy"] != "direct-flirt-only":
        raise ValueError("Oxidizer label analysis policy is invalid")
    if not isinstance(data["tool"], dict):
        raise ValueError("Oxidizer label tool metadata must be an object")
    execution = data["execution"]
    if not isinstance(execution, dict) or set(execution) != {
        "timeout_seconds", "memory_limit_mb", "cache_reused",
    }:
        raise ValueError("Oxidizer label execution metadata has an invalid field set")
    timeout = execution["timeout_seconds"]
    if timeout is not None and (
        not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0
    ):
        raise ValueError("Oxidizer label timeout must be null or a positive integer")
    memory_limit = execution["memory_limit_mb"]
    if memory_limit is not None and (
        not isinstance(memory_limit, int)
        or isinstance(memory_limit, bool)
        or memory_limit <= 0
    ):
        raise ValueError("Oxidizer memory limit must be null or a positive integer")
    if not isinstance(execution["cache_reused"], bool):
        raise ValueError("Oxidizer cache_reused must be boolean")
    seen = set()
    for key, evidence in (
        ("matches", DIRECT_FLIRT),
        ("propagated_wrappers", PROPAGATED_WRAPPER),
        ("cleanup_heuristics", CLEANUP_HEURISTIC),
        ("unmatched_addresses", None),
    ):
        values = data[key]
        if not isinstance(values, list):
            raise ValueError(f"labels.{key} must be a list")
        for index, item in enumerate(values):
            expected_evidence = evidence or _require_string(
                item.get("evidence") if isinstance(item, dict) else None,
                where=f"labels.{key}[{index}].evidence",
            )
            if expected_evidence not in EVIDENCE_STAGES:
                raise ValueError(f"invalid Oxidizer evidence stage: {expected_evidence!r}")
            match = _require_match(
                item,
                evidence=expected_evidence,
                where=f"labels.{key}[{index}]",
            )
            key_address = (_address(match["address"], where=f"labels.{key}[{index}].address"), expected_evidence)
            if key_address in seen:
                raise ValueError(f"duplicate Oxidizer label evidence: {_hex(key_address[0])}/{expected_evidence}")
            seen.add(key_address)
    return data


def load_label_artifact(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read Oxidizer label artifact {path}: {exc}") from exc
    return validate_label_artifact(data)


def probe_from_label_cache(labels: dict[str, Any]) -> dict[str, Any]:
    """Recover reusable probe evidence from a prior label artifact.

    The label artifact preserves every stage, including unmatched addresses, so
    a changed raw graph can be rejoined without rerunning Oxidizer on the same
    stripped binary.
    """
    validate_label_artifact(labels)
    unmatched_by_stage = {
        stage: [
            match for match in labels["unmatched_addresses"]
            if match["evidence"] == stage
        ]
        for stage in EVIDENCE_STAGES
    }
    return {
        "schema_version": LABEL_SCHEMA_VERSION,
        "case": labels["case"],
        "build": labels["build"],
        "profile": labels["profile"],
        "stripped_sha256": labels["stripped_sha256"],
        "analysis": {"input": "stripped-only", "cfg": "cached-label-evidence"},
        "tool": labels["tool"],
        "matches": [*labels["matches"], *unmatched_by_stage[DIRECT_FLIRT]],
        "propagated_wrappers": [
            *labels["propagated_wrappers"],
            *unmatched_by_stage[PROPAGATED_WRAPPER],
        ],
        "cleanup_heuristics": [
            *labels["cleanup_heuristics"],
            *unmatched_by_stage[CLEANUP_HEURISTIC],
        ],
    }


def write_label_artifact(data: dict[str, Any], path: str | Path) -> None:
    validate_label_artifact(data)
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def run_oxidizer_probe(
    *,
    oxidizer_dir: str | Path,
    binary_path: str | Path,
    case: str,
    build: str,
    profile: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run the probe in Oxidizer's own locked uv environment."""
    oxidizer = Path(oxidizer_dir)
    if not (oxidizer / "pyproject.toml").is_file() or not (oxidizer / "uv.lock").is_file():
        raise ValueError(
            f"Oxidizer checkout is incomplete: {oxidizer}. Expected pyproject.toml and uv.lock."
        )
    if shutil.which("uv") is None:
        raise RuntimeError("uv executable was not found; install uv to run the Oxidizer adapter")
    if timeout_seconds <= 0:
        raise ValueError("Oxidizer timeout must be positive")

    probe_path = Path(__file__).with_name("oxidizer_probe.py").resolve()
    with tempfile.TemporaryDirectory(prefix="callkin-oxidizer-") as temp_dir:
        output_path = Path(temp_dir) / "probe.json"
        command = [
            "uv", "run", "--frozen", "python", str(probe_path),
            "--binary", str(Path(binary_path).resolve()),
            "--output", str(output_path),
            "--case", case,
            "--build", build,
            "--profile", profile,
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=oxidizer,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Oxidizer probe timed out after {timeout_seconds}s"
            ) from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(
                f"Oxidizer probe failed with exit code {completed.returncode}: {detail[-4000:]}"
            )
        if not output_path.is_file():
            raise RuntimeError("Oxidizer probe completed without writing its JSON output")
        try:
            return json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Oxidizer probe wrote invalid JSON: {exc}") from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run direct FLIRT in the separate Oxidizer environment."
    )
    parser.add_argument("stem", help="case stem, for example billing-client")
    parser.add_argument("--build", default=DEFAULT_BUILD)
    parser.add_argument("--profile", choices=BUILD_PROFILES, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", help="override verified build manifest path")
    parser.add_argument("--binary", help="override stripped binary path")
    parser.add_argument("--raw-graph", help="override direct raw graph path")
    parser.add_argument("--output", help="override label JSON output path")
    parser.add_argument(
        "--force",
        action="store_true",
        help="rerun Oxidizer instead of reusing matching cached label evidence",
    )
    parser.add_argument(
        "--oxidizer-dir",
        default=DEFAULT_OXIDIZER_DIR,
        help=f"Oxidizer checkout. Default: {DEFAULT_OXIDIZER_DIR}",
    )
    parser.add_argument("--timeout", type=int, default=900, help="probe timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        case, build = split_case_build(args.stem, args.build)
        manifest_path = args.manifest or build_manifest_for(case, build, args.profile)
        verified = load_and_verify_manifest(
            manifest_path,
            expected_case=case,
            expected_build=build,
            expected_profile=args.profile,
        )
        binary_path = Path(args.binary or verified.stripped_binary)
        if binary_path.resolve() != Path(verified.stripped_binary).resolve():
            raise ValueError("--binary must match the stripped binary recorded in the manifest")
        if sha256_file(binary_path) != verified.provenance.stripped_sha256:
            raise ValueError("stripped binary hash differs from the verified build manifest")
        raw_path = args.raw_graph or raw_graph_for(case, build, args.profile)
        raw = load_raw_graph(raw_path)
        if raw["provenance"] != verified.provenance.to_dict():
            raise ValueError("raw graph build provenance differs from the build manifest")
        if raw["binary"]["stripped_sha256"] != verified.provenance.stripped_sha256:
            raise ValueError("raw graph stripped hash differs from the build manifest")
        output = args.output or oxidizer_labels_for(case, build, args.profile)
        output_path = Path(output)
        cached = None
        if output_path.is_file() and not args.force:
            cached = load_label_artifact(output_path)
            cache_identity = (
                cached["case"] == case
                and cached["build"] == build
                and cached["profile"] == args.profile
                and cached["provenance"] == verified.provenance.to_dict()
            )
            if not cache_identity:
                raise ValueError(
                    "cached Oxidizer labels belong to a different build; "
                    "use --force to replace them"
                )
            probe = probe_from_label_cache(cached)
        else:
            probe = run_oxidizer_probe(
                oxidizer_dir=args.oxidizer_dir,
                binary_path=binary_path,
                case=case,
                build=build,
                profile=args.profile,
                timeout_seconds=args.timeout,
            )
        artifact = build_label_artifact(
            raw=raw,
            probe=probe,
            timeout_seconds=args.timeout,
            cache_reused=cached is not None,
        )
        write_label_artifact(artifact, output)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"direct FLIRT labels: {len(artifact['matches'])}")
    print(f"unmatched FLIRT addresses: {len(artifact['unmatched_addresses'])}")
    if cached is not None:
        print("Oxidizer evidence: reused cached stripped-binary labels")
    print(f"wrote: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
