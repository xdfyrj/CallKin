"""Create the pinned, source-boundary observation for a novel Rust case.

This command deliberately stops before candidate generation, F6, and scoring.
The GT and linkage files are retained for the later evaluator, while only
body/fixture/raw-graph artifacts are exposed to the inference command.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import platform
import resource
import signal
import shutil
import sys
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

from novel_common import (
    HERE,
    REPO_ROOT,
    case_config,
    case_identity,
    case_paths,
    config_cases,
    core_base_commit,
    ensure_no_partial_outputs,
    frozen_implementation_hashes,
    implementation_hashes,
    read_json,
    runtime_config,
    sha256_file,
    source_record,
    verify_output_hashes,
    write_json_once,
)


def _config_path() -> Path:
    return HERE / "config.json"


def _protocol_path() -> Path:
    return HERE / "protocol.md"


def _load_frozen_config() -> dict[str, Any]:
    config_path = _config_path()
    protocol_path = _protocol_path()
    config = read_json(config_path)
    if not isinstance(config, dict):
        raise ValueError("config root must be an object")
    expected = config.get("protocol_sha256")
    actual = sha256_file(protocol_path)
    if not isinstance(expected, str) or expected != actual:
        raise ValueError(
            "protocol hash is not frozen in config; refusing observation"
        )
    status = str(config.get("status", ""))
    if status.upper() not in {"FROZEN", "FROZEN-DESIGN", "APPROVED"}:
        raise ValueError(f"config status is not frozen: {status!r}")
    return config


def _verify_core(config: Mapping[str, Any]) -> None:
    """Check the frozen base without importing any prior runner verifier."""

    base = core_base_commit(config)
    if subprocess.run(
        ["git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor", base, "HEAD"],
        check=False,
    ).returncode:
        raise ValueError(f"frozen base commit is not an ancestor: {base}")
    study_prefix = HERE.relative_to(REPO_ROOT).as_posix().rstrip("/") + "/"
    changed = [
        path
        for path in subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "diff", "--name-only", base, "--"],
            text=True,
        ).splitlines()
        if path and not path.startswith(study_prefix)
    ]
    if changed:
        raise ValueError(
            "tracked core files differ from frozen base commit: "
            + ", ".join(changed)
        )


def _manifest_path(config: Mapping[str, Any], case: str, paths: Mapping[str, Path]) -> Path:
    case_spec = case_config(config, case)
    value = case_spec.get("build_manifest")
    if value is None:
        value = config.get("build_manifest")
    if value is None:
        return paths["build_manifest"]
    path = Path(str(value))
    return path if path.is_absolute() else (HERE / path).resolve()


def _resource_limits(config: Mapping[str, Any]) -> tuple[int, int]:
    extraction = runtime_config(config, "extraction")
    address_space = int(extraction.get("address_space_limit_bytes", 12 * 1024**3))
    wall_seconds = int(extraction.get("wall_time_seconds", 3600))
    if address_space <= 0 or wall_seconds <= 0:
        raise ValueError("observation resource limits must be positive")
    return address_space, wall_seconds


def _verify_runtime(config: Mapping[str, Any]) -> dict[str, str]:
    expected = runtime_config(config, "extraction")
    expected_python = expected.get("python")
    if not isinstance(expected_python, str) or platform.python_version() != expected_python:
        raise ValueError(
            f"observation requires Python {expected_python!r}; "
            f"running {platform.python_version()!r}"
        )
    versions = {
        "angr": expected.get("angr"),
        "r2pipe": expected.get("r2pipe"),
        "capstone": expected.get("capstone"),
        "pycparser": expected.get("pycparser"),
        "pyelftools": expected.get("pyelftools"),
    }
    actual: dict[str, str] = {}
    for package, wanted in versions.items():
        if not isinstance(wanted, str):
            raise ValueError(f"runtime extraction version is missing: {package}")
        try:
            found = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError as exc:
            raise ValueError(f"required extraction package is missing: {package}") from exc
        if found != wanted:
            raise ValueError(f"{package} version mismatch: {found!r} != {wanted!r}")
        actual[package] = found
    wanted_r2 = expected.get("radare2")
    if not isinstance(wanted_r2, str):
        raise ValueError("runtime extraction version is missing: radare2")
    executable = shutil.which("radare2")
    if executable is None:
        raise ValueError("radare2 executable is not available")
    output = subprocess.check_output([executable, "-v"], text=True, stderr=subprocess.STDOUT)
    found_r2 = next(
        (token for token in output.split() if token.count(".") == 2 and token[0].isdigit()),
        None,
    )
    if found_r2 != wanted_r2:
        raise ValueError(f"radare2 version mismatch: {found_r2!r} != {wanted_r2!r}")
    actual["radare2"] = found_r2
    actual["python"] = platform.python_version()
    return actual


def _verify_build_pins(
    config: Mapping[str, Any],
    case: str,
    manifest_path: Path,
    verified: Any,
) -> dict[str, Any]:
    source = case_config(config, case)
    prebuilt = source.get("prebuilt")
    if not isinstance(prebuilt, Mapping):
        raise ValueError(f"{case} has no frozen prebuilt hash record")
    expected = {
        "manifest": prebuilt.get("manifest_sha256"),
        "non_stripped": prebuilt.get("non_stripped_sha256"),
        "fixture": prebuilt.get("fixture_sha256"),
        "source": source.get("cargo_inputs_sha256"),
    }
    for name, digest in expected.items():
        if not isinstance(digest, str):
            raise ValueError(f"{case} frozen hash is missing: {name}")
    actual = {
        "manifest": sha256_file(manifest_path),
        "non_stripped": sha256_file(verified.non_stripped_binary),
        "fixture": sha256_file(verified.stripped_binary),
        "source": verified.provenance.source_sha256,
    }
    for name, digest in expected.items():
        if actual[name] != digest:
            raise ValueError(
                f"{case} pinned {name} hash mismatch: {actual[name]} != {digest}"
            )
    source_path = source.get("source")
    if not isinstance(source_path, str) or not source_path:
        raise ValueError(f"{case} source path is missing from config")
    input_root = config.get("main_input_root")
    if not isinstance(input_root, str) or not input_root:
        raise ValueError("config.main_input_root is required for source pin verification")
    expected_source = Path(source_path)
    if not expected_source.is_absolute():
        expected_source = (Path(input_root) / expected_source).resolve()
    if Path(verified.source).resolve() != expected_source:
        raise ValueError(
            f"{case} source path mismatch: {verified.source!r} != {str(expected_source)!r}"
        )
    namespaces = source.get("namespaces")
    if not isinstance(namespaces, list) or tuple(namespaces) != verified.candidate_namespaces:
        raise ValueError(f"{case} candidate namespaces differ from frozen source config")
    return {"expected": expected, "actual": actual}


def _set_address_space(limit: int) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def _timed(function: Any, seconds: int) -> Any:
    def alarm_handler(*_args: Any) -> None:
        raise TimeoutError(f"{seconds}-second extraction ceiling reached")

    previous = signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(seconds)
    try:
        return function()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _output_paths(paths: Mapping[str, Path]) -> dict[str, Path]:
    return {
        key: paths[key]
        for key in (
            "ground_truth",
            "users",
            "boundaries",
            "fixture",
            "raw_graph",
            "body",
            "linkage",
        )
    }


def _retained_metadata(
    metadata_path: Path,
    *,
    identity: Mapping[str, Any],
    outputs: Mapping[str, Path],
) -> dict[str, Any] | None:
    if not metadata_path.exists():
        ensure_no_partial_outputs(outputs, metadata_path)
        return None
    metadata = read_json(metadata_path)
    if not isinstance(metadata, Mapping):
        raise ValueError(f"observation metadata is invalid: {metadata_path}")
    if metadata.get("status") != "completed":
        raise ValueError(
            f"retained observation is {metadata.get('status')!r}; "
            "refusing to replace it"
        )
    for key, value in identity.items():
        if metadata.get(key) != value:
            raise ValueError(f"retained observation {key} identity mismatch")
    records = metadata.get("outputs")
    if not isinstance(records, Mapping) or set(records) != set(outputs):
        raise ValueError("retained observation output manifest is incomplete")
    verify_output_hashes(records)
    return dict(metadata)


def _write_failure(metadata_path: Path, identity: Mapping[str, Any], exc: BaseException) -> None:
    status = "resource-incomplete" if isinstance(exc, (MemoryError, TimeoutError)) else "error"
    write_json_once(
        metadata_path,
        {
            **dict(identity),
            "status": status,
            "error": repr(exc),
            "resource": _resource_metadata(),
        },
    )


def _resource_metadata() -> dict[str, Any]:
    return {
        "max_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "max_rss_unit": "bytes" if sys.platform == "darwin" else "KiB",
        "resource_limit_kind": "virtual-address-space",
    }


def _observe_case(config: Mapping[str, Any], case: str) -> dict[str, Any]:
    identity = case_identity(config, case)
    paths = case_paths(config, case)
    outputs = _output_paths(paths)
    metadata_path = paths["observation_metadata"]
    runtime_versions = _verify_runtime(config)
    expected_implementation = dict(frozen_implementation_hashes(config))
    actual_implementation = implementation_hashes()
    if expected_implementation != actual_implementation:
        raise ValueError(
            "frozen implementation hashes do not match: "
            f"expected {expected_implementation}, got {actual_implementation}"
        )
    manifest_path = _manifest_path(config, case, paths)
    build = identity["build"]
    profile = identity["profile"]
    track = identity["track"]
    anchor_policy = identity["anchor_policy"]
    scope = identity["candidate_scope"]
    mode = identity["mode"]
    if mode != "out-in":
        raise ValueError(f"prospective observation requires out-in mode: {mode!r}")
    # Manifest paths are interpreted relative to the CallKin repository root;
    # verify it and all recorded binaries before considering retained output.
    previous_cwd = Path.cwd()
    os.chdir(REPO_ROOT)
    try:
        from build_manifest import BUILD_TARGET, load_and_verify_manifest

        verified = load_and_verify_manifest(
            manifest_path,
            expected_case=case,
            expected_build=build,
            expected_profile=profile,
            expected_target=BUILD_TARGET,
        )
    finally:
        os.chdir(previous_cwd)
    build_pins = _verify_build_pins(config, case, manifest_path, verified)
    config_sha = sha256_file(_config_path())
    protocol_sha = sha256_file(_protocol_path())
    impl_sha = actual_implementation
    frozen_identity = {
        **identity,
        "config_sha256": config_sha,
        "protocol_sha256": protocol_sha,
        "base_commit": core_base_commit(config),
        "implementation_sha256": impl_sha,
    }
    retained = _retained_metadata(
        metadata_path,
        identity=frozen_identity,
        outputs=outputs,
    )
    if retained is not None:
        if retained.get("manifest") != source_record(manifest_path):
            raise ValueError("retained observation manifest identity mismatch")
        if retained.get("build_pins") != build_pins:
            raise ValueError("retained observation build identity mismatch")
        print(f"{case}: observation already retained", flush=True)
        return retained

    runtime_limit, wall_limit = _resource_limits(config)
    metadata = {
        **frozen_identity,
        "status": "running",
        "manifest": source_record(manifest_path),
        "build_pins": build_pins,
        "runtime_versions": runtime_versions,
        "provenance": verified.provenance.to_dict(),
        "boundary_oracle": {
            "kind": "non-stripped-rust-symbol-extents",
            "binary": source_record(verified.non_stripped_binary),
            "used_for": ["users", "fixture/raw-graph", "body-extents"],
            "origin_labels_in_prediction_inputs": False,
        },
        "resource_limits": {
            "address_space_limit_bytes": runtime_limit,
            "wall_time_limit_seconds": wall_limit,
        },
    }
    # Do not retain a mutable running marker.  It would make a terminated
    # process look resumable; failed runs get an immutable status below.
    started = time.perf_counter()
    _set_address_space(runtime_limit)
    try:
        def produce() -> tuple[dict[str, Any], Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
            previous_cwd = Path.cwd()
            os.chdir(REPO_ROOT)
            try:
                # Lazy imports keep this command usable only in the Sage
                # extraction environment and keep inference on Python 3.12.
                from run_case import extract_fixture, extract_ground_truth
                from gt_extractor import validate_against_fixture

                gt = extract_ground_truth(
                    binary_path=verified.non_stripped_binary,
                    output_path=str(outputs["ground_truth"]),
                    users_path=str(outputs["users"]),
                    case_name=case,
                    build=build,
                    profile=profile,
                    namespaces=tuple(verified.candidate_namespaces),
                    candidate_scope=scope,
                    root_namespace=verified.root_namespace,
                    boundaries_path=str(outputs["boundaries"]),
                    provenance=verified.provenance,
                )
                artifacts = extract_fixture(
                    binary_path=verified.stripped_binary,
                    output_path=str(outputs["fixture"]),
                    case_name=case,
                    build=build,
                    profile=profile,
                    track=track,
                    anchor_policy=anchor_policy,
                    raw_graph_path=str(outputs["raw_graph"]),
                    boundaries_path=str(outputs["boundaries"]),
                    root=None,
                    users_path=str(outputs["users"]),
                    provenance=verified.provenance,
                )
                validate_against_fixture(gt, str(outputs["fixture"]))

                from body_extractor import extract_body_evidence
                from body_evidence import write_body_evidence

                body = extract_body_evidence(
                    binary_path=verified.stripped_binary,
                    selection_path=str(outputs["users"]),
                    raw_graph_path=str(outputs["raw_graph"]),
                    expected_case=case,
                    expected_build=build,
                    expected_profile=profile,
                )
                write_body_evidence(body, str(outputs["body"]))

                from analysis.gt_mangled_audit import build_audit, read_raw_function_symbols

                audit = build_audit(
                    gt,
                    read_raw_function_symbols(verified.non_stripped_binary),
                    ground_truth_sha256=sha256_file(outputs["ground_truth"]),
                    binary_sha256=sha256_file(verified.non_stripped_binary),
                )
                write_json_once(outputs["linkage"], audit)
                return gt, artifacts, body, audit, verified.provenance.to_dict()
            finally:
                os.chdir(previous_cwd)

        gt, artifacts, body, audit, _provenance = _timed(produce, wall_limit)
    except BaseException as exc:
        _write_failure(metadata_path, frozen_identity, exc)
        raise

    metadata.update(
        {
            "status": "completed",
            "elapsed_seconds": time.perf_counter() - started,
            "counts": {
                "ground_truth_origins": len(gt["origins"]),
                "fixture_nodes": len(artifacts.fixture["nodes"]),
                "raw_graph_functions": len(artifacts.raw_graph["functions"]),
                "raw_graph_transfers": len(artifacts.raw_graph["transfers"]),
                "body_functions": len(body["functions"]),
                "linkage_multimember_origins": audit["summary"]["multimember_origin_count"],
            },
            "execution": artifacts.execution,
            "outputs": {
                name: source_record(path) for name, path in outputs.items()
            },
            "resource": _resource_metadata(),
        }
    )
    write_json_once(metadata_path, metadata)
    print(
        f"{case}: observed gt_origins={len(gt['origins'])} "
        f"fixture_nodes={len(artifacts.fixture['nodes'])} "
        f"body_functions={len(body['functions'])}",
        flush=True,
    )
    return metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=None)
    args = parser.parse_args(argv)
    try:
        config = _load_frozen_config()
        _verify_core(config)
        cases = config_cases(config)
        if args.case is not None:
            if args.case not in cases:
                raise ValueError(f"case is outside frozen config: {args.case}")
            cases = (args.case,)
        # Root controls concurrency by launching at most two case processes.
        for case in cases:
            _observe_case(config, case)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
