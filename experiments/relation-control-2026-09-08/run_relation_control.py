"""Run one cached F6 pass for each prepared relation-control arm.

The runner intentionally reads retained F4 predictions only after verifying
that every control artifact and its snapshot hash is present. It never reads
GT or linkage artifacts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from relation_control import (
    BodyFeatureCache,
    actual_cost_ratio,
    cost_summary,
    graph_summary,
    load_bodies,
    run_f6_pair,
)
from prepare_relation_control import (
    DEFAULT_REFERENCE,
    HERE,
    read_json,
    sha256_file,
    write_json_once,
)
from v1_candidates import PairKey
from v1_engine import PairEvidenceCache, PairPolicyConfig


APPROVED_CORE_COMMIT = "7277f7e"


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(HERE.parents[1]), *args],
        text=True,
    ).strip()


def verify_core_identity(approved: str = APPROVED_CORE_COMMIT) -> None:
    repo = HERE.parents[1]
    if subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", approved, "HEAD"],
        check=False,
    ).returncode:
        raise ValueError(f"approved core commit is not an ancestor: {approved}")
    prefix = HERE.relative_to(repo).as_posix().rstrip("/") + "/"
    changed = [
        path
        for path in _git("diff", "--name-only", approved, "--").splitlines()
        if path and not path.startswith(prefix)
    ]
    if changed:
        raise ValueError("core files changed since approved commit: " + ", ".join(changed))


def _resource_metadata() -> dict[str, Any]:
    return {
        "max_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "max_rss_unit": "bytes" if sys.platform == "darwin" else "KiB",
        "resource_limit_kind": "virtual-address-space",
    }


def _timed_call(function, seconds: int):
    def alarm_handler(*_args):
        raise TimeoutError(f"{seconds}-second arm ceiling reached")

    previous = signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(seconds)
    try:
        return function()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def verify_snapshot(output: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    snapshot_path = output / "snapshot.json"
    if not snapshot_path.is_file():
        raise ValueError("controls are not prepared; snapshot.json is missing")
    snapshot = read_json(snapshot_path)
    if snapshot.get("status") != "controls-hashed":
        raise ValueError("snapshot does not prove controls were hashed")
    if snapshot.get("config_sha256") != sha256_file(output / "config.json"):
        raise ValueError("control config hash changed after preparation")
    actual_protocol_sha256 = sha256_file(output / "protocol.md")
    if config.get("protocol_sha256") is None:
        raise ValueError("control protocol hash is not frozen in config")
    if config["protocol_sha256"] != actual_protocol_sha256:
        raise ValueError("control protocol hash differs from config")
    if snapshot.get("protocol_sha256") != actual_protocol_sha256:
        raise ValueError("control protocol hash changed after preparation")
    if snapshot.get("base_commit") != config["base_commit"]:
        raise ValueError("snapshot base commit differs from config")
    implementation = snapshot.get("implementation", {})
    expected_implementation = {
        "relation_control.py",
        "prepare_relation_control.py",
        "run_relation_control.py",
    }
    if set(implementation) != expected_implementation:
        raise ValueError("implementation hash manifest is incomplete")
    for name, record in implementation.items():
        path = output / name
        if not path.is_file() or sha256_file(path) != record.get("sha256"):
            raise ValueError(f"implementation file changed after preparation: {path}")
    selections = snapshot.get("selection_sha256", {})
    for record in (
        snapshot.get("reference", {}).get("reference_config"),
        snapshot.get("reference", {}).get("reference_inputs"),
        snapshot.get("reference", {}).get("reference_protocol"),
    ):
        if not isinstance(record, Mapping) or sha256_file(record["path"]) != record["sha256"]:
            raise ValueError("reference snapshot input changed")
    for case in config["cases"]:
        selection_path = output / "selection" / f"{case}.json"
        if not isinstance(selections, Mapping) or selections.get(case) != sha256_file(selection_path):
            raise ValueError(f"selection hash changed after preparation: {case}")
        case_records = snapshot.get("reference", {}).get("cases", {}).get(case, {})
        for record in case_records.values():
            if sha256_file(record["path"]) != record["sha256"]:
                raise ValueError(f"reference case input changed: {case}")
        if case_records.get("body2_candidates", {}).get("sha256") != config["candidate_sha256"][case]["body2"]:
            raise ValueError(f"body2 candidate pin changed: {case}")
        if case_records.get("combined3_candidates", {}).get("sha256") != config["candidate_sha256"][case]["c3"]:
            raise ValueError(f"C3 candidate pin changed: {case}")
        arms = snapshot.get("controls", {}).get(case, {})
        control_arms = tuple(config["arms"]["controls"])
        if set(arms) != set(control_arms):
            raise ValueError(f"control arm set is incomplete: {case}")
        for arm, expected_sha in arms.items():
            path = output / "candidates" / case / f"{arm}.candidates.json"
            if sha256_file(path) != expected_sha:
                raise ValueError(f"control artifact hash changed: {path}")
    return snapshot


def candidate_demand(
    candidate: Mapping[str, Any],
    bodies: Mapping[str, Any],
    policy: PairPolicyConfig,
) -> dict[str, Any]:
    cache = PairEvidenceCache(bodies, candidate["pairs"], policy)
    pairs = [PairKey.make(item["first"], item["second"]) for item in candidate["pairs"]]
    comparisons, cells = cache.demand(pairs)
    return {
        "candidate_pairs": len(pairs),
        "comparisons": comparisons,
        "alignment_cells": cells,
        "fits": cache.within_budget(comparisons, cells),
    }


def _partition_signature(prediction: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "clusters": prediction.get("clusters", []),
        "status_members": prediction.get("status_members", {}),
        "abstain_reasons": prediction.get("abstain_reasons", {}),
        "blocked_merges": prediction.get("blocked_merges", []),
    }


def _read_old_prediction_paths(reference: Path, case: str) -> list[Path]:
    result: list[Path] = []
    for directory in sorted((reference / "runs" / case).iterdir(), key=lambda path: path.name):
        if not directory.is_dir() or not directory.name.startswith(("body2-", "combined3-")):
            continue
        path = directory / "prediction.json"
        metadata_path = directory / "metadata.json"
        if not metadata_path.is_file():
            continue
        metadata = read_json(metadata_path)
        if metadata.get("status") != "completed":
            continue
        if not path.is_file():
            raise ValueError(f"completed old prediction is missing: {path}")
        expected = metadata.get("prediction_sha256")
        if not expected or sha256_file(path) != expected:
            raise ValueError(f"old prediction hash mismatch: {path}")
        result.append(path)
    return result


def _write_cache_source_manifest(
    output: Path,
    reference: Path,
    case: str,
    paths: list[Path],
) -> dict[str, Any]:
    sources = []
    for prediction_path in paths:
        metadata_path = prediction_path.with_name("metadata.json")
        sources.append(
            {
                "prediction_path": str(prediction_path),
                "prediction_sha256": sha256_file(prediction_path),
                "metadata_path": str(metadata_path),
                "metadata_sha256": sha256_file(metadata_path),
            }
        )
    manifest = {
        "case": case,
        "reference_study": str(reference),
        "status": "validated-before-f4-cache-open",
        "sources": sources,
    }
    write_json_once(output / "physical-cache" / case / "source-manifest.json", manifest)
    return manifest


def _feature_identity(
    snapshot: Mapping[str, Any],
    case: str,
    reference: Path,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    reference_config = read_json(reference / "config.json")
    body = snapshot["reference"]["cases"][case]["body"]
    return {
        "body_evidence_sha256": body["sha256"],
        "config_sha256": sha256_file(reference / "config.json"),
        "python": platform.python_version(),
        "base_commit": reference_config["base_commit"],
        "protocol_sha256": sha256_file(reference / "protocol.md"),
    }


def _run_arm_impl(
    *,
    output: Path,
    reference: Path,
    snapshot: Mapping[str, Any],
    config: Mapping[str, Any],
    case: str,
    arm: str,
    candidate_path: Path,
    bodies: Mapping[str, Any],
    body_artifact: Mapping[str, Any],
    policy: PairPolicyConfig,
    feature_cache: BodyFeatureCache,
    treatment_result: Mapping[str, Any] | None,
    reference_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    candidate = read_json(candidate_path)
    candidate_sha = sha256_file(candidate_path)
    demand = candidate_demand(candidate, bodies, policy)
    metadata: dict[str, Any] = {
        "case": case,
        "arm": arm,
        "candidate_sha256": candidate_sha,
        "body_evidence_sha256": sha256_file(
            snapshot["reference"]["cases"][case]["body"]["path"]
        ),
        "protocol_sha256": sha256_file(output / "protocol.md"),
        "config_sha256": sha256_file(output / "config.json"),
        "base_commit": config["base_commit"],
        "python": platform.python_version(),
        "code_commit": _git("rev-parse", "HEAD"),
        "implementation_sha256": {
            name: record["sha256"]
            for name, record in snapshot.get("implementation", {}).items()
        },
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "demand": demand,
        "candidate_pair_count": demand["candidate_pairs"],
        "eligible_pair_count": demand["comparisons"],
        "ineligible_pair_count": demand["candidate_pairs"] - demand["comparisons"],
    }
    destination = output / "runs" / case / arm
    if not demand["fits"]:
        metadata["status"] = "budget-refused"
        metadata["resource"] = _resource_metadata()
        write_json_once(destination / "metadata.json", metadata)
        return metadata

    hit_before = feature_cache.hits
    miss_before = feature_cache.misses
    physical_comparisons_before = feature_cache.physical_comparisons
    physical_cells_before = feature_cache.physical_alignment_cells
    started = time.perf_counter()
    try:
        prediction, actual_cost = _timed_call(
            lambda: run_f6_pair(
                candidate,
                bodies,
                policy,
                feature_cache=feature_cache,
                body_sha256=metadata["body_evidence_sha256"],
                body_provenance=body_artifact["provenance"],
                candidate_sha256=candidate_sha,
            ),
            int(
                config.get("runtime", {}).get(
                    "wall_time_limit_seconds_per_arm",
                    config.get("runtime", {}).get("wall_time_limit_seconds", 1800),
                )
            ),
        )
    except (MemoryError, TimeoutError) as exc:
        metadata.update(
            {
                "status": "resource-incomplete",
                "error": repr(exc),
                "resource": _resource_metadata(),
                "wall_seconds": time.perf_counter() - started,
            }
        )
        write_json_once(destination / "metadata.json", metadata)
        return metadata
    inference_seconds = time.perf_counter() - started
    write_json_once(destination / "prediction.json", prediction)
    prediction_sha256 = sha256_file(destination / "prediction.json")
    metadata.update(
        {
            "status": "completed",
            "prediction_sha256": prediction_sha256,
            "inference_seconds": inference_seconds,
            "timing_scope": "cached physical work; not a latency comparison",
            "logical_cost": actual_cost,
            **{
                key: actual_cost[key]
                for key in (
                    "candidate_comparisons",
                    "candidate_alignment_cells",
                    "on_demand_comparisons",
                    "on_demand_alignment_cells",
                    "total_comparisons",
                    "total_alignment_cells",
                )
            },
            "physical_cache": {
                "hits_delta": feature_cache.hits - hit_before,
                "misses_delta": feature_cache.misses - miss_before,
                "cache_hit_count": feature_cache.hits - hit_before,
                "physical_cache_comparisons": (
                    feature_cache.physical_comparisons - physical_comparisons_before
                ),
                "physical_cache_alignment_cells": (
                    feature_cache.physical_alignment_cells - physical_cells_before
                ),
                "entries": len(feature_cache.features),
            },
            "graph": graph_summary(candidate["pairs"], candidate["universe"]["target_ids"]),
            "resource": _resource_metadata(),
        }
    )
    if treatment_result is not None:
        metadata["actual_cost_ratio_to_treatment"] = actual_cost_ratio(
            prediction, treatment_result
        )
    if reference_result is not None:
        metadata["reference_partition_match"] = (
            _partition_signature(prediction) == _partition_signature(reference_result)
        )
        metadata["reference_cost_match"] = prediction["metrics"] == reference_result.get("metrics")
        if not metadata["reference_partition_match"] or not metadata["reference_cost_match"]:
            raise ValueError(f"retained C3 replay mismatch for {case}: {metadata}")
    metadata["wall_seconds"] = time.perf_counter() - started
    write_json_once(destination / "metadata.json", metadata)
    return metadata


def _retained_arm_metadata(destination: Path) -> dict[str, Any] | None:
    metadata_path = destination / "metadata.json"
    if not metadata_path.exists():
        if destination.exists() and any(destination.iterdir()):
            raise ValueError(f"partial retained arm exists at {destination}")
        return None
    metadata = read_json(metadata_path)
    status = metadata.get("status")
    if status == "completed":
        prediction_path = destination / "prediction.json"
        expected = metadata.get("prediction_sha256")
        if not expected or not prediction_path.is_file() or sha256_file(prediction_path) != expected:
            raise ValueError(f"retained arm prediction hash is invalid: {destination}")
        return metadata
    if status == "budget-refused":
        return metadata
    raise ValueError(f"retained arm is incomplete or failed: {destination}")


def _validate_retained_identity(metadata: Mapping[str, Any], kwargs: Mapping[str, Any]) -> None:
    output = kwargs["output"]
    snapshot = kwargs["snapshot"]
    config = kwargs["config"]
    case = kwargs["case"]
    candidate_path = kwargs["candidate_path"]
    expected = {
        "case": case,
        "arm": kwargs["arm"],
        "candidate_sha256": sha256_file(candidate_path),
        "body_evidence_sha256": snapshot["reference"]["cases"][case]["body"]["sha256"],
        "protocol_sha256": sha256_file(output / "protocol.md"),
        "config_sha256": sha256_file(output / "config.json"),
        "base_commit": config["base_commit"],
        "python": platform.python_version(),
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"retained arm {key} identity mismatch")
    implementation = {
        name: record["sha256"]
        for name, record in snapshot.get("implementation", {}).items()
    }
    if metadata.get("implementation_sha256") != implementation:
        raise ValueError("retained arm implementation identity mismatch")


def run_arm(**kwargs: Any) -> dict[str, Any]:
    """Run one arm once, preserving retained or failed state on resume."""

    destination = kwargs["output"] / "runs" / kwargs["case"] / kwargs["arm"]
    retained = _retained_arm_metadata(destination)
    if retained is not None:
        _validate_retained_identity(retained, kwargs)
        return retained
    try:
        return _run_arm_impl(**kwargs)
    except Exception as exc:
        metadata_path = destination / "metadata.json"
        if not metadata_path.exists():
            metadata = {
                "case": kwargs["case"],
                "arm": kwargs["arm"],
                "status": "error",
                "error": repr(exc),
                "python": platform.python_version(),
                "code_commit": _git("rev-parse", "HEAD"),
                "resource": _resource_metadata(),
            }
            write_json_once(metadata_path, metadata)
        raise


def run_case(
    *,
    output: Path,
    reference: Path,
    snapshot: Mapping[str, Any],
    config: Mapping[str, Any],
    case: str,
) -> dict[str, Any]:
    reference_inputs = read_json(reference / "inputs.json")
    body_path = Path(reference_inputs["input_root"]) / reference_inputs["cases"][case]["body"]["path"]
    body_artifact = read_json(body_path)
    bodies = load_bodies(body_artifact)
    policy = PairPolicyConfig.from_dict(config["policy"])
    expected_identity = _feature_identity(snapshot, case, reference, config)
    old_predictions = _read_old_prediction_paths(reference, case)
    _write_cache_source_manifest(output, reference, case, old_predictions)
    feature_cache = BodyFeatureCache.from_old_predictions(
        bodies,
        old_predictions,
        expected_identity=expected_identity,
        expected_policy=policy,
    )
    reference_treatment_path = reference / "runs" / case / "combined3-k16" / "prediction.json"
    reference_treatment = read_json(reference_treatment_path)
    treatment_path = reference / "cache" / case / "combined3-k16.candidates.json"
    treatment_meta = run_arm(
        output=output,
        reference=reference,
        snapshot=snapshot,
        config=config,
        case=case,
        arm="C3-k16",
        candidate_path=treatment_path,
        bodies=bodies,
        body_artifact=body_artifact,
        policy=policy,
        feature_cache=feature_cache,
        treatment_result=None,
        reference_result=reference_treatment,
    )
    treatment_prediction_path = output / "runs" / case / "C3-k16" / "prediction.json"
    treatment_prediction = (
        read_json(treatment_prediction_path)
        if treatment_meta["status"] == "completed"
        else None
    )
    summaries = {"C3-k16": treatment_meta}
    for arm in config["arms"]["controls"]:
        candidate_path = output / "candidates" / case / f"{arm}.candidates.json"
        summaries[arm] = run_arm(
            output=output,
            reference=reference,
            snapshot=snapshot,
            config=config,
            case=case,
            arm=arm,
            candidate_path=candidate_path,
            bodies=bodies,
            body_artifact=body_artifact,
            policy=policy,
            feature_cache=feature_cache,
            treatment_result=treatment_prediction,
        )
    return summaries


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument("--output", type=Path, default=HERE)
    parser.add_argument("--case", choices=("zoxide", "fd", "ripgrep-main"))
    args = parser.parse_args()
    config = read_json(args.output / "config.json")
    verify_core_identity(config.get("base_commit", APPROVED_CORE_COMMIT))
    snapshot = verify_snapshot(args.output, config)
    expected_python = config.get("runtime", {}).get("python")
    if expected_python and platform.python_version() != expected_python:
        raise ValueError(
            f"runtime Python {platform.python_version()} differs from frozen {expected_python}"
        )
    address_space = int(config.get("runtime", {}).get("address_space_limit_bytes", 12 * 1024**3))
    resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    cases = [args.case] if args.case else list(config["cases"])
    summaries = {
        case: run_case(
            output=args.output,
            reference=args.reference,
            snapshot=snapshot,
            config=config,
            case=case,
        )
        for case in cases
    }
    summary_path = args.output / "run-summaries" / (
        f"{args.case}.json" if args.case else "all.json"
    )
    write_json_once(summary_path, summaries)
    print(json.dumps({"status": "completed", "cases": cases}, indent=2))


if __name__ == "__main__":
    main()
