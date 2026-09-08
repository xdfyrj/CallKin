"""Generate and run the six frozen prediction arms for a novel case.

Only body, fixture, raw-graph and candidate artifacts are read here.  GT and
linkage files are intentionally left to the separate scoring command.
"""

from __future__ import annotations

import argparse
import platform
import resource
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from novel_common import (
    HERE,
    REPO_ROOT,
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


ARM_V0 = "V0-relation"
ARM_EXACT = "exact-token-hash"
ARM_B2 = "B2-token-cfg"
ARM_C3 = "C3-token-cfg-relation"
ARM_BODY_SCORE = "B2-body-score"
ARM_RESCUE = "C3-rescue"
ARMS = (ARM_V0, ARM_EXACT, ARM_B2, ARM_C3, ARM_BODY_SCORE, ARM_RESCUE)
BODY_SCORE_SEED = "novel-source-2026-09-08/B2-body-score"


def _protocol_path() -> Path:
    return HERE / "protocol.md"


def _config_path() -> Path:
    return HERE / "config.json"


def _load_frozen_config() -> dict[str, Any]:
    config = read_json(_config_path())
    if not isinstance(config, dict):
        raise ValueError("config root must be an object")
    expected = config.get("protocol_sha256")
    actual = sha256_file(_protocol_path())
    if not isinstance(expected, str) or expected != actual:
        raise ValueError("protocol hash is not frozen in config; refusing inference")
    status = str(config.get("status", ""))
    if status.upper() not in {"FROZEN", "FROZEN-DESIGN", "APPROVED"}:
        raise ValueError(f"config status is not frozen: {status!r}")
    return config


def _verify_core(config: Mapping[str, Any]) -> None:
    base = core_base_commit(config)
    if subprocess.run(
        ["git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor", base, "HEAD"],
        check=False,
    ).returncode:
        raise ValueError(f"frozen core commit is not an ancestor: {base}")
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


def _verify_runtime(config: Mapping[str, Any]) -> str:
    expected = runtime_config(config, "inference")
    wanted = expected.get("python")
    actual = platform.python_version()
    if not isinstance(wanted, str) or actual != wanted:
        raise ValueError(f"inference requires Python {wanted!r}; running {actual!r}")
    return actual


def _resource_limits(config: Mapping[str, Any]) -> tuple[int, int, int]:
    runtime = runtime_config(config, "inference")
    address_space = int(runtime.get("address_space_limit_bytes", 12 * 1024**3))
    wall_seconds = int(runtime.get("wall_time_seconds_per_arm", 1800))
    retrieval = config.get("retrieval")
    if not isinstance(retrieval, Mapping):
        raise ValueError("config.retrieval must be an object")
    retrieval_seconds = int(retrieval["wall_time_seconds_per_case"])
    retrieval_address_space = int(retrieval["address_space_limit_bytes"])
    if retrieval_address_space != address_space:
        raise ValueError("retrieval and inference address-space limits differ")
    if address_space <= 0 or wall_seconds <= 0 or retrieval_seconds <= 0:
        raise ValueError("inference resource limits must be positive")
    return address_space, wall_seconds, retrieval_seconds


def _timed(function: Any, seconds: int) -> Any:
    def alarm_handler(*_args: Any) -> None:
        raise TimeoutError(f"{seconds}-second inference arm ceiling reached")

    previous = signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(seconds)
    try:
        return function()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _resource_metadata() -> dict[str, Any]:
    return {
        "max_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "max_rss_unit": "bytes" if sys.platform == "darwin" else "KiB",
        "resource_limit_kind": "virtual-address-space",
    }


def _import_prior_helpers(config: Mapping[str, Any]) -> dict[str, Any]:
    expected = dict(frozen_implementation_hashes(config))
    actual = implementation_hashes()
    if expected != actual:
        raise ValueError(
            "frozen implementation hashes do not match: "
            f"expected {expected}, got {actual}"
        )
    old_followup = REPO_ROOT / "experiments" / "followup-2026-09-08"
    old_controls = REPO_ROOT / "experiments" / "relation-control-2026-09-08"
    for path in (REPO_ROOT, old_followup, old_controls):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    # Importing the old module does not invoke its verifier; only this pure
    # projection helper is used.
    from run_followup import derive
    from analysis.v1_family_rescue import build_rescue_artifact
    from body_similarity import load_body_evidence
    from family_rescue import RescueBudget, rescued_clusters
    from relation_control import BodyFeatureCache, make_control_artifact, select_control_pairs
    from v1_candidates import PairKey, build_multiview_candidate_artifact_from_files, validate_candidate_artifact
    from v1_engine import PairEvidenceCache, PairPolicyConfig
    from v1_retrieval_views import build_token_profiles

    return {
        "derive": derive,
        "build_rescue_artifact": build_rescue_artifact,
        "load_body_evidence": load_body_evidence,
        "RescueBudget": RescueBudget,
        "rescued_clusters": rescued_clusters,
        "BodyFeatureCache": BodyFeatureCache,
        "make_control_artifact": make_control_artifact,
        "select_control_pairs": select_control_pairs,
        "PairKey": PairKey,
        "build_multiview_candidate_artifact_from_files": build_multiview_candidate_artifact_from_files,
        "validate_candidate_artifact": validate_candidate_artifact,
        "PairEvidenceCache": PairEvidenceCache,
        "PairPolicyConfig": PairPolicyConfig,
        "build_token_profiles": build_token_profiles,
    }


def _observation_inputs(config: Mapping[str, Any], case: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    paths = case_paths(config, case)
    metadata_path = paths["observation_metadata"]
    metadata = read_json(metadata_path)
    if not isinstance(metadata, Mapping) or metadata.get("status") != "completed":
        raise ValueError(f"completed observation is required: {metadata_path}")
    expected = {
        "case": case,
        **case_identity(config, case),
        "config_sha256": sha256_file(_config_path()),
        "protocol_sha256": sha256_file(_protocol_path()),
        "base_commit": core_base_commit(config),
        "implementation_sha256": dict(frozen_implementation_hashes(config)),
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"observation {case} {key} identity mismatch")
    records = metadata.get("outputs")
    if not isinstance(records, Mapping):
        raise ValueError(f"observation output manifest is missing: {metadata_path}")
    # Do not open GT, linkage, or users here.  Their hashes remain for the
    # evaluator; inference validates only the artifacts it consumes.
    consumed = {name: records[name] for name in ("body", "fixture", "raw_graph")}
    verify_output_hashes(consumed)
    body_artifact = read_json(paths["body"])
    fixture_artifact = read_json(paths["fixture"])
    raw_graph = read_json(paths["raw_graph"])
    return dict(metadata), body_artifact, {"fixture": fixture_artifact, "raw_graph": raw_graph}


def _f6_policy(config: Mapping[str, Any], helpers: Mapping[str, Any]) -> Any:
    f6 = config.get("f6")
    if not isinstance(f6, Mapping):
        raise ValueError("config.f6 must be an object")
    policy = f6.get("policy")
    budget = f6.get("budget")
    if not isinstance(policy, Mapping) or not isinstance(budget, Mapping):
        raise ValueError("config.f6.policy and config.f6.budget are required")
    values = dict(policy)
    values.update(
        max_comparison_count=int(budget["max_comparison_count"]),
        max_alignment_cell_budget=int(budget["max_alignment_cell_budget"]),
    )
    return helpers["PairPolicyConfig"].from_dict(values)


def _candidate_demand(candidate: Mapping[str, Any], bodies: Mapping[str, Any], policy: Any, helpers: Mapping[str, Any]) -> dict[str, Any]:
    cache = helpers["PairEvidenceCache"](bodies, candidate["pairs"], policy)
    pairs = [helpers["PairKey"].make(item["first"], item["second"]) for item in candidate["pairs"]]
    comparisons, cells = cache.demand(pairs)
    return {
        "candidate_pairs": len(pairs),
        "comparisons": comparisons,
        "alignment_cells": cells,
        "fits": cache.within_budget(comparisons, cells),
    }


def _candidate_paths(paths: Mapping[str, Path]) -> dict[str, Path]:
    return {
        "multi": paths["multi_candidates"],
        "body2": paths["body2_candidates"],
        "c3": paths["c3_candidates"],
        "rescue": paths["rescue_candidates"],
        "body_score": paths["body_score_candidates"],
    }


def _candidate_metadata(
    config: Mapping[str, Any],
    case: str,
    paths: Mapping[str, Path],
    outputs: Mapping[str, Path],
    identity: Mapping[str, Any],
) -> dict[str, Any] | None:
    metadata_path = paths["candidate_metadata"]
    if not metadata_path.exists():
        ensure_no_partial_outputs(outputs, metadata_path)
        return None
    metadata = read_json(metadata_path)
    if not isinstance(metadata, Mapping) or metadata.get("status") != "completed":
        raise ValueError(f"retained candidate preparation is not complete: {metadata_path}")
    expected = {
        "case": case,
        **identity,
        "config_sha256": sha256_file(_config_path()),
        "protocol_sha256": sha256_file(_protocol_path()),
        "base_commit": core_base_commit(config),
        "implementation_sha256": dict(frozen_implementation_hashes(config)),
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"candidate metadata {key} identity mismatch")
    records = metadata.get("outputs")
    if not isinstance(records, Mapping) or set(records) != set(outputs):
        raise ValueError("candidate output manifest is incomplete")
    verify_output_hashes(records)
    return dict(metadata)


def _write_candidate_failure(
    config: Mapping[str, Any],
    case: str,
    paths: Mapping[str, Path],
    exc: BaseException,
    *,
    address_space_limit: int,
    retrieval_wall_limit: int,
) -> None:
    destination = paths["candidate_metadata"]
    if destination.exists():
        return
    candidate_paths = _candidate_paths(paths)
    state = {
        name: (
            source_record(path)
            if path.is_file()
            else {"path": str(path), "status": "missing"}
        )
        for name, path in candidate_paths.items()
    }
    identity = case_identity(config, case)
    write_json_once(
        destination,
        {
            "status": "upstream-failure",
            "failure_kind": (
                "resource-incomplete"
                if isinstance(exc, (MemoryError, TimeoutError))
                else "error"
            ),
            "case": case,
            **identity,
            "config_sha256": sha256_file(_config_path()),
            "protocol_sha256": sha256_file(_protocol_path()),
            "base_commit": core_base_commit(config),
            "implementation_sha256": dict(frozen_implementation_hashes(config)),
            "error": repr(exc),
            "resource_limits": {
                "address_space_limit_bytes": address_space_limit,
                "retrieval_wall_time_seconds": retrieval_wall_limit,
            },
            "outputs": state,
        },
    )


def _prepare_candidates(
    config: Mapping[str, Any],
    case: str,
    body_artifact: Mapping[str, Any],
    helpers: Mapping[str, Any],
    *,
    resource_limits: Mapping[str, int],
) -> tuple[dict[str, Any], dict[str, Any]]:
    identity = case_identity(config, case)
    paths = case_paths(config, case)
    candidate_paths = _candidate_paths(paths)
    existing = _candidate_metadata(
        config,
        case,
        paths,
        candidate_paths,
        identity,
    )
    if existing is not None:
        for key, expected in (
            ("body_evidence_sha256", sha256_file(paths["body"])),
            ("fixture_sha256", sha256_file(paths["fixture"])),
            ("raw_graph_sha256", sha256_file(paths["raw_graph"])),
        ):
            if existing.get(key) != expected:
                raise ValueError(f"retained candidate {key} identity mismatch")
        loaded = {name: read_json(path) for name, path in candidate_paths.items()}
        for artifact in loaded.values():
            helpers["validate_candidate_artifact"](artifact)
        return existing, loaded

    body_path = paths["body"]
    fixture_path = paths["fixture"]
    body_sha = sha256_file(body_path)
    fixture_sha = sha256_file(fixture_path)
    started = time.perf_counter()
    base = helpers["build_multiview_candidate_artifact_from_files"](
        body_path=body_path,
        fixture_path=fixture_path,
        top_k=identity["k"],
        mode=identity["mode"],
        views=("token", "cfg", "relation"),
        track=identity["track"],
        candidate_scope=identity["candidate_scope"],
        anchor_policy=identity["anchor_policy"],
    )
    multi_sha = write_json_once(candidate_paths["multi"], base)
    derive = helpers["derive"]
    body2 = derive(
        base,
        identity["k"],
        ("token", "cfg"),
        source_sha=multi_sha,
    )
    c3 = derive(
        base,
        identity["k"],
        ("token", "cfg", "relation"),
        source_sha=multi_sha,
    )
    rescue = derive(
        base,
        identity["k"],
        ("token", "cfg", "relation"),
        minimum=2,
        source_sha=multi_sha,
    )
    for name, artifact in (("body2", body2), ("c3", c3), ("rescue", rescue)):
        helpers["validate_candidate_artifact"](artifact)
        write_json_once(candidate_paths[name], artifact)

    bodies = helpers["load_body_evidence"](body_artifact)
    selection = helpers["select_control_pairs"](
        body2,
        c3,
        bodies,
        seed=BODY_SCORE_SEED,
    )
    body_score = helpers["make_control_artifact"](
        body2,
        selection["body-score"],
        ARM_BODY_SCORE,
        {
            "case": case,
            "seed": BODY_SCORE_SEED,
            "selection": selection["body_score_stats"],
            "body2_source_sha256": sha256_file(candidate_paths["body2"]),
            "treatment_source_sha256": sha256_file(candidate_paths["c3"]),
        },
    )
    write_json_once(candidate_paths["body_score"], body_score)
    policy = _f6_policy(config, helpers)
    demand = {
        name: _candidate_demand(artifact, bodies, policy, helpers)
        for name, artifact in (
            ("body2", body2),
            ("c3", c3),
            ("rescue", rescue),
            ("body_score", body_score),
        )
    }
    metadata = {
        "status": "completed",
        "case": case,
        **identity,
        "config_sha256": sha256_file(_config_path()),
        "protocol_sha256": sha256_file(_protocol_path()),
        "base_commit": core_base_commit(config),
        "implementation_sha256": dict(frozen_implementation_hashes(config)),
        "body_evidence_sha256": body_sha,
        "fixture_sha256": fixture_sha,
        "raw_graph_sha256": sha256_file(paths["raw_graph"]),
        "generation_seconds": time.perf_counter() - started,
        "selection_frozen_before_f4_cache": True,
        "gt_used_for_selection": False,
        "linkage_used_for_selection": False,
        "relation_flags_used_for_selection": False,
        "body_score_seed": BODY_SCORE_SEED,
        "resource_limits": dict(resource_limits),
        "selection": selection["body_score_stats"],
        "demand": demand,
        "outputs": {name: source_record(path) for name, path in candidate_paths.items()},
    }
    write_json_once(paths["candidate_metadata"], metadata)
    return metadata, {name: read_json(path) for name, path in candidate_paths.items()}


def _prediction_identity(
    config: Mapping[str, Any],
    case: str,
    arm: str,
    candidate_sha: str | None,
) -> dict[str, Any]:
    return {
        "case": case,
        "arm": arm,
        "config_sha256": sha256_file(_config_path()),
        "protocol_sha256": sha256_file(_protocol_path()),
        "base_commit": core_base_commit(config),
        "implementation_sha256": dict(frozen_implementation_hashes(config)),
        "candidate_sha256": candidate_sha,
    }


def _retained_arm(
    config: Mapping[str, Any],
    case: str,
    arm: str,
    destination: Path,
    candidate_sha: str | None,
) -> dict[str, Any] | None:
    metadata_path = destination / "metadata.json"
    prediction_path = destination / "prediction.json"
    identity = _prediction_identity(config, case, arm, candidate_sha)
    if not metadata_path.exists():
        if destination.exists() and any(destination.iterdir()):
            raise ValueError(f"partial retained prediction exists: {destination}")
        return None
    metadata = read_json(metadata_path)
    if not isinstance(metadata, Mapping):
        raise ValueError(f"prediction metadata is invalid: {metadata_path}")
    for key, value in identity.items():
        if metadata.get(key) != value:
            raise ValueError(f"retained prediction {arm} {key} identity mismatch")
    status = metadata.get("status")
    if status == "completed":
        expected = metadata.get("prediction_sha256")
        if not prediction_path.is_file() or sha256_file(prediction_path) != expected:
            raise ValueError(f"retained prediction hash mismatch: {prediction_path}")
    elif status not in {"budget-refused", "resource-incomplete", "blocked-prerequisite"}:
        raise ValueError(f"retained prediction has invalid status: {status!r}")
    elif prediction_path.exists():
        raise ValueError(f"non-completed prediction has an output: {prediction_path}")
    return dict(metadata)


def _write_arm_metadata(destination: Path, metadata: Mapping[str, Any]) -> dict[str, Any]:
    write_json_once(destination / "metadata.json", dict(metadata))
    return dict(metadata)


def _simple_prediction(
    case: str,
    identity: Mapping[str, Any],
    arm: str,
    target_ids: list[str],
    clusters: Any,
) -> dict[str, Any]:
    target_set = set(target_ids)
    return {
        "artifact": "novel-source-prediction",
        "case": case,
        "build": identity["build"],
        "profile": identity["profile"],
        "scope": identity["candidate_scope"],
        "arm": arm,
        "universe": {"target_ids": sorted(target_ids)},
        "clusters": [
            {"members": sorted(set(group) & target_set), "status": "accepted"}
            for group in clusters
            if len(set(group) & target_set) >= 2
        ],
    }


def _run_v0(
    case: str,
    identity: Mapping[str, Any],
    fixture_path: Path,
    target_ids: list[str],
) -> dict[str, Any]:
    from engine import run_cg_wl
    from loader import load_case

    result = run_cg_wl(load_case(str(fixture_path)), mode=identity["mode"], trace=True)
    return _simple_prediction(case, identity, ARM_V0, target_ids, result.clusters)


def _run_exact(
    case: str,
    identity: Mapping[str, Any],
    bodies: Mapping[str, Any],
    build_token_profiles: Any,
) -> dict[str, Any]:
    groups: defaultdict[str, list[str]] = defaultdict(list)
    for function_id, profile in build_token_profiles(bodies).items():
        body = bodies[function_id]
        if body.complete and body.instructions and not body.quality.get("opaque_indirect_jumps", 0):
            groups[profile.exact_token_hash].append(function_id)
    return _simple_prediction(case, identity, ARM_EXACT, list(bodies), groups.values())


def _run_f6(
    candidate: Mapping[str, Any],
    candidate_sha: str,
    body_path: Path,
    bodies: Mapping[str, Any],
    body_artifact: Mapping[str, Any],
    policy: Any,
    feature_cache: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from relation_control import run_f6_pair

    return run_f6_pair(
        candidate,
        bodies,
        policy,
        feature_cache=feature_cache,
        body_sha256=sha256_file(body_path),
        body_provenance=body_artifact["provenance"],
        candidate_sha256=candidate_sha,
    )


def _run_case(config: Mapping[str, Any], case: str, helpers: Mapping[str, Any]) -> dict[str, Any]:
    identity = case_identity(config, case)
    paths = case_paths(config, case)
    runtime_limit, wall_limit, retrieval_wall_limit = _resource_limits(config)
    resource.setrlimit(resource.RLIMIT_AS, (runtime_limit, runtime_limit))
    _observation, body_artifact, observed = _observation_inputs(config, case)
    bodies = helpers["load_body_evidence"](body_artifact)
    try:
        _candidate_metadata_record, candidates = _timed(
            lambda: _prepare_candidates(
                config,
                case,
                body_artifact,
                helpers,
                resource_limits={
                    "address_space_limit_bytes": runtime_limit,
                    "retrieval_wall_time_seconds": retrieval_wall_limit,
                },
            ),
            retrieval_wall_limit,
        )
    except (MemoryError, TimeoutError) as exc:
        _write_candidate_failure(
            config,
            case,
            paths,
            exc,
            address_space_limit=runtime_limit,
            retrieval_wall_limit=retrieval_wall_limit,
        )
        raise
    except Exception as exc:
        _write_candidate_failure(
            config,
            case,
            paths,
            exc,
            address_space_limit=runtime_limit,
            retrieval_wall_limit=retrieval_wall_limit,
        )
        raise
    candidate_paths = _candidate_paths(paths)
    policy = _f6_policy(config, helpers)
    feature_cache = helpers["BodyFeatureCache"](bodies)
    results: dict[str, Any] = {}
    arm_candidate_keys = {
        ARM_B2: "body2",
        ARM_C3: "c3",
        ARM_BODY_SCORE: "body_score",
        ARM_RESCUE: "rescue",
    }

    def run_arm(
        arm: str,
        candidate: Mapping[str, Any] | None,
        operation: Any,
    ) -> dict[str, Any]:
        candidate_key = arm_candidate_keys.get(arm)
        candidate_sha = (
            sha256_file(candidate_paths[candidate_key]) if candidate_key else None
        )
        destination = paths["prediction_dir"] / arm
        retained = _retained_arm(config, case, arm, destination, candidate_sha)
        if retained is not None:
            results[arm] = retained
            print(f"{case}/{arm}: {retained['status']}", flush=True)
            return retained
        started = time.perf_counter()
        metadata: dict[str, Any] = {
            **_prediction_identity(config, case, arm, candidate_sha),
            "status": "running",
            "body_evidence_sha256": sha256_file(paths["body"]),
            "fixture_sha256": sha256_file(paths["fixture"]),
            "resource_limits": {
                "address_space_limit_bytes": runtime_limit,
                "wall_time_limit_seconds": wall_limit,
            },
        }
        if candidate is not None:
            demand = _candidate_demand(candidate, bodies, policy, helpers)
            metadata["demand"] = demand
            if not demand["fits"]:
                metadata.update({
                    "status": "budget-refused",
                    "resource": _resource_metadata(),
                })
                result = _write_arm_metadata(destination, metadata)
                results[arm] = result
                print(f"{case}/{arm}: budget-refused", flush=True)
                return result
        try:
            before = {
                "hits": feature_cache.hits,
                "misses": feature_cache.misses,
                "comparisons": feature_cache.physical_comparisons,
                "cells": feature_cache.physical_alignment_cells,
            }
            prediction, actual_cost = _timed(operation, wall_limit)
            prediction_path = destination / "prediction.json"
            write_json_once(prediction_path, prediction)
            metadata.update({
                "status": "completed",
                "prediction_sha256": sha256_file(prediction_path),
                "elapsed_seconds": time.perf_counter() - started,
                "logical_cost": actual_cost,
                "comparison_cost": actual_cost,
                "physical_cache": {
                    "hits_delta": feature_cache.hits - before["hits"],
                    "misses_delta": feature_cache.misses - before["misses"],
                    "physical_cache_comparisons": feature_cache.physical_comparisons - before["comparisons"],
                    "physical_cache_alignment_cells": feature_cache.physical_alignment_cells - before["cells"],
                    "entries": len(feature_cache.features),
                },
                "resource": _resource_metadata(),
            })
        except (MemoryError, TimeoutError) as exc:
            metadata.update({
                "status": "resource-incomplete",
                "error": repr(exc),
                "elapsed_seconds": time.perf_counter() - started,
                "resource": _resource_metadata(),
            })
        except Exception as exc:
            metadata.update({"status": "error", "error": repr(exc)})
            _write_arm_metadata(destination, metadata)
            raise
        result = _write_arm_metadata(destination, metadata)
        results[arm] = result
        print(f"{case}/{arm}: {result['status']}", flush=True)
        return result

    target_ids = sorted(bodies)
    run_arm(
        ARM_V0,
        None,
        lambda: (_run_v0(case, identity, paths["fixture"], target_ids), {}),
    )
    run_arm(
        ARM_EXACT,
        None,
        lambda: (_run_exact(case, identity, bodies, helpers["build_token_profiles"]), {}),
    )

    def strict_operation(candidate: Mapping[str, Any], candidate_path: Path) -> Any:
        return lambda: _run_f6(
            candidate,
            sha256_file(candidate_path),
            paths["body"],
            bodies,
            body_artifact,
            policy,
            feature_cache,
        )

    run_arm(
        ARM_B2,
        candidates["body2"],
        strict_operation(candidates["body2"], candidate_paths["body2"]),
    )
    c3_meta = run_arm(
        ARM_C3,
        candidates["c3"],
        strict_operation(candidates["c3"], candidate_paths["c3"]),
    )
    run_arm(
        ARM_BODY_SCORE,
        candidates["body_score"],
        strict_operation(candidates["body_score"], candidate_paths["body_score"]),
    )

    strict_path = paths["prediction_dir"] / ARM_C3 / "prediction.json"
    rescue_candidate_sha = sha256_file(candidate_paths["rescue"])
    rescue_destination = paths["prediction_dir"] / ARM_RESCUE
    retained_rescue = _retained_arm(
        config,
        case,
        ARM_RESCUE,
        rescue_destination,
        rescue_candidate_sha,
    )
    if retained_rescue is not None:
        results[ARM_RESCUE] = retained_rescue
        print(f"{case}/{ARM_RESCUE}: {retained_rescue['status']}", flush=True)
        return results
    if c3_meta.get("status") != "completed":
        rescue_metadata = {
            **_prediction_identity(config, case, ARM_RESCUE, rescue_candidate_sha),
            "status": "blocked-prerequisite",
            "prerequisite": ARM_C3,
            "resource": _resource_metadata(),
        }
        _write_arm_metadata(rescue_destination, rescue_metadata)
        results[ARM_RESCUE] = rescue_metadata
        print(f"{case}/{ARM_RESCUE}: blocked-prerequisite", flush=True)
    else:
        def rescue_operation() -> tuple[dict[str, Any], dict[str, Any]]:
            rescue_config = config.get("rescue")
            if not isinstance(rescue_config, Mapping) or not isinstance(rescue_config.get("budget"), Mapping):
                raise ValueError("config.rescue.budget is required")
            budget = helpers["RescueBudget"](**{
                key: int(value)
                for key, value in rescue_config["budget"].items()
            })
            strict = read_json(strict_path)
            rescue_artifact = helpers["build_rescue_artifact"](
                strict,
                candidates["rescue"],
                body_artifact,
                observed["raw_graph"],
                budget=budget,
                provenance={
                    "family_artifact_sha256": sha256_file(strict_path),
                    "candidate_artifact_sha256": sha256_file(candidate_paths["rescue"]),
                    "body_evidence_sha256": sha256_file(paths["body"]),
                    "raw_graph_sha256": sha256_file(paths["raw_graph"]),
                },
            )
            destination = rescue_destination
            rescue_path = destination / "rescue-artifact.json"
            write_json_once(rescue_path, rescue_artifact)
            clusters = helpers["rescued_clusters"](
                strict,
                rescue_artifact,
                family_artifact_sha256=sha256_file(strict_path),
            )
            prediction = _simple_prediction(case, identity, ARM_RESCUE, target_ids, clusters)
            return prediction, {
                "rescue_artifact_sha256": sha256_file(rescue_path),
                "rescue_budget": budget.to_dict(),
                "rescue_summary": rescue_artifact["summary"],
            }

        # Rescue has an additional explicit budget and is timed separately;
        # its body work is not charged to strict F6 logical cost.
        destination = rescue_destination
        started = time.perf_counter()
        metadata = {
            **_prediction_identity(config, case, ARM_RESCUE, rescue_candidate_sha),
            "status": "running",
            "body_evidence_sha256": sha256_file(paths["body"]),
            "fixture_sha256": sha256_file(paths["fixture"]),
            "resource_limits": {
                "address_space_limit_bytes": runtime_limit,
                "wall_time_limit_seconds": wall_limit,
            },
        }
        try:
            prediction, rescue_info = _timed(rescue_operation, wall_limit)
            prediction_path = destination / "prediction.json"
            write_json_once(prediction_path, prediction)
            metadata.update({
                "status": "completed",
                "prediction_sha256": sha256_file(prediction_path),
                "elapsed_seconds": time.perf_counter() - started,
                **rescue_info,
                "resource": _resource_metadata(),
            })
        except (MemoryError, TimeoutError) as exc:
            metadata.update({
                "status": "resource-incomplete",
                "error": repr(exc),
                "elapsed_seconds": time.perf_counter() - started,
                "resource": _resource_metadata(),
            })
        except Exception as exc:
            metadata.update({"status": "error", "error": repr(exc)})
            _write_arm_metadata(destination, metadata)
            raise
        _write_arm_metadata(destination, metadata)
        results[ARM_RESCUE] = metadata
        print(f"{case}/{ARM_RESCUE}: {metadata['status']}", flush=True)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case")
    args = parser.parse_args(argv)
    try:
        config = _load_frozen_config()
        _verify_core(config)
        _verify_runtime(config)
        cases = config_cases(config)
        if args.case is not None:
            if args.case not in cases:
                raise ValueError(f"case is outside frozen config: {args.case}")
            cases = (args.case,)
        helpers = _import_prior_helpers(config)
        for case in cases:
            _run_case(config, case, helpers)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
