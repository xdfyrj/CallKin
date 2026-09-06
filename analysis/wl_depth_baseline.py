"""Preregistered seed/r1/r2/fixpoint CG-WL depth baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine import (  # noqa: E402
    CGWLResult,
    CGWLRoundTrace,
    make_cluster_id_by_node,
    run_cg_wl,
)
from loader import load_case  # noqa: E402
from model import Case  # noqa: E402
import scores as frozen_scores  # noqa: E402
from scores import (  # noqa: E402
    GroundTruth,
    _check_join,
    _pairwise_score,
    load_ground_truth,
)


ARTIFACT = "callkin-wl-depth-baseline"
SCHEMA_VERSION = 1
COST_CAP_SECONDS = 600.0
PROTOCOL_COMMIT = "0da3732fb7221e1ea043561d181f44594c528a8a"
PROTOCOL_SHA256 = "7a129d77acd9c3447574ca0fc7d6c53a74da42b12a35778e9d762ce157a38459"
RIPGREP_FIXTURE_SHA256 = "cb224f069a413c82a8f2a45029be8d0660ea008a89ff32333fb38d3a5ba7af81"
RIPGREP_GT_SHA256 = "e792a9c8442ffb833b5d47f34fbcf5f26395c8369230780f0a46a5903b5bf166"
DEFAULT_OUTPUT = ROOT / "results/wl-depth-baseline/plain/wl-depth-baseline.json"
DEFAULT_RUNTIME_OUTPUT = ROOT / "results/wl-depth-baseline/plain/wl-depth-baseline.runtime.json"
DEFAULT_RIPGREP_ROOT = ROOT.parent / "v0-engine-py"
DEFAULT_PROTOCOL = (
    Path("/mnt/c/users/sumyr/playground/+/obsidian/gear/research")
    / "30_Experiments/CallKin WL Depth Baseline Protocol.md"
)
DEPTHS = (("seed", 0), ("r1", 1), ("r2", 2), ("fixpoint", None))


@dataclass(frozen=True)
class Job:
    cohort: str
    case: str
    build: str
    profile: str
    mode: str
    fixture_path: Path
    ground_truth_path: Path
    fixture_repository: str
    ground_truth_repository: str
    fixture_must_be_tracked: bool = True
    ground_truth_must_be_tracked: bool = True

    @property
    def job_id(self) -> str:
        return f"{self.cohort}/{self.case}/{self.build}/{self.profile}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _enforce_cost_cap(elapsed_seconds: float, job_id: str, stage: str) -> None:
    if elapsed_seconds > COST_CAP_SECONDS:
        raise RuntimeError(
            f"10-minute cost cap exceeded at {job_id} during {stage}: "
            f"{elapsed_seconds:.3f}s"
        )


def _partition_is_nested(
    coarse: Iterable[Iterable[str]],
    fine: Iterable[Iterable[str]],
) -> bool:
    coarse_sets = [set(cluster) for cluster in coarse]
    return all(
        any(set(cluster) <= parent for parent in coarse_sets)
        for cluster in fine
    )


def _score_partition(
    clusters: tuple[tuple[str, ...], ...],
    ground_truth: GroundTruth,
) -> dict[str, Any]:
    normalized = [list(cluster) for cluster in clusters]
    cluster_of = make_cluster_id_by_node(normalized)
    origin_of = ground_truth.origin_of()
    tp = fp = fn = tn = 0
    for first, second in combinations(sorted(cluster_of), 2):
        predicted_same = cluster_of[first] == cluster_of[second]
        actual_same = origin_of[first] == origin_of[second]
        if predicted_same and actual_same:
            tp += 1
        elif predicted_same:
            fp += 1
        elif actual_same:
            fn += 1
        else:
            tn += 1

    pairwise = _pairwise_score(tp, fp, fn, tn)
    fragmented_origins = sum(
        1
        for group in ground_truth.origins
        if len(group.members) > 1
        and len({cluster_of[member] for member in group.members if member in cluster_of}) > 1
    )
    collision_clusters = sum(
        1
        for cluster in normalized
        if len({origin_of[member] for member in cluster}) > 1
    )
    return {
        "partition_sha256": _canonical_sha256(normalized),
        "pairwise": {
            "TP": pairwise.tp,
            "FP": pairwise.fp,
            "FN": pairwise.fn,
            "TN": pairwise.tn,
            "precision": pairwise.precision,
            "recall": pairwise.recall,
            "F1": pairwise.f1,
        },
        "cluster_count": len(normalized),
        "singleton_count": sum(len(cluster) == 1 for cluster in normalized),
        "fragmented_origin_count": fragmented_origins,
        "collision_cluster_count": collision_clusters,
    }


def _reference_partition_matches(
    final: dict[str, Any],
    reference_clusters: Iterable[Any],
) -> bool:
    expected = [list(cluster.member_ids) for cluster in reference_clusters]
    return final["partition_sha256"] == _canonical_sha256(expected)


def _common_coverage(case: Case, ground_truth: GroundTruth) -> dict[str, Any]:
    grouped = sum(node.scored for node in case.nodes)
    abstained = len(case.abstentions)
    target = grouped + abstained
    decision_pairs = grouped * (grouped - 1) // 2
    target_pairs = target * (target - 1) // 2
    total_same_family_pairs = sum(
        len(group.members) * (len(group.members) - 1) // 2
        for group in ground_truth.origins
    )
    abstained_ids = {item.id for item in case.abstentions}
    scored_same_family_pairs = sum(
        len([member for member in group.members if member not in abstained_ids])
        * (len([member for member in group.members if member not in abstained_ids]) - 1)
        // 2
        for group in ground_truth.origins
    )
    return {
        "target_count": target,
        "grouped_candidate_count": grouped,
        "abstained_candidate_count": abstained,
        "target_pair_count": target_pairs,
        "decision_pair_count": decision_pairs,
        "total_same_family_pair_count": total_same_family_pairs,
        "scored_same_family_pair_count": scored_same_family_pairs,
        "target_coverage": grouped / target if target else None,
        "pair_decision_coverage": decision_pairs / target_pairs if target_pairs else None,
        "same_family_pair_coverage": (
            scored_same_family_pairs / total_same_family_pairs
            if total_same_family_pairs else None
        ),
    }


def evaluate_case(
    case: Case,
    ground_truth: GroundTruth,
    *,
    mode: str,
    include_clusters: bool = False,
) -> dict[str, Any]:
    """Score the four preregistered views of one unchanged traced WL run."""

    _check_join(case, ground_truth)
    result = run_cg_wl(case, mode=mode, trace=True)
    trace_by_round = {step.round_index: step for step in result.trace}
    if not result.trace or result.trace[-1].changed is not False:
        raise ValueError("traced CG-WL run does not end at a confirmed fixpoint")

    grouped_universe = sorted(node.id for node in case.nodes if node.scored)
    target_universe = sorted(
        grouped_universe + [item.id for item in case.abstentions]
    )
    depths: dict[str, dict[str, Any]] = {}
    partitions: list[tuple[tuple[str, ...], ...]] = []
    for name, requested_round in DEPTHS:
        source_round = (
            result.rounds
            if requested_round is None
            else min(requested_round, result.rounds)
        )
        step: CGWLRoundTrace = trace_by_round[source_round]
        observed_universe = sorted(member for cluster in step.clusters for member in cluster)
        if observed_universe != grouped_universe:
            raise ValueError(f"target universe changed at {name}")
        row = _score_partition(step.clusters, ground_truth)
        row.update({
            "source_round": source_round,
            "carried_forward": (
                requested_round is not None and requested_round > result.rounds
            ),
        })
        if include_clusters:
            row["_clusters"] = [list(cluster) for cluster in step.clusters]
        depths[name] = row
        partitions.append(step.clusters)

    seed = depths["seed"]["pairwise"]
    for row in depths.values():
        score = row["pairwise"]
        row["delta_from_seed"] = {
            key: score[key] - seed[key]
            for key in ("TP", "FP", "FN")
        }

    nesting = all(
        _partition_is_nested(coarse, fine)
        for coarse, fine in zip(partitions, partitions[1:])
    )
    if not nesting:
        raise ValueError("WL refinement partitions are not monotonically nested")

    return {
        "fixpoint_round": result.rounds,
        "common_coverage": _common_coverage(case, ground_truth),
        "grouped_universe_sha256": _canonical_sha256(grouped_universe),
        "target_universe_sha256": _canonical_sha256(target_universe),
        "depths": depths,
        "validation": {
            "target_universe_fixed": True,
            "partition_nesting_monotonic": True,
        },
    }


def _jobs(ripgrep_root: Path) -> list[Job]:
    jobs = []
    for profile in ("plain", "min"):
        for case, build in (
            ("family_graph_01", "O3S"),
            ("family_graph_02", "O3S"),
            ("family_graph_03", "O3S"),
            ("family_graph_03", "O3KS"),
        ):
            jobs.append(Job(
                "controlled", case, build, profile, "full",
                ROOT / f"fixtures/{profile}/{case}.{build}.fixture.json",
                ROOT / f"ground_truth/{profile}/{case}.{build}.gt.json",
                "experiment", "experiment",
            ))
    for profile in ("plain", "min"):
        for case in ("billing-client", "zoxide", "fd"):
            jobs.append(Job(
                "real-world", case, "O3S", profile, "out-in",
                ROOT / f"fixtures/angr/role/rust-nonstd/{profile}/{case}.O3S.fixture.json",
                ROOT / f"ground_truth/rust-nonstd/{profile}/{case}.O3S.gt.json",
                "experiment", "experiment",
            ))
    jobs.append(Job(
        "real-world", "ripgrep-main", "O3S", "plain", "out-in",
        ripgrep_root / "fixtures/angr/role/rust-nonstd/plain/ripgrep-main.O3S.fixture.json",
        ripgrep_root / "ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json",
        "canonical-ripgrep", "canonical-ripgrep", False, False,
    ))
    return jobs


def _relative_reference(path: Path, repository_root: Path) -> str:
    return path.resolve().relative_to(repository_root.resolve()).as_posix()


def _git_commit(repository_root: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _verify_protocol_commit(protocol_path: Path) -> None:
    vault_root = protocol_path.parents[1]
    relative = protocol_path.relative_to(vault_root).as_posix()
    committed = subprocess.run(
        ["git", "-C", str(vault_root), "show", f"{PROTOCOL_COMMIT}:{relative}"],
        check=True,
        capture_output=True,
    ).stdout
    if hashlib.sha256(committed).hexdigest() != PROTOCOL_SHA256:
        raise ValueError("preregistered commit does not contain the protocol bytes")


def _assert_tracked(path: Path, repository_root: Path) -> None:
    relative = _relative_reference(path, repository_root)
    subprocess.run(
        ["git", "-C", str(repository_root), "ls-files", "--error-unmatch", relative],
        check=True,
        capture_output=True,
        text=True,
    )
    unchanged = subprocess.run(
        ["git", "-C", str(repository_root), "diff", "--quiet", "HEAD", "--", relative],
        check=False,
    ).returncode == 0
    if not unchanged:
        raise ValueError(f"tracked input differs from HEAD: {relative}")


def _validate_job_identity(job: Job, case: Case, ground_truth: GroundTruth) -> None:
    expected = (job.case, job.build, job.profile)
    fixture_identity = (case.case, case.build, case.profile)
    ground_truth_identity = (
        ground_truth.case,
        ground_truth.build,
        ground_truth.profile,
    )
    if fixture_identity != expected or ground_truth_identity != expected:
        raise ValueError(
            f"{job.job_id}: loaded input identity mismatch: "
            f"expected={expected}, fixture={fixture_identity}, "
            f"ground_truth={ground_truth_identity}"
        )


def _score_with_existing_scorer(
    fixture: str | Path,
    ground_truth: str | Path,
    *,
    mode: str,
    clusters: list[list[str]],
    fixpoint_round: int,
):
    synthetic = CGWLResult(
        mode=mode,
        cluster_id_by_node=make_cluster_id_by_node(clusters),
        clusters=clusters,
        rounds=fixpoint_round,
    )
    original = frozen_scores.run_cg_wl
    frozen_scores.run_cg_wl = lambda _case, **_kwargs: synthetic
    try:
        return frozen_scores.score_case(
            str(fixture),
            str(ground_truth),
            mode=mode,
        )
    finally:
        frozen_scores.run_cg_wl = original


def _depth_matches_reference(
    row: dict[str, Any],
    coverage: dict[str, Any],
    reference: Any,
) -> bool:
    pairwise = reference.pairwise
    expected_pairwise = {
        "TP": pairwise.tp,
        "FP": pairwise.fp,
        "FN": pairwise.fn,
        "TN": pairwise.tn,
        "precision": pairwise.precision,
        "recall": pairwise.recall,
        "F1": pairwise.f1,
    }
    return (
        row["pairwise"] == expected_pairwise
        and row["cluster_count"] == len(reference.clusters)
        and row["singleton_count"]
        == sum(len(cluster.member_ids) == 1 for cluster in reference.clusters)
        and row["fragmented_origin_count"]
        == sum(
            origin.k_obs > 1 and origin.predicted_cluster_count > 1
            for origin in reference.origins
        )
        and row["collision_cluster_count"]
        == sum(len(cluster.origins) > 1 for cluster in reference.clusters)
        and _reference_partition_matches(row, reference.clusters)
        and coverage["target_count"] == reference.target_count
        and coverage["grouped_candidate_count"] == reference.grouped_candidate_count
        and coverage["abstained_candidate_count"] == len(reference.abstentions)
        and coverage["target_pair_count"] == reference.target_pair_count
        and coverage["decision_pair_count"] == reference.pair_count
        and coverage["total_same_family_pair_count"]
        == reference.total_same_family_pair_count
        and coverage["scored_same_family_pair_count"]
        == reference.scored_same_family_pair_count
        and coverage["target_coverage"] == reference.target_coverage
        and coverage["pair_decision_coverage"] == reference.pair_decision_coverage
        and coverage["same_family_pair_coverage"] == reference.same_family_pair_coverage
    )


def build_report(
    *,
    ripgrep_root: Path = DEFAULT_RIPGREP_ROOT,
    protocol_path: Path = DEFAULT_PROTOCOL,
    runtime_output_path: Path = DEFAULT_RUNTIME_OUTPUT,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _verify_protocol_commit(protocol_path)
    if sha256_file(protocol_path) != PROTOCOL_SHA256:
        raise ValueError("protocol bytes do not match preregistered commit")

    repositories = {
        "experiment": ROOT,
        "canonical-ripgrep": ripgrep_root,
    }
    jobs = _jobs(ripgrep_root)
    if len(jobs) != 15:
        raise AssertionError(f"expected 15 jobs, found {len(jobs)}")

    total_start = time.perf_counter()
    initial_hashes: dict[Path, str] = {}
    for job in jobs:
        for path, repository, must_be_tracked in (
            (
                job.fixture_path,
                job.fixture_repository,
                job.fixture_must_be_tracked,
            ),
            (
                job.ground_truth_path,
                job.ground_truth_repository,
                job.ground_truth_must_be_tracked,
            ),
        ):
            if must_be_tracked:
                _assert_tracked(path, repositories[repository])
            initial_hashes[path] = sha256_file(path)
            _enforce_cost_cap(
                time.perf_counter() - total_start,
                job.job_id,
                "input pinning",
            )
    ripgrep_job = jobs[-1]
    if initial_hashes[ripgrep_job.fixture_path] != RIPGREP_FIXTURE_SHA256:
        raise ValueError("ripgrep fixture SHA-256 mismatch")
    if initial_hashes[ripgrep_job.ground_truth_path] != RIPGREP_GT_SHA256:
        raise ValueError("ripgrep ground-truth SHA-256 mismatch")

    records = []
    runtimes = []
    for job in jobs:
        started = time.perf_counter()
        case = load_case(str(job.fixture_path))
        ground_truth = load_ground_truth(str(job.ground_truth_path))
        _validate_job_identity(job, case, ground_truth)
        _enforce_cost_cap(
            time.perf_counter() - total_start,
            job.job_id,
            "input loading",
        )
        if job.cohort == "real-world" and (
            case.analysis is None
            or case.analysis.track != "angr"
            or case.analysis.anchor_policy != "role"
            or case.analysis.candidate_scope != "rust-nonstd"
        ):
            raise ValueError(f"{job.job_id}: real-world analysis configuration mismatch")
        result = evaluate_case(
            case,
            ground_truth,
            mode=job.mode,
            include_clusters=True,
        )
        _enforce_cost_cap(
            time.perf_counter() - total_start,
            job.job_id,
            "depth scoring",
        )
        for depth, row in result["depths"].items():
            reference = _score_with_existing_scorer(
                job.fixture_path,
                job.ground_truth_path,
                mode=job.mode,
                clusters=row.pop("_clusters"),
                fixpoint_round=result["fixpoint_round"],
            )
            if not _depth_matches_reference(
                row,
                result["common_coverage"],
                reference,
            ):
                raise ValueError(
                    f"{job.job_id}/{depth}: differs from unchanged scores.py"
                )
        _enforce_cost_cap(
            time.perf_counter() - total_start,
            job.job_id,
            "existing scorer validation",
        )
        result["validation"]["all_depths_match_existing_scorer"] = True
        result.update({
            "id": job.job_id,
            "cohort": job.cohort,
            "case": job.case,
            "build": job.build,
            "profile": job.profile,
            "mode": job.mode,
            "analysis": (
                case.analysis.to_dict() if case.analysis is not None else None
            ),
            "inputs": {
                "fixture": {
                    "repository": job.fixture_repository,
                    "path": _relative_reference(
                        job.fixture_path, repositories[job.fixture_repository]
                    ),
                    "sha256": initial_hashes[job.fixture_path],
                    "git_tracked": job.fixture_must_be_tracked,
                },
                "ground_truth": {
                    "repository": job.ground_truth_repository,
                    "path": _relative_reference(
                        job.ground_truth_path,
                        repositories[job.ground_truth_repository],
                    ),
                    "sha256": initial_hashes[job.ground_truth_path],
                    "git_tracked": job.ground_truth_must_be_tracked,
                },
            },
        })
        records.append(result)
        runtimes.append({
            "id": job.job_id,
            "seconds": time.perf_counter() - started,
        })

    if any(sha256_file(path) != digest for path, digest in initial_hashes.items()):
        raise ValueError("one or more input files changed during the run")

    report = {
        "artifact": ARTIFACT,
        "schema_version": SCHEMA_VERSION,
        "protocol": {
            "commit": PROTOCOL_COMMIT,
            "path": "30_Experiments/CallKin WL Depth Baseline Protocol.md",
            "sha256": PROTOCOL_SHA256,
        },
        "code": {
            "repository_commit": _git_commit(ROOT),
            "runner_sha256": sha256_file(Path(__file__)),
            "engine_sha256": sha256_file(ROOT / "engine.py"),
            "scores_sha256": sha256_file(ROOT / "scores.py"),
        },
        "runtime_metadata": {
            "separate_path": (
                runtime_output_path.resolve().relative_to(ROOT.resolve()).as_posix()
                if runtime_output_path.resolve().is_relative_to(ROOT.resolve())
                else runtime_output_path.resolve().as_posix()
            ),
        },
        "validation": {
            "job_count": len(records),
            "inputs_unchanged": True,
            "all_target_universes_fixed": True,
            "all_partitions_nested_monotonically": True,
            "all_depths_match_existing_scorer": True,
        },
        "jobs": records,
    }
    runtime = {
        "artifact": f"{ARTIFACT}-runtime",
        "schema_version": 1,
        "canonical_result_sha256": None,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "total_seconds": time.perf_counter() - total_start,
        "jobs": runtimes,
    }
    return report, runtime


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--runtime-output", type=Path, default=DEFAULT_RUNTIME_OUTPUT)
    parser.add_argument("--ripgrep-root", type=Path, default=DEFAULT_RIPGREP_ROOT)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    args = parser.parse_args(argv)
    try:
        report, runtime = build_report(
            ripgrep_root=args.ripgrep_root,
            protocol_path=args.protocol,
            runtime_output_path=args.runtime_output,
        )
        _write_json(args.output, report)
        runtime["canonical_result_sha256"] = sha256_file(args.output)
        _write_json(args.runtime_output, runtime)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.output}")
    print(f"sha256 {runtime['canonical_result_sha256']}")
    print(f"runtime {runtime['total_seconds']:.6f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
