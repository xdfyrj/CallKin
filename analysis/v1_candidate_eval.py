"""Evaluation-only metrics for an F5 candidate-pair artifact.

Ground truth is intentionally confined to this module.  ``v1_candidates``
and the F6 engine can therefore be run on a binary without knowing source
origins; this file only measures recall, reduction, and family connectivity
after the candidate set has been fixed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from v1_candidates import PairKey, validate_candidate_artifact  # noqa: E402


def evaluate_candidate_artifact(
    candidate_artifact: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
) -> dict[str, Any]:
    """Return F5 coverage/reduction metrics using GT labels only here."""

    validate_candidate_artifact(candidate_artifact)
    _validate_metadata(candidate_artifact, ground_truth)
    target_ids = list(candidate_artifact["universe"]["target_ids"])
    target_set = set(target_ids)
    origin_by_member = _ground_truth_index(ground_truth)
    origins = {
        origin: sorted(set(members) & target_set)
        for origin, members in _ground_truth_groups(ground_truth).items()
        if set(members) & target_set
    }
    missing_gt_members = sorted(target_set - set(origin_by_member))
    labeled_ids = sorted(target_set & set(origin_by_member))

    candidate_pairs: set[PairKey] = set()
    reason_counts: Counter[str] = Counter()
    for item in candidate_artifact["pairs"]:
        pair = PairKey.make(item["first"], item["second"])
        candidate_pairs.add(pair)
        reason_counts.update(item["reasons"])

    # Do not materialize the O(n^2) labelled-pair set.  F5 evaluation only
    # needs its cardinality and the candidate intersection; both can be
    # computed in one pass over GT groups and one pass over the bounded
    # candidate artifact.
    same_origin_pair_count = sum(
        len(members) * (len(members) - 1) // 2
        for members in origins.values()
    )
    candidate_labeled_pair_count = 0
    candidate_same_pair_count = 0
    for pair in candidate_pairs:
        first_origin = origin_by_member.get(pair.left)
        second_origin = origin_by_member.get(pair.right)
        if first_origin is None or second_origin is None:
            continue
        candidate_labeled_pair_count += 1
        if first_origin == second_origin:
            candidate_same_pair_count += 1
    candidate_pair_recall = (
        candidate_same_pair_count / same_origin_pair_count
        if same_origin_pair_count else None
    )
    total_pair_count = len(target_ids) * (len(target_ids) - 1) // 2
    candidate_pair_count = len(candidate_pairs)
    candidate_pair_fraction = (
        candidate_pair_count / total_pair_count if total_pair_count else 0.0
    )

    # Build candidate adjacency once.  The old implementation scanned every
    # candidate pair once per GT origin, which made the evaluator O(F*C).
    # This induced-adjacency representation makes each family report depend
    # only on its own members and their incident candidate edges.
    candidate_adjacency: dict[str, set[str]] = {
        member: set() for member in target_ids
    }
    for pair in candidate_pairs:
        candidate_adjacency[pair.left].add(pair.right)
        candidate_adjacency[pair.right].add(pair.left)

    family_reports = []
    for origin in sorted(origins):
        members = origins[origin]
        member_set = set(members)
        adjacency = {
            member: candidate_adjacency[member] & member_set
            for member in members
        }
        internal_edge_count = sum(len(neighbors) for neighbors in adjacency.values()) // 2
        covered_members = {
            member for member, neighbors in adjacency.items()
            if neighbors or len(members) == 1
        }
        connected = _connected(members, adjacency)
        family_reports.append({
            "origin": origin,
            "member_count": len(members),
            "candidate_member_count": len(covered_members),
            "member_coverage": (
                len(covered_members) / len(members) if members else 1.0
            ),
            "candidate_same_pair_count": internal_edge_count,
            "connected": connected,
        })

    coverage_values = [item["member_coverage"] for item in family_reports]
    member_coverage_summary = {
        "count": len(coverage_values),
        "min": min(coverage_values) if coverage_values else None,
        "mean": statistics.fmean(coverage_values) if coverage_values else None,
        "all_ge_0.95": bool(coverage_values) and min(coverage_values) >= 0.95,
    }
    multimember_reports = [
        report for report in family_reports
        if report["member_count"] > 1
    ]
    multimember_family_count = len(multimember_reports)
    multimember_member_count = sum(
        report["member_count"] for report in multimember_reports
    )
    same_origin_covered_member_count = sum(
        report["candidate_member_count"] for report in multimember_reports
    )
    member_without_same_origin_candidate_count = (
        multimember_member_count - same_origin_covered_member_count
    )
    same_origin_member_coverage = (
        same_origin_covered_member_count / multimember_member_count
        if multimember_member_count else None
    )
    connected_family_count = sum(
        bool(report["connected"]) for report in multimember_reports
    )
    connected_family_rate = (
        connected_family_count / multimember_family_count
        if multimember_family_count else None
    )
    all_multimember_families_connected = (
        bool(multimember_reports)
        and connected_family_count == multimember_family_count
    )
    metrics = {
        "target_count": len(target_ids),
        "labeled_target_count": len(labeled_ids),
        "missing_gt_member_count": len(missing_gt_members),
        "total_pair_count": total_pair_count,
        "candidate_pair_count": candidate_pair_count,
        "candidate_pair_fraction": candidate_pair_fraction,
        "pair_reduction": 1.0 - candidate_pair_fraction,
        "same_origin_pair_count": same_origin_pair_count,
        "candidate_labeled_pair_count": candidate_labeled_pair_count,
        "candidate_same_origin_pair_count": candidate_same_pair_count,
        "candidate_pair_recall": candidate_pair_recall,
        "expected_detailed_comparisons": candidate_pair_count,
        "reason_counts": dict(sorted(reason_counts.items())),
        "family_count": len(family_reports),
        "family_member_coverage": member_coverage_summary,
        "all_multimember_families_connected": all_multimember_families_connected,
        "multimember_family_count": multimember_family_count,
        "multimember_member_count": multimember_member_count,
        "same_origin_covered_member_count": same_origin_covered_member_count,
        "member_without_same_origin_candidate_count": (
            member_without_same_origin_candidate_count
        ),
        "same_origin_member_coverage": same_origin_member_coverage,
        "connected_family_count": connected_family_count,
        "connected_family_rate": connected_family_rate,
    }
    gate = {
        "candidate_pair_recall_ge_0.90": (
            candidate_pair_recall is not None and candidate_pair_recall >= 0.90
        ),
        "candidate_pair_fraction_le_0.02": candidate_pair_fraction <= 0.02,
        "family_member_coverage_ge_0.95": (
            same_origin_member_coverage is not None
            and same_origin_member_coverage >= 0.95
        ),
        "all_multimember_families_connected": all_multimember_families_connected,
    }
    gate["passed"] = all(gate.values())
    return {
        "schema_version": 1,
        "artifact": "v1-candidate-evaluation",
        "case": candidate_artifact["case"],
        "build": candidate_artifact["build"],
        "profile": candidate_artifact["profile"],
        "scope": candidate_artifact["scope"],
        "candidate_artifact": {
            "schema_version": candidate_artifact["schema_version"],
            "config": candidate_artifact["config"],
            "provenance": candidate_artifact["provenance"],
        },
        "ground_truth": {
            "used_for": "evaluation labels only",
            "origin_count": len(origins),
            "missing_member_ids": missing_gt_members,
        },
        "metrics": metrics,
        "gate_b": gate,
        "families": family_reports,
    }


def evaluate_candidate_files(
    candidate_path: str | Path,
    ground_truth_path: str | Path,
) -> dict[str, Any]:
    candidate = _read_json(candidate_path)
    ground_truth = _read_json(ground_truth_path)
    return evaluate_candidate_artifact(candidate, ground_truth)


def evaluate_candidate_sweep(
    candidate_artifacts: Mapping[int, Mapping[str, Any]],
    ground_truth: Mapping[str, Any],
    *,
    artifact_paths: Mapping[int, str] | None = None,
) -> dict[str, Any]:
    """Evaluate several F5 ``top_k`` artifacts and select the smallest pass.

    The sweep is an evaluation-plane operation: GT is read here, never by
    the candidate generator.  Every run is evaluated independently, then
    the smallest configured ``top_k`` whose Gate B is true is selected.  A
    failed sweep is an explicit retrieval-design failure, not a silent choice
    of an arbitrary k.
    """

    if not candidate_artifacts:
        raise ValueError("candidate sweep must contain at least one artifact")
    runs: list[dict[str, Any]] = []
    seen_top_k: set[int] = set()
    first_report: dict[str, Any] | None = None
    first_candidate: Mapping[str, Any] | None = None
    base_identity: tuple[Any, ...] | None = None
    for top_k, candidate in sorted(candidate_artifacts.items()):
        if not isinstance(top_k, int) or isinstance(top_k, bool) or top_k < 1:
            raise ValueError("candidate sweep top_k keys must be positive integers")
        if top_k in seen_top_k:
            raise ValueError(f"duplicate candidate sweep top_k: {top_k}")
        seen_top_k.add(top_k)
        config = candidate.get("config")
        if not isinstance(config, Mapping) or config.get("top_k") != top_k:
            raise ValueError(
                f"candidate sweep key {top_k} does not match artifact config"
            )
        report = evaluate_candidate_artifact(candidate, ground_truth)
        identity = _sweep_identity(report, candidate)
        if base_identity is None:
            base_identity = identity
        elif identity != base_identity:
            raise ValueError(
                "candidate sweep artifacts do not describe the same binary/configuration"
            )
        if first_report is None:
            first_report = report
            first_candidate = candidate
        metrics = report["metrics"]
        runs.append({
            "top_k": top_k,
            "artifact": artifact_paths.get(top_k) if artifact_paths else None,
            "metrics": {
                "target_count": metrics["target_count"],
                "candidate_pair_count": metrics["candidate_pair_count"],
                "candidate_pair_fraction": metrics["candidate_pair_fraction"],
                "pair_reduction": metrics["pair_reduction"],
                "same_origin_pair_count": metrics["same_origin_pair_count"],
                "candidate_same_origin_pair_count": metrics[
                    "candidate_same_origin_pair_count"
                ],
                "candidate_pair_recall": metrics["candidate_pair_recall"],
                "family_member_coverage": metrics["family_member_coverage"],
                "all_multimember_families_connected": metrics[
                    "all_multimember_families_connected"
                ],
                "multimember_family_count": metrics["multimember_family_count"],
                "multimember_member_count": metrics["multimember_member_count"],
                "same_origin_covered_member_count": metrics[
                    "same_origin_covered_member_count"
                ],
                "member_without_same_origin_candidate_count": metrics[
                    "member_without_same_origin_candidate_count"
                ],
                "same_origin_member_coverage": metrics[
                    "same_origin_member_coverage"
                ],
                "connected_family_count": metrics["connected_family_count"],
                "connected_family_rate": metrics["connected_family_rate"],
            },
            "gate_b": dict(report["gate_b"]),
        })

    passing = [run for run in runs if run["gate_b"]["passed"]]
    selected = min(passing, key=lambda run: run["top_k"]) if passing else None
    first = first_report or {}
    return {
        "schema_version": 1,
        "artifact": "v1-candidate-sweep-evaluation",
        "case": first.get("case"),
        "build": first.get("build"),
        "profile": first.get("profile"),
        "scope": first.get("scope"),
        "identity": _sweep_identity_summary(first, first_candidate or {}),
        "ground_truth": {
            "used_for": "evaluation labels only",
        },
        "selection": {
            "criterion": "smallest top_k passing Gate B",
            "status": "passed" if selected is not None else "failed",
            "selected_top_k": selected["top_k"] if selected is not None else None,
            "gate_b_passed": selected is not None,
            "next_action": (
                "use selected top_k for F6"
                if selected is not None
                else "redesign retrieval features before F6"
            ),
        },
        "runs": runs,
    }


def _sweep_identity(
    report: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
) -> tuple[Any, ...]:
    """Return the immutable analysis identity used by a k-sweep.

    A sweep is meaningful only when every top-k run was produced from the
    same binary, body extraction, graph projection, and relation policy.  A
    stripped hash alone is not enough: two runs can use the same binary while
    disagreeing about the candidate universe or graph artifact.
    """

    provenance = report["candidate_artifact"].get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("candidate sweep artifact is missing provenance")
    required_provenance = (
        "stripped_sha256",
        "body_evidence_sha256",
        "candidate_selection_sha256",
        "raw_graph_sha256",
        "projection_config_sha256",
        "fixture_sha256",
        "track",
        "anchor_policy",
    )
    missing = [
        key for key in required_provenance
        if provenance.get(key) in (None, "")
    ]
    if missing:
        raise ValueError(
            "candidate sweep artifact is missing identity provenance: "
            + ", ".join(missing)
        )
    relation = candidate_artifact.get("relation")
    if not isinstance(relation, Mapping) or not relation.get("mode"):
        raise ValueError("candidate sweep artifact is missing relation mode")
    universe = candidate_artifact.get("universe")
    target_ids = universe.get("target_ids") if isinstance(universe, Mapping) else None
    if not isinstance(target_ids, list) or any(
        not isinstance(function_id, str) or not function_id
        for function_id in target_ids
    ):
        raise ValueError("candidate sweep artifact is missing target IDs")
    config = candidate_artifact.get("config")
    if not isinstance(config, Mapping):
        raise ValueError("candidate sweep artifact is missing config")
    config_identity = json.dumps(
        {key: value for key, value in config.items() if key != "top_k"},
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    edge_policy = provenance.get("edge_policy")
    if edge_policy is not None:
        if not isinstance(edge_policy, list):
            raise ValueError("candidate sweep edge_policy must be a list")
        edge_policy = tuple(edge_policy)
    return (
        report["case"],
        report["build"],
        report["profile"],
        report["scope"],
        tuple(provenance[key] for key in required_provenance),
        edge_policy,
        config_identity,
        relation.get("mode"),
        tuple(sorted(target_ids)),
    )


def _sweep_identity_summary(
    report: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    """Expose the checked identity in the persisted sweep report."""

    provenance = report["candidate_artifact"]["provenance"]
    target_ids = candidate_artifact["universe"]["target_ids"]
    encoded_targets = json.dumps(
        sorted(target_ids), ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    relation = candidate_artifact["relation"]
    config = candidate_artifact["config"]
    config_without_k = {
        key: value for key, value in config.items() if key != "top_k"
    }
    edge_policy = provenance.get("edge_policy")
    return {
        "provenance": {
            key: provenance[key]
            for key in (
                "stripped_sha256",
                "body_evidence_sha256",
                "candidate_selection_sha256",
                "raw_graph_sha256",
                "projection_config_sha256",
                "fixture_sha256",
                "track",
                "anchor_policy",
            )
        },
        "relation_mode": relation["mode"],
        "edge_policy": edge_policy,
        "candidate_config": config_without_k,
        "target_count": len(target_ids),
        "target_ids_sha256": hashlib.sha256(encoded_targets).hexdigest(),
    }


def evaluate_candidate_files_sweep(
    candidate_paths: Sequence[str | Path],
    ground_truth_path: str | Path,
) -> dict[str, Any]:
    """Load and evaluate candidate artifacts keyed by their declared top-k."""

    ground_truth = _read_json(ground_truth_path)
    candidates: dict[int, Mapping[str, Any]] = {}
    paths: dict[int, str] = {}
    for path in candidate_paths:
        candidate = _read_json(path)
        config = candidate.get("config")
        if not isinstance(config, Mapping) or not isinstance(config.get("top_k"), int):
            raise ValueError(f"candidate artifact has no valid top_k: {path}")
        top_k = int(config["top_k"])
        if top_k in candidates:
            raise ValueError(f"duplicate candidate sweep top_k: {top_k}")
        candidates[top_k] = candidate
        paths[top_k] = str(path)
    return evaluate_candidate_sweep(candidates, ground_truth, artifact_paths=paths)


def _ground_truth_groups(ground_truth: Mapping[str, Any]) -> dict[str, list[str]]:
    origins = ground_truth.get("origins")
    if not isinstance(origins, list) or not origins:
        raise ValueError("ground truth origins must be a non-empty list")
    result: dict[str, list[str]] = {}
    seen_members: set[str] = set()
    for index, group in enumerate(origins):
        if not isinstance(group, Mapping) or set(group) != {"origin", "members"}:
            raise ValueError(f"ground_truth.origins[{index}] has an invalid schema")
        origin = group["origin"]
        members = group["members"]
        if not isinstance(origin, str) or not origin:
            raise ValueError(f"ground_truth.origins[{index}].origin is invalid")
        if origin in result:
            raise ValueError(f"duplicate ground-truth origin: {origin}")
        if not isinstance(members, list) or any(
            not isinstance(member, str) or not member for member in members
        ):
            raise ValueError(f"ground_truth.origins[{index}].members is invalid")
        if len(set(members)) != len(members):
            raise ValueError(f"duplicate members in ground-truth origin: {origin}")
        overlap = seen_members.intersection(members)
        if overlap:
            raise ValueError(f"ground-truth member appears twice: {sorted(overlap)}")
        seen_members.update(members)
        result[origin] = sorted(members)
    return result


def _ground_truth_index(ground_truth: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for origin, members in _ground_truth_groups(ground_truth).items():
        for member in members:
            result[member] = origin
    return result


def _connected(
    members: list[str],
    adjacency: Mapping[str, set[str]],
) -> bool:
    if len(members) <= 1:
        return True
    seen = {members[0]}
    pending = [members[0]]
    while pending:
        current = pending.pop()
        for neighbor in adjacency.get(current, ()):
            if neighbor not in seen:
                seen.add(neighbor)
                pending.append(neighbor)
    return len(seen) == len(members)


def _validate_metadata(
    candidate: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
) -> None:
    for key in ("case", "build", "profile"):
        if key in ground_truth and ground_truth[key] != candidate[key]:
            raise ValueError(
                f"candidate/ground-truth {key} mismatch: "
                f"{candidate[key]!r} != {ground_truth[key]!r}"
            )
    candidate_provenance = candidate.get("provenance", {})
    gt_provenance = ground_truth.get("provenance", {})
    if isinstance(candidate_provenance, Mapping) and isinstance(gt_provenance, Mapping):
        for key in ("stripped_sha256",):
            expected = candidate_provenance.get(key)
            actual = gt_provenance.get(key)
            if expected and actual and expected != actual:
                raise ValueError(f"candidate/ground-truth {key} mismatch")


def _read_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate F5 candidate recall, reduction, and connectivity."
    )
    parser.add_argument(
        "candidate_artifacts",
        nargs="+",
        help="one artifact, or several top-k artifacts for an automatic sweep",
    )
    parser.add_argument("ground_truth")
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if len(args.candidate_artifacts) == 1:
            report = evaluate_candidate_files(
                args.candidate_artifacts[0], args.ground_truth
            )
        else:
            report = evaluate_candidate_files_sweep(
                args.candidate_artifacts, args.ground_truth
            )
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        else:
            print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        print(f"wrote {args.output}")
    if report["artifact"] == "v1-candidate-sweep-evaluation":
        selection = report["selection"]
        print(f"selected_top_k={selection['selected_top_k']}")
        print(f"gate_b_passed={selection['gate_b_passed']}")
    else:
        print(f"candidate_pair_recall={report['metrics']['candidate_pair_recall']}")
        print(f"candidate_pair_count={report['metrics']['candidate_pair_count']}")
        print(f"gate_b_passed={report['gate_b']['passed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
