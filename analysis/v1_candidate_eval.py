"""Evaluation-only metrics for an F5 candidate-pair artifact.

Ground truth is intentionally confined to this module.  ``v1_candidates``
and the F6 engine can therefore be run on a binary without knowing source
origins; this file only measures recall, reduction, and family connectivity
after the candidate set has been fixed.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Mapping


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

    all_pairs = list(combinations(labeled_ids, 2))
    same_origin_pairs = {
        PairKey.make(first, second)
        for first, second in all_pairs
        if origin_by_member[first] == origin_by_member[second]
    }
    candidate_labeled_pairs = {
        pair for pair in candidate_pairs
        if pair.left in origin_by_member and pair.right in origin_by_member
    }
    candidate_same_pairs = candidate_labeled_pairs & same_origin_pairs
    candidate_pair_recall = (
        len(candidate_same_pairs) / len(same_origin_pairs)
        if same_origin_pairs else None
    )
    total_pair_count = len(target_ids) * (len(target_ids) - 1) // 2
    candidate_pair_count = len(candidate_pairs)
    candidate_pair_fraction = (
        candidate_pair_count / total_pair_count if total_pair_count else 0.0
    )

    family_reports = []
    for origin in sorted(origins):
        members = origins[origin]
        member_set = set(members)
        internal_edges = {
            pair for pair in candidate_pairs
            if pair.left in member_set and pair.right in member_set
        }
        adjacency = {member: set() for member in members}
        for pair in internal_edges:
            adjacency[pair.left].add(pair.right)
            adjacency[pair.right].add(pair.left)
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
            "candidate_same_pair_count": len(internal_edges),
            "connected": connected,
        })

    coverage_values = [item["member_coverage"] for item in family_reports]
    connectivity_values = [item["connected"] for item in family_reports]
    member_coverage_summary = {
        "count": len(coverage_values),
        "min": min(coverage_values) if coverage_values else None,
        "mean": statistics.fmean(coverage_values) if coverage_values else None,
        "all_ge_0.95": bool(coverage_values) and min(coverage_values) >= 0.95,
    }
    all_connected = bool(connectivity_values) and all(connectivity_values)
    metrics = {
        "target_count": len(target_ids),
        "labeled_target_count": len(labeled_ids),
        "missing_gt_member_count": len(missing_gt_members),
        "total_pair_count": total_pair_count,
        "candidate_pair_count": candidate_pair_count,
        "candidate_pair_fraction": candidate_pair_fraction,
        "pair_reduction": 1.0 - candidate_pair_fraction,
        "same_origin_pair_count": len(same_origin_pairs),
        "candidate_same_origin_pair_count": len(candidate_same_pairs),
        "candidate_pair_recall": candidate_pair_recall,
        "expected_detailed_comparisons": candidate_pair_count,
        "reason_counts": dict(sorted(reason_counts.items())),
        "family_count": len(family_reports),
        "family_member_coverage": member_coverage_summary,
        "all_multimember_families_connected": all_connected,
    }
    gate = {
        "candidate_pair_recall_ge_0.90": (
            candidate_pair_recall is not None and candidate_pair_recall >= 0.90
        ),
        "candidate_pair_fraction_le_0.02": candidate_pair_fraction <= 0.02,
        "family_member_coverage_ge_0.95": member_coverage_summary["all_ge_0.95"],
        "all_multimember_families_connected": all_connected,
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
    parser.add_argument("candidate_artifact")
    parser.add_argument("ground_truth")
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = evaluate_candidate_files(args.candidate_artifact, args.ground_truth)
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
    print(f"candidate_pair_recall={report['metrics']['candidate_pair_recall']}")
    print(f"candidate_pair_count={report['metrics']['candidate_pair_count']}")
    print(f"gate_b_passed={report['gate_b']['passed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
