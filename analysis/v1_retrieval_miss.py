"""Evaluation-only diagnosis for pairs missed by an F5 candidate artifact.

This module explains *why* a bounded retrieval missed same-origin pairs.  It
does not generate candidates and it never passes ground-truth labels to the
F5 or F6 engines.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from body_similarity import FunctionBody, load_body_evidence  # noqa: E402
from engine import CG_WL_MODES, run_cg_wl  # noqa: E402
from loader import load_case  # noqa: E402
from v1_candidates import (  # noqa: E402
    PairKey,
    build_cheap_profiles,
    relation_context_from_cgwl,
    validate_candidate_artifact,
)


RETRIEVAL_SOURCES = {
    "body_top_k",
    "same_final_color",
    "same_prior_round_color",
}


def audit_retrieval(
    candidate_artifact: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
    bodies: Mapping[str, FunctionBody],
    *,
    relation_context: Mapping[str, Any],
    expected_top_k: int | None = 64,
) -> dict[str, Any]:
    """Return per-family diagnostics for a fixed F5 candidate artifact."""

    validate_candidate_artifact(candidate_artifact)
    _validate_metadata(candidate_artifact, ground_truth)
    if expected_top_k is not None:
        actual_top_k = candidate_artifact["config"]["top_k"]
        if actual_top_k != expected_top_k:
            raise ValueError(
                f"retrieval miss audit expects top_k={expected_top_k}, "
                f"got {actual_top_k}"
            )
    target_ids = sorted(candidate_artifact["universe"]["target_ids"])
    target_set = set(target_ids)
    profiles = build_cheap_profiles({
        function_id: bodies[function_id]
        for function_id in target_ids
        if function_id in bodies
    })
    candidate_records = {
        PairKey.make(item["first"], item["second"]): item
        for item in candidate_artifact["pairs"]
    }
    candidate_adjacency: dict[str, set[str]] = {
        function_id: set() for function_id in target_ids
    }
    for pair in candidate_records:
        candidate_adjacency[pair.left].add(pair.right)
        candidate_adjacency[pair.right].add(pair.left)

    final_membership = _membership(relation_context.get("final_groups", ()))
    prior_memberships = [
        (int(round_index), _membership(groups))
        for round_index, groups in relation_context.get("prior_round_groups", ())
    ]
    origins = {
        origin: sorted(set(members) & target_set)
        for origin, members in _ground_truth_groups(ground_truth).items()
        if set(members) & target_set
    }
    origin_by_member = {
        member: origin
        for origin, members in origins.items()
        for member in members
    }
    exact_mnemonic_stats = _exact_mnemonic_bucket_stats(
        profiles,
        origin_by_member,
    )

    family_reports = []
    found_pair_source_counts: Counter[str] = Counter()
    found_pair_count = 0
    missed_pair_count = 0
    same_origin_pair_count = 0
    member_without_candidate_count = 0
    multimember_family_count = 0
    multimember_member_count = 0
    member_without_same_origin_candidate_count = 0
    same_origin_candidate_member_count = 0
    connected_family_count = 0
    exact_hash_pair_count = 0
    found_exact_hash_pair_count = 0
    missed_exact_hash_pair_count = 0
    found_body_pairs: list[Mapping[str, Any]] = []
    missed_body_pairs: list[Mapping[str, Any]] = []

    for origin in sorted(origins):
        members = origins[origin]
        member_set = set(members)
        members_without_candidate = sorted(
            member
            for member in members
            if not candidate_adjacency.get(member)
        )
        member_without_candidate_count += len(members_without_candidate)
        if len(members) > 1:
            multimember_family_count += 1
            multimember_member_count += len(members)
            same_origin_adjacency = {
                member: candidate_adjacency.get(member, set()) & member_set
                for member in members
            }
            members_without_same_origin_candidate = sorted(
                member
                for member, neighbors in same_origin_adjacency.items()
                if not neighbors
            )
            same_origin_member_count = (
                len(members) - len(members_without_same_origin_candidate)
            )
            member_without_same_origin_candidate_count += len(
                members_without_same_origin_candidate
            )
            same_origin_candidate_member_count += same_origin_member_count
        else:
            same_origin_adjacency = {}
            members_without_same_origin_candidate = []
            same_origin_member_count = 0
        pair_reports = []
        source_counts: Counter[str] = Counter()
        family_exact_hash_pair_count = 0
        for first, second in combinations(members, 2):
            same_origin_pair_count += 1
            pair = PairKey.make(first, second)
            record = candidate_records.get(pair)
            found = record is not None
            reasons = sorted(record["reasons"]) if record else []
            retrieval_sources = sorted(set(reasons) & RETRIEVAL_SOURCES)
            source_counts.update(retrieval_sources)
            found_pair_source_counts.update(retrieval_sources)
            body_summary = _body_pair_summary(
                first,
                second,
                bodies.get(first),
                bodies.get(second),
                profiles,
            )
            exact_hash_equal = body_summary["exact_mnemonic_hash_equal"]
            if exact_hash_equal:
                family_exact_hash_pair_count += 1
                exact_hash_pair_count += 1
                if found:
                    found_exact_hash_pair_count += 1
                else:
                    missed_exact_hash_pair_count += 1
            pair_report = {
                "pair": [first, second],
                "found": found,
                "candidate_reasons": reasons,
                "retrieval_sources": retrieval_sources,
                "same_final_color": _same_final(
                    first, second, final_membership,
                    record.get("same_final_color") if record else None,
                ),
                "same_prior_color": _same_prior(
                    first, second, prior_memberships,
                    record.get("same_prior_color") if record else None,
                ),
                "exact_mnemonic_hash_equal": exact_hash_equal,
                "body": body_summary,
            }
            pair_reports.append(pair_report)
            if found:
                found_pair_count += 1
                found_body_pairs.append(body_summary)
            else:
                missed_pair_count += 1
                missed_body_pairs.append(body_summary)

        connected = _connected(members, candidate_adjacency)
        if connected and len(members) > 1:
            connected_family_count += 1
        family_reports.append({
            "origin": origin,
            "members": members,
            "member_count": len(members),
            "members_without_candidate": members_without_candidate,
            "candidate_member_count": len(members) - len(members_without_candidate),
            "members_without_same_origin_candidate": (
                members_without_same_origin_candidate
            ),
            "same_origin_candidate_member_count": same_origin_member_count,
            "same_origin_member_coverage": (
                same_origin_member_count / len(members)
                if len(members) > 1 else None
            ),
            "pair_count": len(pair_reports),
            "found_pair_count": sum(item["found"] for item in pair_reports),
            "missed_pair_count": sum(not item["found"] for item in pair_reports),
            "candidate_graph_edge_count": _internal_edge_count(
                members, candidate_adjacency
            ),
            "candidate_graph_connected": connected,
            "same_exact_mnemonic_hash_pair_count": family_exact_hash_pair_count,
            "same_final_color_pair_count": sum(
                item["same_final_color"] is True for item in pair_reports
            ),
            "same_prior_color_pair_count": sum(
                item["same_prior_color"] is True for item in pair_reports
            ),
            "retrieval_source_counts": dict(sorted(source_counts.items())),
            "found_pair_body_summary": _summarize_bodies(
                [item["body"] for item in pair_reports if item["found"]]
            ),
            "missed_pair_body_summary": _summarize_bodies(
                [item["body"] for item in pair_reports if not item["found"]]
            ),
            "pairs": pair_reports,
        })

    total_pair_count = len(target_ids) * (len(target_ids) - 1) // 2
    candidate_pair_count = len(candidate_records)
    candidate_pair_fraction = (
        candidate_pair_count / total_pair_count if total_pair_count else 0.0
    )
    return {
        "schema_version": 1,
        "artifact": "v1-retrieval-miss-audit",
        "case": candidate_artifact["case"],
        "build": candidate_artifact["build"],
        "profile": candidate_artifact["profile"],
        "scope": candidate_artifact["scope"],
        "input": {
            "candidate_top_k": candidate_artifact["config"]["top_k"],
            "ground_truth_used_for": "labels and diagnostics only",
            "body_evidence_used_for": "local feature measurements only",
            "relation_used_for": "final/prior color diagnostics only",
        },
        "provenance": dict(candidate_artifact.get("provenance", {})),
        "relation": {
            "mode": relation_context.get("mode"),
            "rounds": relation_context.get("rounds"),
            "final_round": relation_context.get("final_round"),
            "prior_round_count": len(prior_memberships),
        },
        "universe": {
            "target_count": len(target_ids),
            "body_count": len(profiles),
            "missing_body_ids": sorted(target_set - set(profiles)),
            "incomplete_body_ids": sorted(
                function_id
                for function_id, body in bodies.items()
                if function_id in target_set and not body.complete
            ),
        },
        "metrics": {
            "family_count": len(family_reports),
            "same_origin_pair_count": same_origin_pair_count,
            "found_same_origin_pair_count": found_pair_count,
            "missed_same_origin_pair_count": missed_pair_count,
            "candidate_pair_recall": (
                found_pair_count / same_origin_pair_count
                if same_origin_pair_count else None
            ),
            "total_pair_count": total_pair_count,
            "candidate_pair_count": candidate_pair_count,
            "candidate_pair_fraction": candidate_pair_fraction,
            "member_without_candidate_count": member_without_candidate_count,
            "connected_family_count": connected_family_count,
            "multimember_family_count": multimember_family_count,
            "multimember_member_count": multimember_member_count,
            "member_without_same_origin_candidate_count": (
                member_without_same_origin_candidate_count
            ),
            "same_origin_candidate_member_count": same_origin_candidate_member_count,
            "same_origin_member_coverage": (
                same_origin_candidate_member_count / multimember_member_count
                if multimember_member_count else None
            ),
            "connected_family_rate": (
                connected_family_count / multimember_family_count
                if multimember_family_count else None
            ),
            "all_multimember_families_connected": (
                connected_family_count == multimember_family_count
            ),
            "same_exact_mnemonic_hash_pair_count": exact_hash_pair_count,
            "found_same_exact_mnemonic_hash_pair_count": found_exact_hash_pair_count,
            "missed_same_exact_mnemonic_hash_pair_count": missed_exact_hash_pair_count,
            **exact_mnemonic_stats,
            "retrieval_source_counts": dict(sorted(found_pair_source_counts.items())),
            "found_pair_body_summary": _summarize_bodies(found_body_pairs),
            "missed_pair_body_summary": _summarize_bodies(missed_body_pairs),
        },
        "families": family_reports,
    }


def audit_retrieval_files(
    candidate_path: str | Path,
    ground_truth_path: str | Path,
    body_path: str | Path,
    fixture_path: str | Path,
    *,
    expected_top_k: int | None = 64,
) -> dict[str, Any]:
    candidate = _read_json(candidate_path)
    ground_truth = _read_json(ground_truth_path)
    bodies = load_body_evidence(body_path)
    case = load_case(str(fixture_path))
    mode = candidate.get("relation", {}).get("mode", "out-in")
    if mode not in CG_WL_MODES:
        raise ValueError(f"candidate relation mode is invalid: {mode!r}")
    relation = relation_context_from_cgwl(
        case,
        run_cg_wl(case, mode=mode, trace=True),
    )
    return audit_retrieval(
        candidate,
        ground_truth,
        bodies,
        relation_context=relation,
        expected_top_k=expected_top_k,
    )


def _body_pair_summary(
    first_id: str,
    second_id: str,
    first: FunctionBody | None,
    second: FunctionBody | None,
    profiles: Mapping[str, Any],
) -> dict[str, Any]:
    if first is None or second is None:
        return {
            "available": False,
            "complete": False,
            "exact_mnemonic_hash_equal": None,
            "size_difference": None,
            "instruction_count_difference": None,
            "block_count_difference": None,
            "size_ratio": None,
            "instruction_count_ratio": None,
            "block_count_ratio": None,
            "mnemonic_ngram_jaccard": None,
        }
    first_profile = profiles.get(first_id)
    second_profile = profiles.get(second_id)
    return {
        "available": True,
        "complete": first.complete and second.complete,
        "exact_mnemonic_hash_equal": (
            first_profile.exact_mnemonic_hash == second_profile.exact_mnemonic_hash
        ),
        "size_first": first_profile.size,
        "size_second": second_profile.size,
        "size_difference": abs(first_profile.size - second_profile.size),
        "instruction_count_first": first_profile.instruction_count,
        "instruction_count_second": second_profile.instruction_count,
        "instruction_count_difference": abs(
            first_profile.instruction_count - second_profile.instruction_count
        ),
        "block_count_first": first_profile.block_count,
        "block_count_second": second_profile.block_count,
        "block_count_difference": abs(
            first_profile.block_count - second_profile.block_count
        ),
        "size_ratio": _ratio(first_profile.size, second_profile.size),
        "instruction_count_ratio": _ratio(
            first_profile.instruction_count, second_profile.instruction_count
        ),
        "block_count_ratio": _ratio(
            first_profile.block_count, second_profile.block_count
        ),
        "mnemonic_ngram_jaccard": _set_jaccard(
            first_profile.mnemonic_ngrams,
            second_profile.mnemonic_ngrams,
        ),
    }


def _summarize_bodies(items: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    items = list(items)
    result: dict[str, Any] = {"count": len(items)}
    for key in (
        "size_difference",
        "instruction_count_difference",
        "block_count_difference",
        "size_ratio",
        "instruction_count_ratio",
        "block_count_ratio",
        "mnemonic_ngram_jaccard",
    ):
        values = [item[key] for item in items if item.get(key) is not None]
        result[key] = {
            "min": min(values) if values else None,
            "mean": statistics.fmean(values) if values else None,
            "median": statistics.median(values) if values else None,
            "p75": _percentile(values, 0.75),
            "p90": _percentile(values, 0.90),
            "max": max(values) if values else None,
        }
    return result


def _exact_mnemonic_bucket_stats(
    profiles: Mapping[str, Any],
    origin_by_member: Mapping[str, str],
) -> dict[str, int]:
    """Count exact-mnemonic collisions without expanding their pair buckets.

    ``exact_mnemonic_all_pair_count`` describes every body function in the
    audit universe.  The cross-origin value is restricted to functions with a
    ground-truth label, so an unlabeled body is not silently treated as a
    different origin.
    """

    buckets: dict[str, list[str]] = defaultdict(list)
    for function_id, profile in profiles.items():
        buckets[profile.exact_mnemonic_hash].append(function_id)

    largest_bucket = max((len(members) for members in buckets.values()), default=0)
    all_pair_count = sum(
        len(members) * (len(members) - 1) // 2
        for members in buckets.values()
    )

    same_origin_pair_count = 0
    labeled_pair_count = 0
    for members in buckets.values():
        counts = Counter(
            origin_by_member[member]
            for member in members
            if member in origin_by_member
        )
        labeled_count = sum(counts.values())
        labeled_pair_count += labeled_count * (labeled_count - 1) // 2
        same_origin_pair_count += sum(
            count * (count - 1) // 2
            for count in counts.values()
        )

    return {
        "largest_exact_mnemonic_bucket_size": largest_bucket,
        "exact_mnemonic_all_pair_count": all_pair_count,
        "exact_mnemonic_labeled_pair_count": labeled_pair_count,
        "exact_mnemonic_same_origin_pair_count": same_origin_pair_count,
        "exact_mnemonic_cross_origin_pair_count": (
            labeled_pair_count - same_origin_pair_count
        ),
    }


def _percentile(values: Iterable[float], quantile: float) -> float | None:
    """Inclusive linear percentile without a dependency on NumPy."""

    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _membership(groups: Iterable[Iterable[str]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for index, group in enumerate(groups):
        for function_id in group:
            result[function_id] = index
    return result


def _same_final(
    first: str,
    second: str,
    membership: Mapping[str, int],
    artifact_value: bool | None,
) -> bool | None:
    if first in membership and second in membership:
        return membership[first] == membership[second]
    return artifact_value


def _same_prior(
    first: str,
    second: str,
    memberships: Iterable[tuple[int, Mapping[str, int]]],
    artifact_value: bool | None,
) -> bool | None:
    available = False
    for _round_index, membership in memberships:
        if first in membership and second in membership:
            available = True
            if membership[first] == membership[second]:
                return True
    return False if available else artifact_value


def _connected(members: list[str], adjacency: Mapping[str, set[str]]) -> bool:
    if len(members) <= 1:
        return True
    seen = {members[0]}
    pending = [members[0]]
    while pending:
        current = pending.pop()
        for neighbor in adjacency.get(current, ()):
            if neighbor in members and neighbor not in seen:
                seen.add(neighbor)
                pending.append(neighbor)
    return len(seen) == len(members)


def _internal_edge_count(
    members: list[str],
    adjacency: Mapping[str, set[str]],
) -> int:
    member_set = set(members)
    return sum(
        len(adjacency.get(member, ()) & member_set)
        for member in members
    ) // 2


def _ratio(first: int, second: int) -> float:
    denominator = max(first, second)
    return min(first, second) / denominator if denominator else 1.0


def _set_jaccard(first: Iterable[Any], second: Iterable[Any]) -> float:
    left, right = set(first), set(second)
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _ground_truth_groups(ground_truth: Mapping[str, Any]) -> dict[str, list[str]]:
    origins = ground_truth.get("origins")
    if not isinstance(origins, list) or not origins:
        raise ValueError("ground truth origins must be a non-empty list")
    result: dict[str, list[str]] = {}
    seen: set[str] = set()
    for item in origins:
        if not isinstance(item, Mapping):
            raise ValueError("ground truth origin must be an object")
        origin, members = item.get("origin"), item.get("members")
        if not isinstance(origin, str) or not origin:
            raise ValueError("ground truth origin is invalid")
        if origin in result or not isinstance(members, list):
            raise ValueError("duplicate or invalid ground truth origin")
        if any(not isinstance(member, str) or not member for member in members):
            raise ValueError("ground truth member is invalid")
        if len(set(members)) != len(members):
            raise ValueError("ground truth origin contains duplicate members")
        if seen.intersection(members):
            raise ValueError("ground truth member appears in multiple origins")
        seen.update(members)
        result[origin] = sorted(members)
    return result


def _validate_metadata(
    candidate: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
) -> None:
    for key in ("case", "build", "profile"):
        if key in ground_truth and ground_truth[key] != candidate[key]:
            raise ValueError(f"candidate/ground-truth {key} mismatch")
    candidate_provenance = candidate.get("provenance", {})
    gt_provenance = ground_truth.get("provenance", {})
    if isinstance(candidate_provenance, Mapping) and isinstance(gt_provenance, Mapping):
        expected = candidate_provenance.get("stripped_sha256")
        actual = gt_provenance.get("stripped_sha256")
        if expected and actual and expected != actual:
            raise ValueError("candidate/ground-truth stripped binary mismatch")


def _read_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Diagnose F5 same-origin pairs missed by a candidate artifact."
    )
    parser.add_argument("candidate_artifact")
    parser.add_argument("ground_truth")
    parser.add_argument("--body-evidence", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--expected-top-k", type=int, default=64)
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = audit_retrieval_files(
            args.candidate_artifact,
            args.ground_truth,
            args.body_evidence,
            args.fixture,
            expected_top_k=args.expected_top_k,
        )
        encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(encoded, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(encoded, end="")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    metrics = report["metrics"]
    print(
        f"families={metrics['family_count']} "
        f"found={metrics['found_same_origin_pair_count']} "
        f"missed={metrics['missed_same_origin_pair_count']} "
        f"recall={metrics['candidate_pair_recall']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
