from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from body_similarity import (  # noqa: E402
    METRICS,
    body_evidence_sha256,
    compare_bodies,
    load_body_evidence,
)
from paths import normalize_build, normalize_profile, result_dir_for  # noqa: E402


DEFAULT_POSITIVE_ORIGINS = (
    "grep_searcher::searcher::glue::ReadByLine<M,R,S>::run",
    "grep_searcher::line_buffer::LineBuffer::fill",
    "grep_searcher::searcher::core::Core<M,S>::match_by_line",
)
def build_feasibility_report(
    *,
    artifact: dict[str, Any],
    ground_truth: dict[str, Any],
    positive_origins: set[str] | None = None,
    negatives_per_family: int = 32,
    body_evidence_sha256: str = "",
) -> dict[str, Any]:
    _validate_metadata(artifact, ground_truth)
    selected_origins = set(
        DEFAULT_POSITIVE_ORIGINS if positive_origins is None else positive_origins
    )
    origin_by_member, members_by_origin = _ground_truth_index(ground_truth)
    missing_origins = selected_origins - set(members_by_origin)
    if missing_origins:
        raise ValueError(f"positive origins absent from GT: {sorted(missing_origins)}")

    bodies = load_body_evidence(artifact)
    complete_ids = {
        item_id for item_id, body in bodies.items() if body.complete
    }
    positives: list[dict[str, Any]] = []
    for origin in sorted(selected_origins):
        ids = sorted(set(members_by_origin[origin]) & complete_ids)
        positives.extend(_pairs_from_ids(ids, origin=origin, label="positive"))

    negative_target = min(negatives_per_family * len(selected_origins), 10000)
    seed = hashlib.sha256(
        ":".join((
            artifact["case"], artifact["build"], artifact["profile"],
            artifact["scope"],
        )).encode("utf-8")
    ).hexdigest()
    negatives = _matched_negatives(
        bodies,
        complete_ids,
        origin_by_member,
        negative_target,
        random.Random(int(seed[:16], 16)),
    )
    evidence = []
    for pair in positives + negatives:
        first_body = bodies[pair["first"]]
        second_body = bodies[pair["second"]]
        comparison = compare_bodies(
            first_body,
            second_body,
        ).to_dict()
        evidence_slot_consistency = _multiset_jaccard(
            _evidence_slots(first_body),
            _evidence_slots(second_body),
        )
        variation_support = (
            comparison["constant_slot_consistency"]
            + comparison["call_slot_shape_consistency"]
            + evidence_slot_consistency
        ) / 3.0
        slot_adjusted_ratio = min(
            comparison["aligned_instruction_ratio"], variation_support
        )
        evidence.append({
            "pair": comparison.pop("pair"),
            "label": pair["label"],
            "origin": pair["origin"],
            **comparison,
            "evidence_slot_consistency": evidence_slot_consistency,
            "slot_adjusted_aligned_instruction_ratio": (
                slot_adjusted_ratio
            ),
        })
    distributions = {
        metric: {
            label: _distribution(
                [item[metric] for item in evidence if item["label"] == label]
            )
            for label in ("positive", "negative")
        }
        for metric in (*METRICS, "slot_adjusted_aligned_instruction_ratio")
    }
    primary = distributions["aligned_instruction_ratio"]
    secondary = distributions["slot_adjusted_aligned_instruction_ratio"]
    primary_separated = (
        primary["positive"]["count"] > 0
        and primary["negative"]["count"] > 0
        and primary["positive"]["min"] > primary["negative"]["p95"]
    )
    secondary_separated = (
        secondary["positive"]["count"] > 0
        and secondary["negative"]["count"] > 0
        and secondary["positive"]["min"] > secondary["negative"]["p95"]
    )
    if primary_separated:
        decision = "primary-metric-separated"
    elif secondary_separated:
        decision = "secondary-only-separated"
    else:
        decision = "not-separated"

    return {
        "schema_version": 1,
        "case": artifact["case"],
        "build": artifact["build"],
        "profile": artifact["profile"],
        "scope": artifact["scope"],
        "provenance": {
            **artifact["provenance"],
            "body_evidence_sha256": body_evidence_sha256,
            "gt_stripped_sha256": ground_truth["provenance"]["stripped_sha256"],
        },
        "selection": {
            "positive_origins": sorted(selected_origins),
            "negatives_per_positive_family": negatives_per_family,
            "sampling_seed": seed,
            "complete_function_count": len(complete_ids),
            "incomplete_excluded_count": len(bodies) - len(complete_ids),
            "negative_constraints": {
                "distinct_origin": True,
                "minimum_size_ratio": 0.75,
                "minimum_instruction_ratio": 0.75,
                "minimum_block_ratio": 0.75,
            },
        },
        "primary_metric": "aligned_instruction_ratio",
        "secondary_metric": "slot_adjusted_aligned_instruction_ratio",
        # `separated` is intentionally tied to the pre-registered primary
        # metric.  A secondary-only separation is useful evidence, but it is
        # not a primary Gate-A success and must not be reported as one.
        "primary_separated": primary_separated,
        "secondary_separated": secondary_separated,
        "separated": primary_separated,
        "decision": decision,
        "distributions": distributions,
        "pairs": evidence,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare V1 body metrics on GT-labelled diagnostic pairs."
    )
    parser.add_argument("case")
    parser.add_argument("--build", default="O3S")
    parser.add_argument("--profile", default="plain")
    parser.add_argument(
        "--candidate-scope",
        default="rust-nonstd",
        choices=("subject", "rust-nonstd"),
    )
    parser.add_argument("--body-evidence", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--output")
    parser.add_argument(
        "--positive-origin",
        action="append",
        default=None,
        help="repeatable; defaults to the Stage A diagnostic origins",
    )
    parser.add_argument("--negatives-per-family", type=int, default=32)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    build = normalize_build(args.build)
    profile = normalize_profile(args.profile)
    artifact_path = Path(args.body_evidence)
    gt_path = Path(args.ground_truth)
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        ground_truth = json.loads(gt_path.read_text(encoding="utf-8"))
        report = build_feasibility_report(
            artifact=artifact,
            ground_truth=ground_truth,
            positive_origins=(
                set(args.positive_origin)
                if args.positive_origin is not None
                else None
            ),
            negatives_per_family=args.negatives_per_family,
            body_evidence_sha256=body_evidence_sha256(artifact_path),
        )
        output_path = Path(
            args.output
            or (Path(result_dir_for(args.case, profile)) / "v1.feasibility.json")
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    primary = report["distributions"]["aligned_instruction_ratio"]
    secondary = report["distributions"][
        "slot_adjusted_aligned_instruction_ratio"
    ]
    print(f"wrote {output_path}")
    print(
        "positive_min={:.6f} negative_p95={:.6f} separated={}".format(
            primary["positive"]["min"],
            primary["negative"]["p95"],
            report["separated"],
        )
    )
    print(
        "slot_positive_min={:.6f} slot_negative_p95={:.6f} decision={}".format(
            secondary["positive"]["min"],
            secondary["negative"]["p95"],
            report["decision"],
        )
    )
    return 0


def _validate_metadata(
    artifact: dict[str, Any], ground_truth: dict[str, Any]
) -> None:
    if artifact.get("schema_version") != 2:
        raise ValueError("body evidence must use schema version 2")
    for key in ("case", "build", "profile"):
        if artifact.get(key) != ground_truth.get(key):
            raise ValueError(f"{key} mismatch between body evidence and GT")
    # Older GT artifacts intentionally omit scope because the same symbol
    # oracle can be reused for multiple candidate scopes.  When a newer GT
    # artifact records it, reject a mixed-scope join instead of silently
    # comparing different candidate universes.
    if (
        ground_truth.get("scope") is not None
        and artifact.get("scope") != ground_truth.get("scope")
    ):
        raise ValueError("scope mismatch between body evidence and GT")
    body_sha = artifact.get("provenance", {}).get("stripped_sha256")
    gt_sha = ground_truth.get("provenance", {}).get("stripped_sha256")
    if not body_sha or not gt_sha or body_sha != gt_sha:
        raise ValueError("stripped binary SHA mismatch between body evidence and GT")


def _ground_truth_index(
    ground_truth: dict[str, Any],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    origin_by_member: dict[str, str] = {}
    members_by_origin: dict[str, list[str]] = defaultdict(list)
    for origin in ground_truth.get("origins", []):
        name = origin["origin"]
        for member in origin["members"]:
            if member in origin_by_member:
                raise ValueError(f"duplicate GT membership for {member}")
            origin_by_member[member] = name
            members_by_origin[name].append(member)
    return origin_by_member, dict(members_by_origin)


def _pairs_from_ids(
    ids: list[str], *, origin: str, label: str
) -> list[dict[str, str]]:
    return [
        {"first": left, "second": right, "origin": origin, "label": label}
        for index, left in enumerate(ids)
        for right in ids[index + 1:]
    ]


def _matched_negatives(
    bodies: dict[str, Any],
    complete_ids: set[str],
    origin_by_member: dict[str, str],
    target_count: int,
    rng: random.Random,
) -> list[dict[str, str]]:
    if target_count <= 0 or len(complete_ids) < 2:
        return []

    ordered_ids = sorted(complete_ids)
    negatives: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    attempts = 0
    max_attempts = max(target_count * 200, 10000)
    while len(negatives) < target_count and attempts < max_attempts:
        attempts += 1
        left_id, right_id = sorted(rng.sample(ordered_ids, 2))
        if (left_id, right_id) in seen:
            continue
        left, right = bodies[left_id], bodies[right_id]
        if origin_by_member.get(left_id) == origin_by_member.get(right_id):
            continue
        if _ratio(left.size, right.size) < 0.75:
            continue
        if _ratio(len(left.instructions), len(right.instructions)) < 0.75:
            continue
        if _ratio(len(left.blocks), len(right.blocks)) < 0.75:
            continue
        seen.add((left_id, right_id))
        negatives.append({
            "first": left_id,
            "second": right_id,
            "origin": f"{origin_by_member[left_id]} | {origin_by_member[right_id]}",
            "label": "negative",
        })
    if len(negatives) < target_count:
        print(
            f"warning: only {len(negatives)} matched negatives found; "
            f"requested {target_count}",
            file=sys.stderr,
        )
    return negatives


def _ratio(left: int, right: int) -> float:
    denominator = max(left, right)
    return min(left, right) / denominator if denominator else 1.0


def _evidence_slots(body: Any) -> Counter[tuple[Any, ...]]:
    values: Counter[tuple[Any, ...]] = Counter()
    for instruction in body.instructions:
        for slot in instruction.get("slots", []):
            # Local-only comparison excludes call identity/status/resolver.
            if slot.get("kind") == "call":
                continue
            values[(
                slot.get("kind"),
                slot.get("value"),
                slot.get("status"),
                slot.get("resolver"),
            )] += 1
    return values


def _multiset_jaccard(
    left: Counter[tuple[Any, ...]],
    right: Counter[tuple[Any, ...]],
) -> float:
    union = sum((left | right).values())
    return sum((left & right).values()) / union if union else 1.0


def _distribution(values: list[float]) -> dict[str, int | float]:
    ordered = sorted(float(value) for value in values)
    count = len(ordered)
    return {
        "count": count,
        "min": ordered[0] if ordered else 0.0,
        "p05": _quantile(ordered, 0.05),
        "median": _quantile(ordered, 0.50),
        "p95": _quantile(ordered, 0.95),
        "max": ordered[-1] if ordered else 0.0,
    }


def _quantile(values: list[float], probability: float) -> float:
    if not values:
        return 0.0
    position = (len(values) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] * (1.0 - fraction) + values[upper] * fraction


if __name__ == "__main__":
    raise SystemExit(main())
