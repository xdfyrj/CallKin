"""Evaluation-only pair and family metrics for the F6 artifact."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from linkage_overlay import load_overlay, score_labeled_pairs  # noqa: E402
from v1_candidates import PairKey  # noqa: E402
from v1_engine import (  # noqa: E402
    DECISIONS,
    PairFeatures,
    PairPolicyConfig,
    classify_pair,
)


MATCH_THRESHOLD_GRID = (0.80, 0.90, 0.95, 1.00)
SLOT_THRESHOLD_GRID = (0.80, 1.00)
REJECT_THRESHOLD_GRID: tuple[float | None, ...] = (None, 0.00, 0.10, 0.20, 0.30)


def evaluate_family_artifact(
    family_artifact: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
    linkage_audit: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Score accepted F6 families against GT after grouping is complete.

    Supplying the linkage audit adds `linkage_metrics`, which sets aside pairs
    the binary cannot decide: two emissions of one mono item, and addresses
    standing for several source origins.
    """

    _validate_family_artifact(family_artifact)
    _validate_metadata(family_artifact, ground_truth)
    target_ids = list(family_artifact["universe"]["target_ids"])
    origin_by_member, gt_groups = _ground_truth_index(ground_truth)
    labeled_ids = sorted(set(target_ids) & set(origin_by_member))
    accepted_clusters = [
        sorted(item["members"])
        for item in family_artifact["clusters"]
        if item["status"] == "accepted"
    ]
    raw_predicted_pairs = {
        PairKey.make(first, second)
        for cluster in accepted_clusters
        for first, second in combinations(cluster, 2)
    }
    all_pairs = {
        PairKey.make(first, second)
        for first, second in combinations(labeled_ids, 2)
    }
    positive_pairs = {
        pair for pair in all_pairs
        if origin_by_member[pair.left] == origin_by_member[pair.right]
    }
    predicted_pairs = raw_predicted_pairs & all_pairs
    tp = len(predicted_pairs & positive_pairs)
    fp = len(predicted_pairs - positive_pairs)
    fn = len(positive_pairs - predicted_pairs)
    tn = len(all_pairs - predicted_pairs - positive_pairs)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )

    linkage_metrics = None
    if linkage_audit is not None:
        origins_by_address, identities_by_address = load_overlay(linkage_audit)
        linkage_metrics = score_labeled_pairs(
            [(pair.left, pair.right) for pair in all_pairs],
            [(pair.left, pair.right) for pair in predicted_pairs],
            origins_by_address=origins_by_address,
            identities_by_address=identities_by_address,
        )

    decision_counts: Counter[str] = Counter()
    decision_confusion: Counter[tuple[str, str]] = Counter()
    for item in family_artifact["pair_decisions"]:
        decision = item["decision"]
        decision_counts[decision] += 1
        pair_values = item["pair"]
        pair = PairKey.make(pair_values[0], pair_values[1])
        if pair.left in origin_by_member and pair.right in origin_by_member:
            label = (
                "same-origin"
                if origin_by_member[pair.left] == origin_by_member[pair.right]
                else "different-origin"
            )
            decision_confusion[(decision, label)] += 1

    # Two coverage notions are intentionally separated.  A member appearing
    # in any accepted cluster is only *participation*; if that cluster mixes
    # origins it is not a correctly recovered family member.  The latter is
    # the coverage used for research claims.
    accepted_coverage = []
    for origin, members in sorted(gt_groups.items()):
        member_set = set(members) & set(target_ids)
        participating = set()
        correctly_accepted = set()
        exact_family = False
        for cluster in accepted_clusters:
            cluster_set = set(cluster)
            participating.update(member_set & cluster_set)
            if cluster_set and cluster_set.issubset(member_set):
                correctly_accepted.update(cluster_set)
            if cluster_set == member_set and member_set:
                exact_family = True
        accepted_coverage.append({
            "origin": origin,
            "member_count": len(member_set),
            "accepted_participation_count": len(participating),
            "accepted_participation_coverage": (
                len(participating) / len(member_set) if member_set else 1.0
            ),
            "correctly_accepted_member_count": len(correctly_accepted),
            "correct_member_coverage": (
                len(correctly_accepted) / len(member_set) if member_set else 1.0
            ),
            "exact_family_recovered": exact_family,
        })
    participation_count = sum(
        item["accepted_participation_count"] for item in accepted_coverage
    )
    correct_member_count = sum(
        item["correctly_accepted_member_count"] for item in accepted_coverage
    )
    exact_family_count = sum(
        item["exact_family_recovered"] for item in accepted_coverage
    )
    return {
        "schema_version": 1,
        "artifact": "v1-family-evaluation",
        "case": family_artifact["case"],
        "build": family_artifact["build"],
        "profile": family_artifact["profile"],
        "scope": family_artifact["scope"],
        "linkage_metrics": linkage_metrics,
        "ground_truth": {
            "used_for": "evaluation labels only",
            "origin_count": len(gt_groups),
            "missing_member_ids": sorted(set(target_ids) - set(origin_by_member)),
        },
        "metrics": {
            "target_count": len(target_ids),
            "labeled_target_count": len(labeled_ids),
            "total_pair_count": len(all_pairs),
            "predicted_pair_count": len(predicted_pairs),
            "predicted_unlabeled_pair_count": len(raw_predicted_pairs - all_pairs),
            "accepted_family_count": len(accepted_clusters),
            "accepted_cluster_member_count": sum(
                len(cluster) for cluster in accepted_clusters
            ),
            "accepted_participation_member_count": participation_count,
            "correctly_accepted_member_count": correct_member_count,
            "exact_family_recovered_count": exact_family_count,
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "TN": tn,
            "Precision": precision,
            "Recall": recall,
            "F1": f1,
            "decision_counts": dict(sorted(decision_counts.items())),
            "decision_confusion": {
                f"{decision}|{label}": count
                for (decision, label), count in sorted(decision_confusion.items())
            },
        },
        "accepted_family_coverage": accepted_coverage,
        "provenance": family_artifact.get("provenance", {}),
    }


def evaluate_family_files(
    family_path: str | Path,
    ground_truth_path: str | Path,
    linkage_audit_path: str | Path | None = None,
) -> dict[str, Any]:
    return evaluate_family_artifact(
        _read_json(family_path),
        _read_json(ground_truth_path),
        None if linkage_audit_path is None else _read_json(linkage_audit_path),
    )


def select_development_policy(
    family_artifact: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    ground_truth: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    artifact_paths: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Select F6 thresholds on one or more development artifacts.

    The artifacts must contain the pair features produced by F6.  GT labels
    are combined only inside this evaluation helper; the engine remains GT
    free.  After selection, the caller must rerun ``v1_engine.py`` with the
    returned policy before evaluating a held-out test case.
    """

    artifacts = (
        [family_artifact]
        if isinstance(family_artifact, Mapping)
        else list(family_artifact)
    )
    truths = (
        [ground_truth]
        if isinstance(ground_truth, Mapping)
        else list(ground_truth)
    )
    if len(artifacts) != len(truths) or not artifacts:
        raise ValueError("development artifacts and GT files must have equal non-zero length")
    if artifact_paths is not None and len(artifact_paths) != len(artifacts):
        raise ValueError("development artifact path count mismatch")

    rows = []
    development_cases = []
    for index, (artifact, truth) in enumerate(zip(artifacts, truths)):
        _validate_family_artifact(artifact)
        _validate_metadata(artifact, truth)
        origin_by_member, _groups = _ground_truth_index(truth)
        case_rows = 0
        excluded_pair_count = 0
        for item in artifact["pair_decisions"]:
            # Thresholds must be selected from a fixed, policy-independent
            # sample.  On-demand pairs are created only after an engine has
            # already made a policy-dependent decision (for example during
            # complete-link validation), so including them would leak the
            # previous policy into the development split.
            source = item.get("source")
            if source is None:
                raise ValueError(
                    "development pair decision is missing source; "
                    "regenerate the family artifact with the current F6 schema"
                )
            if source != "candidate":
                excluded_pair_count += 1
                continue
            values = item["pair"]
            pair = PairKey.make(values[0], values[1])
            if pair.left not in origin_by_member or pair.right not in origin_by_member:
                continue
            rows.append((
                _features_from_dict(item["features"]),
                origin_by_member[pair.left] == origin_by_member[pair.right],
            ))
            case_rows += 1
        development_cases.append({
            "case": artifact["case"],
            "build": artifact["build"],
            "profile": artifact["profile"],
            "scope": artifact["scope"],
            "pair_count": case_rows,
            "candidate_pair_count": case_rows,
            "excluded_non_candidate_pair_count": excluded_pair_count,
        })
        if artifact_paths is not None:
            development_cases[-1]["artifact"] = artifact_paths[index]
    if not rows:
        raise ValueError("development artifact has no GT-labeled pair features")

    candidates = []
    for structure_threshold in MATCH_THRESHOLD_GRID:
        for slot_threshold in SLOT_THRESHOLD_GRID:
            for reject_threshold in REJECT_THRESHOLD_GRID:
                config = PairPolicyConfig(
                    structure_match_threshold=structure_threshold,
                    slot_match_threshold=slot_threshold,
                    structure_reject_threshold=reject_threshold,
                )
                decisions = [classify_pair(features, config) for features, _ in rows]
                same_labels = [same for _features, same in rows]
                match_indices = [index for index, decision in enumerate(decisions) if decision == "match"]
                match_tp = sum(same_labels[index] for index in match_indices)
                match_fp = len(match_indices) - match_tp
                match_fn = sum(
                    same and decisions[index] != "match"
                    for index, same in enumerate(same_labels)
                )
                match_precision = (
                    match_tp / (match_tp + match_fp)
                    if match_tp + match_fp else 1.0
                )
                match_recall = (
                    match_tp / (match_tp + match_fn)
                    if match_tp + match_fn else 0.0
                )
                reject_indices = [index for index, decision in enumerate(decisions) if decision == "reject"]
                reject_correct = sum(not same_labels[index] for index in reject_indices)
                reject_precision = (
                    reject_correct / len(reject_indices) if reject_indices else 1.0
                )
                unknown_count = sum(
                    decision in {"unknown", "abstain"} for decision in decisions
                )
                if match_precision < 0.95 or reject_precision < 0.95:
                    continue
                candidates.append({
                    "config": config,
                    "match_precision": match_precision,
                    "match_recall": match_recall,
                    "reject_precision": reject_precision,
                    "unknown_count": unknown_count,
                })
    if not candidates:
        raise ValueError("no F6 threshold configuration satisfies development precision gates")
    candidates.sort(
        key=lambda item: (
            -item["match_recall"],
            item["unknown_count"],
            -item["config"].structure_match_threshold,
            -item["config"].slot_match_threshold,
            0 if item["config"].structure_reject_threshold is None else 1,
            item["config"].structure_reject_threshold or 0.0,
        )
    )
    selected = candidates[0]
    return {
        "schema_version": 1,
        "version": "v1",
        "selection_split": "development",
        "pair_source": "candidate-only",
        "development_cases": development_cases,
        "development_pair_count": len(rows),
        "policy": selected["config"].to_dict() | {
            "source": "development-grid",
        },
        "development_metrics": {
            key: selected[key]
            for key in (
                "match_precision",
                "match_recall",
                "reject_precision",
                "unknown_count",
            )
        },
        "grid": {
            "structure_match_threshold": list(MATCH_THRESHOLD_GRID),
            "slot_match_threshold": list(SLOT_THRESHOLD_GRID),
            "structure_reject_threshold": list(REJECT_THRESHOLD_GRID),
        },
    }


def select_development_policy_files(
    pairs: Sequence[tuple[str | Path, str | Path]],
) -> dict[str, Any]:
    """Load several ``(family artifact, GT)`` development pairs."""

    if not pairs:
        raise ValueError("at least one development pair is required")
    artifacts = [_read_json(artifact_path) for artifact_path, _ in pairs]
    truths = [_read_json(gt_path) for _, gt_path in pairs]
    return select_development_policy(
        artifacts,
        truths,
        artifact_paths=[str(artifact_path) for artifact_path, _ in pairs],
    )


def _validate_family_artifact(artifact: Mapping[str, Any]) -> None:
    required = {
        "schema_version", "artifact", "case", "build", "profile", "scope",
        "config", "provenance", "universe", "clusters", "status_members",
        "pair_decisions", "blocked_merges", "metrics",
    }
    if not isinstance(artifact, Mapping) or not required.issubset(artifact):
        raise ValueError("invalid v1 family artifact")
    if artifact["schema_version"] != 1 or artifact["artifact"] != "v1-family-grouping":
        raise ValueError("unsupported v1 family artifact")
    target_ids = artifact["universe"].get("target_ids")
    if not isinstance(target_ids, list) or len(set(target_ids)) != len(target_ids):
        raise ValueError("family artifact target_ids are invalid")
    status_members = artifact["status_members"]
    if set(status_members) != {"accepted", "provisional", "unresolved", "abstain"}:
        raise ValueError("family artifact statuses are invalid")
    buckets = [set(status_members[name]) for name in status_members]
    if any(left & right for index, left in enumerate(buckets) for right in buckets[index + 1:]):
        raise ValueError("family artifact status buckets overlap")
    if set().union(*buckets) != set(target_ids):
        raise ValueError("family artifact statuses do not cover target_ids")
    if not isinstance(artifact["pair_decisions"], list):
        raise ValueError("family artifact pair_decisions must be a list")
    for item in artifact["pair_decisions"]:
        if item.get("decision") not in DECISIONS:
            raise ValueError("unknown family pair decision")


def _features_from_dict(value: Mapping[str, Any]) -> PairFeatures:
    pair_values = value.get("pair")
    if not isinstance(pair_values, list) or len(pair_values) != 2:
        raise ValueError("pair feature record has an invalid pair")
    pair = PairKey.make(pair_values[0], pair_values[1])
    required = {
        "structure_score",
        "aligned_instruction_ratio",
        "sequence_ratio",
        "mnemonic_multiset_jaccard",
        "constant_similarity",
        "call_shape_similarity",
        "data_reference_similarity",
        "same_final_color",
        "same_prior_color",
        "same_out_signature",
        "same_in_signature",
        "both_complete",
        "opaque_indirect_jumps",
    }
    if not required.issubset(value):
        raise ValueError("pair feature record is incomplete")
    return PairFeatures(
        pair=pair,
        structure_score=float(value["structure_score"]),
        aligned_instruction_ratio=float(value["aligned_instruction_ratio"]),
        sequence_ratio=float(value["sequence_ratio"]),
        mnemonic_multiset_jaccard=float(value["mnemonic_multiset_jaccard"]),
        constant_similarity=value["constant_similarity"],
        call_shape_similarity=value["call_shape_similarity"],
        data_reference_similarity=value["data_reference_similarity"],
        same_final_color=value["same_final_color"],
        same_prior_color=value["same_prior_color"],
        same_out_signature=value["same_out_signature"],
        same_in_signature=value["same_in_signature"],
        both_complete=bool(value["both_complete"]),
        opaque_indirect_jumps=int(value["opaque_indirect_jumps"]),
    )


def _ground_truth_index(
    ground_truth: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    origins = ground_truth.get("origins")
    if not isinstance(origins, list) or not origins:
        raise ValueError("ground truth origins must be a non-empty list")
    index: dict[str, str] = {}
    groups: dict[str, list[str]] = {}
    for item in origins:
        if not isinstance(item, Mapping) or set(item) != {"origin", "members"}:
            raise ValueError("invalid ground truth origin")
        origin = item["origin"]
        members = item["members"]
        if not isinstance(origin, str) or not origin:
            raise ValueError("invalid ground truth origin name")
        if origin in groups or not isinstance(members, list):
            raise ValueError("duplicate or invalid ground truth origin")
        groups[origin] = sorted(members)
        for member in members:
            if not isinstance(member, str) or not member or member in index:
                raise ValueError("invalid or duplicate ground truth member")
            index[member] = origin
    return index, groups


def _validate_metadata(
    artifact: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
) -> None:
    for key in ("case", "build", "profile"):
        if key in ground_truth and ground_truth[key] != artifact[key]:
            raise ValueError(f"family/ground-truth {key} mismatch")
    artifact_provenance = artifact.get("provenance", {})
    gt_provenance = ground_truth.get("provenance", {})
    if isinstance(artifact_provenance, Mapping) and isinstance(gt_provenance, Mapping):
        expected = artifact_provenance.get("stripped_sha256")
        actual = gt_provenance.get("stripped_sha256")
        if expected and actual and expected != actual:
            raise ValueError("family/ground-truth stripped binary mismatch")


def _read_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate F6 family grouping.")
    parser.add_argument("family_artifact")
    parser.add_argument("ground_truth")
    parser.add_argument("--output")
    parser.add_argument(
        "--linkage-audit",
        help="gt-mangled-audit artifact; adds primary and source-origin metrics "
             "that set aside pairs the binary cannot decide",
    )
    parser.add_argument(
        "--development-config-output",
        help="select thresholds on this development artifact and write a policy JSON",
    )
    parser.add_argument(
        "--development-pair",
        action="append",
        nargs=2,
        metavar=("FAMILY_ARTIFACT", "GROUND_TRUTH"),
        help=(
            "add another (family artifact, GT) development pair; the two "
            "positional files are always included"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = evaluate_family_files(
            args.family_artifact, args.ground_truth, args.linkage_audit
        )
        encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(encoded, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(encoded, end="")
        if args.development_config_output:
            development_pairs = [(args.family_artifact, args.ground_truth)]
            development_pairs.extend(tuple(item) for item in (args.development_pair or []))
            selected = select_development_policy_files(development_pairs)
            destination = Path(args.development_config_output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(selected, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"wrote development policy {args.development_config_output}")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    metrics = report["metrics"]
    print(
        f"TP={metrics['TP']} FP={metrics['FP']} "
        f"FN={metrics['FN']} TN={metrics['TN']} F1={metrics['F1']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
