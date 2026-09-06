"""Compare independent F5.2 retrieval views on one labelled corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from v1_candidates import PairKey, validate_candidate_artifact  # noqa: E402
from analysis.v1_candidate_eval import (  # noqa: E402
    _ground_truth_index,
    evaluate_candidate_artifact,
)


def evaluate_multiview_artifacts(
    artifacts: Mapping[str, Mapping[str, Any]],
    ground_truth: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate view-only and union artifacts without changing retrieval."""

    if not artifacts:
        raise ValueError("at least one multiview artifact is required")
    reports: dict[str, dict[str, Any]] = {}
    pair_sets: dict[str, set[PairKey]] = {}
    identity: tuple[Any, ...] | None = None
    for name in sorted(artifacts):
        artifact = artifacts[name]
        validate_candidate_artifact(artifact)
        report = evaluate_candidate_artifact(artifact, ground_truth)
        current_identity = _artifact_identity(report, artifact)
        if identity is None:
            identity = current_identity
        elif current_identity != identity:
            raise ValueError("multiview artifacts do not share the same universe")
        reports[name] = report
        pair_sets[name] = {
            PairKey.make(item["first"], item["second"])
            for item in artifact["pairs"]
        }

    single_view_names = [
        name
        for name in sorted(artifacts)
        if _artifact_views(artifacts[name]) and len(_artifact_views(artifacts[name])) == 1
    ]
    variants = []
    for name in sorted(reports):
        report = reports[name]
        artifact = artifacts[name]
        metrics = report["metrics"]
        other_single_pairs = set().union(
            *(pair_sets[other] for other in single_view_names if other != name)
        ) if single_view_names else set()
        own_pairs = pair_sets[name]
        exclusive_pairs = own_pairs - other_single_pairs
        exclusive_same_origin = _same_origin_count(
            exclusive_pairs,
            _ground_truth_index(ground_truth),
        )
        variants.append({
            "name": name,
            "views": _artifact_views(artifact),
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
                "reason_counts": metrics["reason_counts"],
                "exclusive_candidate_pair_count": len(exclusive_pairs),
                "exclusive_same_origin_pair_count": exclusive_same_origin,
            },
        })

    return {
        "schema_version": 1,
        "artifact": "v1-multiview-evaluation",
        "case": identity[0],
        "build": identity[1],
        "profile": identity[2],
        "scope": identity[3],
        "ground_truth": {"used_for": "evaluation labels only"},
        "variants": variants,
    }


def _artifact_views(artifact: Mapping[str, Any]) -> list[str]:
    config = artifact.get("config")
    if not isinstance(config, Mapping):
        return []
    views = config.get("views")
    if not isinstance(views, list):
        return []
    return list(views)


def _artifact_identity(
    report: Mapping[str, Any],
    artifact: Mapping[str, Any],
) -> tuple[Any, ...]:
    """Return the immutable corpus identity shared by view variants.

    View selection is intentionally excluded from this identity; every other
    input that can change a retrieval result must agree before variants are
    compared.  This prevents a union report from silently mixing body, graph,
    or relation artifacts from different runs.
    """

    universe = artifact.get("universe")
    provenance = artifact.get("provenance")
    relation = artifact.get("relation", {})
    config = artifact.get("config")
    if not isinstance(universe, Mapping):
        raise ValueError("multiview artifact is missing universe")
    if not isinstance(provenance, Mapping):
        raise ValueError("multiview artifact is missing provenance")
    if not isinstance(relation, Mapping):
        raise ValueError("multiview artifact relation metadata must be an object")
    if not isinstance(config, Mapping) or not isinstance(config.get("top_k"), int):
        raise ValueError("multiview artifact is missing top_k")
    config_identity = {
        key: value
        for key, value in config.items()
        if key not in {"views", "view_top_k", "view_profiles"}
    }
    return (
        report["case"],
        report["build"],
        report["profile"],
        report["scope"],
        config["top_k"],
        _canonical_json(provenance),
        _canonical_json({
            key: value
            for key, value in universe.items()
            if key != "target_count"
        }),
        _canonical_json(relation),
        _canonical_json(config_identity),
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _same_origin_count(
    pairs: set[PairKey],
    origin_by_member: Mapping[str, str],
) -> int:
    return sum(
        origin_by_member.get(pair.left) is not None
        and origin_by_member.get(pair.left) == origin_by_member.get(pair.right)
        for pair in pairs
    )


def _read_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate independent F5.2 view artifacts and their union."
    )
    parser.add_argument("ground_truth")
    parser.add_argument(
        "--variant",
        action="append",
        required=True,
        metavar="NAME=PATH",
        help="repeat for each view or union artifact",
    )
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        artifacts: dict[str, Mapping[str, Any]] = {}
        for item in args.variant:
            if "=" not in item:
                raise ValueError("--variant must have NAME=PATH form")
            name, path = item.split("=", 1)
            if not name or not path or name in artifacts:
                raise ValueError(f"invalid or duplicate variant: {item!r}")
            artifacts[name] = _read_json(path)
        report = evaluate_multiview_artifacts(
            artifacts,
            _read_json(args.ground_truth),
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
    for variant in report["variants"]:
        metrics = variant["metrics"]
        print(
            f"{variant['name']}: candidates={metrics['candidate_pair_count']} "
            f"recall={metrics['candidate_pair_recall']} "
            f"fraction={metrics['candidate_pair_fraction']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
