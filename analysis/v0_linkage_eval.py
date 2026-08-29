"""Score V0 on exactly the universe and labels V1 was scored on.

V0's own report counts pairs over its own decision set and treats every
same-origin pair as recoverable. V1 is scored over the whole target universe
with the linkage overlay, which sets aside pairs the binary cannot decide. The
two numbers were never comparable. This evaluator re-scores the V0 partition
with the V1 universe and the same `score_labeled_pairs`, and refuses to run at
all if the two artifacts do not describe the same analysis of the same binary.

V1's grouping is never read: only its target universe and provenance.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from itertools import combinations
from pathlib import Path
from typing import Any, Mapping


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from build_manifest import sha256_file  # noqa: E402
from linkage_overlay import load_overlay, score_labeled_pairs  # noqa: E402


EVAL_ARTIFACT = "v0-linkage-evaluation"
EVAL_SCHEMA_VERSION = 1
RELATION_MODE = "out-in"

# Fields that must agree before the two partitions may be compared. Each names
# an input that would change what either side is looking at.
ANALYSIS_FIELDS = (
    "track",
    "candidate_scope",
    "anchor_policy",
    "raw_graph_sha256",
    "candidate_selection_sha256",
    "projection_config_sha256",
    "edge_policy",
)


def select_v0_run(v0_result: Mapping[str, Any], mode: str = RELATION_MODE) -> Mapping[str, Any]:
    runs = [item for item in v0_result["results"] if item.get("mode") == mode]
    if len(runs) != 1:
        raise ValueError(
            f"expected exactly one {mode!r} run in the V0 result, found {len(runs)}"
        )
    return runs[0]


def v0_target_ids(run: Mapping[str, Any]) -> list[str]:
    """Every function V0 saw: grouped members plus the ones it abstained on."""
    grouped = [
        member["id"]
        for cluster in run["clusters"]
        for member in cluster["members"]
    ]
    abstained = [item["id"] for item in run["abstentions"]]
    together = grouped + abstained
    duplicates = len(together) - len(set(together))
    if duplicates:
        raise ValueError(f"V0 run lists {duplicates} function(s) more than once")
    return sorted(together)


def v0_predicted_pairs(run: Mapping[str, Any]) -> set[tuple[str, str]]:
    """Every pair V0 put in one cluster.

    A singleton cluster and an abstention both predict "not grouped with
    anything", so neither contributes a pair.
    """
    pairs: set[tuple[str, str]] = set()
    for cluster in run["clusters"]:
        members = sorted(member["id"] for member in cluster["members"])
        pairs.update(combinations(members, 2))
    return pairs


def check_same_analysis(
    run: Mapping[str, Any],
    v1_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    """Refuse to compare two partitions of different things."""
    for field in ("case", "build", "profile"):
        if run.get(field) != v1_artifact.get(field):
            raise ValueError(
                f"V0 and V1 disagree on {field}: "
                f"{run.get(field)!r} vs {v1_artifact.get(field)!r}"
            )

    v0_stripped = (run.get("provenance") or {}).get("stripped_sha256")
    v1_stripped = (v1_artifact.get("provenance") or {}).get("stripped_sha256")
    if not v0_stripped or v0_stripped != v1_stripped:
        raise ValueError(
            f"V0 and V1 disagree on stripped_sha256: {v0_stripped!r} vs {v1_stripped!r}"
        )

    analysis = run.get("analysis") or {}
    v1_provenance = v1_artifact.get("provenance") or {}
    verified: dict[str, Any] = {"stripped_sha256": v0_stripped}
    for field in ANALYSIS_FIELDS:
        left = analysis.get(field)
        right = v1_provenance.get(field)
        if field == "candidate_scope":
            right = v1_artifact.get("scope")
        if left is None or left != right:
            raise ValueError(
                f"V0 and V1 disagree on {field}: {left!r} vs {right!r}"
            )
        verified[field] = left
    if analysis.get("track") != "angr":
        raise ValueError(f"expected the angr track, found {analysis.get('track')!r}")
    if analysis.get("anchor_policy") != "role":
        raise ValueError(
            f"expected the role anchor policy, found {analysis.get('anchor_policy')!r}"
        )
    return verified


def evaluate_v0(
    v0_result: Mapping[str, Any],
    v1_artifact: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
    linkage_audit: Mapping[str, Any],
    *,
    ground_truth_sha256: str,
    provenance: Mapping[str, str] | None = None,
    mode: str = RELATION_MODE,
) -> dict[str, Any]:
    run = select_v0_run(v0_result, mode)
    verified = check_same_analysis(run, v1_artifact)

    universe = sorted(v1_artifact["universe"]["target_ids"])
    observed = v0_target_ids(run)
    if observed != universe:
        only_v0 = sorted(set(observed) - set(universe))
        only_v1 = sorted(set(universe) - set(observed))
        raise ValueError(
            "V0 and V1 target universes differ: "
            f"{len(only_v0)} only in V0 (first {only_v0[:1]}), "
            f"{len(only_v1)} only in V1 (first {only_v1[:1]})"
        )
    for field in ("case", "build", "profile"):
        if ground_truth.get(field) != run.get(field):
            raise ValueError(f"ground truth disagrees on {field}")
        if linkage_audit.get(field) != run.get(field):
            raise ValueError(f"linkage audit disagrees on {field}")
    # Matching case/build/profile does not make these the same file. The audit
    # records the ground truth it was built from; anything else is a different
    # set of labels wearing the same name.
    audited = (linkage_audit.get("provenance") or {}).get("ground_truth_sha256")
    if not audited:
        raise ValueError("linkage audit does not record a ground_truth_sha256")
    if audited != ground_truth_sha256:
        raise ValueError(
            "linkage audit ground_truth_sha256 mismatch: audit was built from "
            f"{audited}, supplied ground truth is {ground_truth_sha256}"
        )

    origins_by_address, identities_by_address = load_overlay(linkage_audit)
    predicted = v0_predicted_pairs(run)
    metrics = score_labeled_pairs(
        combinations(universe, 2),
        predicted,
        origins_by_address=origins_by_address,
        identities_by_address=identities_by_address,
    )

    return {
        "artifact": EVAL_ARTIFACT,
        "schema_version": EVAL_SCHEMA_VERSION,
        "case": run.get("case"),
        "build": run.get("build"),
        "profile": run.get("profile"),
        "mode": mode,
        "method": "V0 relation-only",
        "ground_truth": {"used_for": "evaluation labels only"},
        "provenance": dict(provenance or {}),
        "verified_analysis": verified,
        "universe": {
            "target_count": len(universe),
            "total_pair_count": len(universe) * (len(universe) - 1) // 2,
            "grouped_candidate_count": run.get("grouped_candidate_count"),
            "abstained_candidate_count": run.get("abstained_candidate_count"),
            "cluster_count": len(run["clusters"]),
        },
        "predicted_pair_count": len(predicted),
        "linkage_metrics": metrics,
    }


def evaluate_v0_files(
    v0_result_path: str | Path,
    v1_universe_path: str | Path,
    ground_truth_path: str | Path,
    linkage_audit_path: str | Path,
    *,
    mode: str = RELATION_MODE,
) -> dict[str, Any]:
    read = lambda path: json.loads(Path(path).read_text(encoding="utf-8"))  # noqa: E731
    return evaluate_v0(
        read(v0_result_path),
        read(v1_universe_path),
        read(ground_truth_path),
        read(linkage_audit_path),
        ground_truth_sha256=sha256_file(ground_truth_path),
        provenance={
            "v0_result_sha256": sha256_file(v0_result_path),
            "v1_universe_sha256": sha256_file(v1_universe_path),
            "ground_truth_sha256": sha256_file(ground_truth_path),
            "linkage_audit_sha256": sha256_file(linkage_audit_path),
        },
        mode=mode,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v0-result", required=True)
    parser.add_argument("--v1-universe", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--linkage-audit", required=True)
    parser.add_argument("--mode", default=RELATION_MODE)
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = evaluate_v0_files(
            args.v0_result,
            args.v1_universe,
            args.ground_truth,
            args.linkage_audit,
            mode=args.mode,
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
    primary = report["linkage_metrics"]["primary"]
    print(
        f"primary TP={primary['TP']} FP={primary['FP']} FN={primary['FN']} "
        f"TN={primary['TN']}"
    )
    print(
        f"precision={primary['precision']} recall={primary['recall']} "
        f"F1={primary['F1']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
