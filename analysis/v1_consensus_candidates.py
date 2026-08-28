"""Derive a consensus candidate artifact from a multi-view one.

The union artifact is the F5 result; this narrows it to the pairs every view
agreed on, which is a much cheaper and much higher-precision starting point for
F6. It is written as its own F5 artifact rather than being filtered inside F6,
so what F6 consumed stays visible in the record.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import load_body_evidence  # noqa: E402


def build_consensus_artifact(
    artifact: dict[str, Any],
    *,
    minimum_views: int | None = None,
) -> dict[str, Any]:
    views = list(artifact["config"]["views"])
    required = len(views) if minimum_views is None else minimum_views
    if not 1 <= required <= len(views):
        raise ValueError(f"minimum_views must be within 1..{len(views)}")

    # `views` holds a score for every view that ranked the pair, so it is the
    # selection reasons that say which views actually chose it.
    kept = [
        pair for pair in artifact["pairs"]
        if len([reason for reason in pair["reasons"] if reason.endswith("_top_k")])
        >= required
    ]
    consensus = dict(artifact)
    consensus["artifact"] = "v1-consensus-candidate-pairs"
    consensus["pairs"] = kept
    consensus["config"] = {
        **artifact["config"],
        "consensus_minimum_views": required,
    }
    consensus["derived_from"] = {
        "artifact": artifact.get("artifact"),
        "pair_count": len(artifact["pairs"]),
    }
    return consensus


def cost_summary(
    artifact: dict[str, Any],
    bodies: dict[str, Any],
) -> dict[str, Any]:
    counts = {name: len(body.instructions) for name, body in bodies.items()}
    cells = [
        counts.get(pair["first"], 0) * counts.get(pair["second"], 0)
        for pair in artifact["pairs"]
    ]
    cells.sort()
    def quantile(fraction: float) -> int:
        if not cells:
            return 0
        return cells[min(int(fraction * (len(cells) - 1) + 0.5), len(cells) - 1)]
    return {
        "pair_count": len(cells),
        "alignment_cells": sum(cells),
        "alignment_cells_median": quantile(0.5),
        "alignment_cells_p99": quantile(0.99),
        "alignment_cells_max": max(cells) if cells else 0,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidates")
    parser.add_argument("--body-evidence", required=True)
    parser.add_argument(
        "--minimum-views",
        type=int,
        default=None,
        help="how many views must select a pair; defaults to all of them",
    )
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        artifact = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
        consensus = build_consensus_artifact(
            artifact, minimum_views=args.minimum_views
        )
        bodies = load_body_evidence(args.body_evidence)
        summary = {
            "source": cost_summary(artifact, bodies),
            "consensus": cost_summary(consensus, bodies),
        }
        consensus["cost"] = summary["consensus"]
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(consensus, indent=2, sort_keys=True, ensure_ascii=False)
                + "\n",
                encoding="utf-8",
            )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        print(f"wrote {args.output}")
    for name, block in summary.items():
        print(
            f"{name}: pairs={block['pair_count']} "
            f"cells={block['alignment_cells']} "
            f"median={block['alignment_cells_median']} "
            f"p99={block['alignment_cells_p99']} "
            f"max={block['alignment_cells_max']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
