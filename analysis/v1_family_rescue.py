"""Run F7 fragment rescue over a strict F6 partition and write the artifact.

Ground truth is not an input. The rescue rule reads the strict partition, a
2-view candidate queue, body evidence and the raw call graph, and nothing that
names a source origin.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.gt_mangled_audit import address_from_function_id  # noqa: E402
from body_similarity import load_body_evidence  # noqa: E402
from build_manifest import sha256_file  # noqa: E402
from family_rescue import (  # noqa: E402
    ACCEPTED,
    BUDGET_BLOCKED,
    RESCUE_RULE_VERSION,
    REJECTED,
    RescueBudget,
    accepted_fragments,
    check_inputs_agree,
    final_partition,
    rescue_families,
)
from slot_overlay import transfers_by_source  # noqa: E402


RESCUE_ARTIFACT = "v1-family-rescue"
RESCUE_SCHEMA_VERSION = 1


def build_rescue_artifact(
    family_artifact: dict[str, Any],
    candidate_artifact: dict[str, Any],
    body_artifact: dict[str, Any],
    raw_graph: dict[str, Any],
    *,
    budget: RescueBudget,
    provenance: dict[str, str],
) -> dict[str, Any]:
    verified = check_inputs_agree(family_artifact, candidate_artifact)
    bodies = load_body_evidence(body_artifact)
    transfers = transfers_by_source(raw_graph)
    address_of = {member: address_from_function_id(member) for member in bodies}

    components, used = rescue_families(
        family_artifact, candidate_artifact, bodies, transfers, address_of,
        budget=budget,
    )
    strict = accepted_fragments(family_artifact)
    final = final_partition(family_artifact, components)
    statuses = Counter(component.status for component in components)
    reasons = Counter(
        component.reason for component in components if component.reason
    )

    return {
        "artifact": RESCUE_ARTIFACT,
        "schema_version": RESCUE_SCHEMA_VERSION,
        "rescue_rule_version": RESCUE_RULE_VERSION,
        "case": family_artifact.get("case"),
        "build": family_artifact.get("build"),
        "profile": family_artifact.get("profile"),
        "scope": family_artifact.get("scope"),
        "ground_truth": {"used_for": "not used"},
        "provenance": provenance,
        "verified_provenance": verified,
        "budget": budget.to_dict(),
        "summary": {
            "strict_accepted_fragment_count": len(strict),
            "strict_accepted_member_count": sum(len(v) for v in strict.values()),
            "component_count": len(components),
            "accepted_component_count": statuses.get(ACCEPTED, 0),
            "rejected_component_count": statuses.get(REJECTED, 0),
            "budget_blocked_component_count": statuses.get(BUDGET_BLOCKED, 0),
            "rejection_reasons": dict(sorted(reasons.items())),
            "reserved_comparisons": used["reserved_comparisons"],
            "reserved_alignment_cells": used["reserved_alignment_cells"],
            "final_family_count": len(final),
            "rescued_family_count": sum(
                1 for item in final if item["origin"] == "rescued"
            ),
        },
        "strict_partition": [
            {"id": name, "members": list(members)}
            for name, members in sorted(strict.items())
        ],
        "final_partition": final,
        "components": [component.to_dict() for component in components],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family-artifact", required=True)
    parser.add_argument("--candidates", required=True, help="2-view consensus queue")
    parser.add_argument("--body-evidence", required=True)
    parser.add_argument("--raw-graph", required=True)
    parser.add_argument("--max-component-members", type=int, default=None)
    parser.add_argument("--max-comparisons", type=int, default=None)
    parser.add_argument("--max-alignment-cells", type=int, default=None)
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    defaults = RescueBudget()
    budget = RescueBudget(
        max_component_members=(
            args.max_component_members
            if args.max_component_members is not None
            else defaults.max_component_members
        ),
        max_comparisons=(
            args.max_comparisons
            if args.max_comparisons is not None
            else defaults.max_comparisons
        ),
        max_alignment_cells=(
            args.max_alignment_cells
            if args.max_alignment_cells is not None
            else defaults.max_alignment_cells
        ),
    )
    read = lambda path: json.loads(Path(path).read_text(encoding="utf-8"))  # noqa: E731
    try:
        report = build_rescue_artifact(
            read(args.family_artifact),
            read(args.candidates),
            read(args.body_evidence),
            read(args.raw_graph),
            budget=budget,
            provenance={
                "family_artifact_sha256": sha256_file(args.family_artifact),
                "candidate_artifact_sha256": sha256_file(args.candidates),
                "body_evidence_sha256": sha256_file(args.body_evidence),
                "raw_graph_sha256": sha256_file(args.raw_graph),
            },
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
    summary = report["summary"]
    print(
        f"components={summary['component_count']} "
        f"accepted={summary['accepted_component_count']} "
        f"rejected={summary['rejected_component_count']} "
        f"budget_blocked={summary['budget_blocked_component_count']}"
    )
    for reason, count in summary["rejection_reasons"].items():
        print(f"  {reason}={count}")
    print(
        f"reserved {summary['reserved_comparisons']} comparisons, "
        f"{summary['reserved_alignment_cells']} alignment cells"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
