"""F7.3 probe: recover anonymous variation axes for named ground-truth families.

Ground truth is used only to say which functions belong to a family. Nothing
about the source types reaches the axis inference, and the output never claims
to name a type parameter: it reports how many observable axes were found, how
many variants each has, and how completely they cover their joint product.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.gt_mangled_audit import address_from_function_id  # noqa: E402
from body_similarity import load_body_evidence  # noqa: E402
from build_manifest import sha256_file  # noqa: E402
from family_template import axis_report, build_family_template, select_medoid  # noqa: E402
from slot_overlay import collect_slot_observations, transfers_by_source  # noqa: E402


PROBE_ARTIFACT = "v1-axis-probe"
PROBE_SCHEMA_VERSION = 1


def probe_family(
    bodies: dict[str, Any],
    transfer_index: dict[int, dict[int, Any]],
    members: list[str],
) -> dict[str, Any]:
    selected = {member: bodies[member] for member in members}
    observations = {}
    for member in members:
        base = address_from_function_id(member)
        observations[member] = collect_slot_observations(
            selected[member], base, transfer_index.get(base, {})
        )
    selection = select_medoid(selected, members)
    template = build_family_template(selected, selection, observations)
    report = axis_report(template)
    report["members"] = list(members)
    report["medoid_score"] = selection.score
    report["block_roles"] = dict(sorted(template.block_roles.items()))
    report["member_specific_blocks"] = {
        member: list(blocks)
        for member, blocks in sorted(template.member_specific_blocks.items())
    }
    return report


def check_inputs_agree(
    body_artifact: dict[str, Any],
    raw_graph: dict[str, Any],
    ground_truth: dict[str, Any],
    *,
    raw_graph_sha256: str,
) -> None:
    """Refuse inputs that do not describe the same build of the same binary."""
    sources = {
        "body evidence": body_artifact,
        "raw graph": raw_graph,
        "ground truth": ground_truth,
    }
    for field in ("case", "build", "profile"):
        values = {name: artifact.get(field) for name, artifact in sources.items()}
        if len(set(values.values())) != 1:
            raise ValueError(f"inputs disagree on {field}: {values}")

    stripped = {
        name: (artifact.get("provenance") or {}).get("stripped_sha256")
        for name, artifact in sources.items()
    }
    if len(set(stripped.values())) != 1 or None in stripped.values():
        raise ValueError(f"inputs disagree on stripped_sha256: {stripped}")

    recorded = (body_artifact.get("provenance") or {}).get("raw_graph_sha256")
    if recorded is not None and recorded != raw_graph_sha256:
        raise ValueError(
            "body evidence was built against raw graph "
            f"{recorded}, not {raw_graph_sha256}"
        )


def build_probe(
    body_artifact: dict[str, Any],
    raw_graph: dict[str, Any],
    ground_truth: dict[str, Any],
    origins: list[str],
    *,
    provenance: dict[str, str],
    allow_incomplete_family: bool = False,
) -> dict[str, Any]:
    check_inputs_agree(
        body_artifact,
        raw_graph,
        ground_truth,
        raw_graph_sha256=provenance["raw_graph_sha256"],
    )
    bodies = load_body_evidence(body_artifact)
    transfer_index = transfers_by_source(raw_graph)
    members_by_origin = {
        group["origin"]: sorted(group["members"]) for group in ground_truth["origins"]
    }

    families = []
    for origin in origins:
        members = members_by_origin.get(origin)
        if members is None:
            raise ValueError(f"origin absent from ground truth: {origin!r}")

        # Fail closed: a member silently dropped here can turn an incomplete
        # Cartesian product into an apparently complete one.
        absent = [member for member in members if member not in bodies]
        incomplete = [
            member for member in members
            if member in bodies and not bodies[member].complete
        ]
        if not allow_incomplete_family:
            if absent:
                raise ValueError(
                    f"origin {origin!r} has {len(absent)} members without a body, "
                    f"first is {absent[0]!r}"
                )
            if incomplete:
                raise ValueError(
                    f"origin {origin!r} has {len(incomplete)} members whose decode "
                    f"is incomplete, first is {incomplete[0]!r}"
                )
        usable = [
            member for member in members
            if member in bodies and bodies[member].complete
        ]
        if len(usable) < 2:
            raise ValueError(f"origin {origin!r} has fewer than two usable bodies")

        report = probe_family(bodies, transfer_index, usable)
        report["origin"] = origin
        report["ground_truth_member_count"] = len(members)
        report["excluded_members"] = {
            "no_body": sorted(absent),
            "incomplete_decode": sorted(incomplete),
        }
        families.append(report)

    return {
        "artifact": PROBE_ARTIFACT,
        "schema_version": PROBE_SCHEMA_VERSION,
        "case": body_artifact.get("case"),
        "build": body_artifact.get("build"),
        "profile": body_artifact.get("profile"),
        "ground_truth": {"used_for": "family membership only"},
        "provenance": provenance,
        "families": families,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body-evidence", required=True)
    parser.add_argument("--raw-graph", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--origin", action="append", required=True)
    parser.add_argument("--output")
    parser.add_argument(
        "--allow-incomplete-family",
        action="store_true",
        help="diagnose a family whose members lack a body or a complete decode; "
             "the default refuses, because a dropped member can make an "
             "incomplete product look complete",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = build_probe(
            json.loads(Path(args.body_evidence).read_text(encoding="utf-8")),
            json.loads(Path(args.raw_graph).read_text(encoding="utf-8")),
            json.loads(Path(args.ground_truth).read_text(encoding="utf-8")),
            args.origin,
            provenance={
                "body_evidence_sha256": sha256_file(args.body_evidence),
                "raw_graph_sha256": sha256_file(args.raw_graph),
                "ground_truth_sha256": sha256_file(args.ground_truth),
            },
            allow_incomplete_family=args.allow_incomplete_family,
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
    for family in report["families"]:
        print(
            f"{family['origin']}: members={family['member_count']} "
            f"axes={family['axis_count']} "
            f"variants={[axis['variant_count'] for axis in family['axes']]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
