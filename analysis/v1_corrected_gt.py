"""Build the corrected ground truth used to score generic family recovery.

Origins whose members all carry the same raw linkage symbol are codegen
duplicates of one mono item, not distinct monomorphizations. They are not
deleted, because deleting them would change the evaluation universe. Each of
their members becomes its own singleton origin instead, so an algorithm that
groups codegen duplicates into a family is charged a false positive.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.gt_mangled_audit import (  # noqa: E402
    AUDIT_ARTIFACT,
    DISTINCT,
    REPEATED,
    UNRESOLVED,
)
from build_manifest import sha256_file  # noqa: E402


CORRECTED_GT_SCHEMA_VERSION = 1
CORRECTED_GT_ARTIFACT = "v1-corrected-ground-truth"
REPEATED_ORIGIN_PREFIX = "repeated@"
SINGLETON = "singleton"


def repeated_origin_name(member: str) -> str:
    return f"{REPEATED_ORIGIN_PREFIX}{member}"


def build_corrected_ground_truth(
    ground_truth: Mapping[str, Any],
    audit: Mapping[str, Any],
    *,
    ground_truth_sha256: str,
    audit_sha256: str,
) -> dict[str, Any]:
    if audit.get("artifact") != AUDIT_ARTIFACT:
        raise ValueError(f"expected a {AUDIT_ARTIFACT} artifact")
    for field in ("case", "build", "profile"):
        if audit.get(field) != ground_truth.get(field):
            raise ValueError(f"audit and ground truth disagree on {field}")
    audited_ground_truth_sha256 = (audit.get("provenance") or {}).get(
        "ground_truth_sha256"
    )
    if audited_ground_truth_sha256 != ground_truth_sha256:
        raise ValueError("audit ground truth hash does not match the supplied ground truth")

    audit_entries: dict[str, Mapping[str, Any]] = {}
    for entry in audit["origins"]:
        origin = entry["origin"]
        if origin in audit_entries:
            raise ValueError(f"audit contains duplicate origin {origin!r}")
        audit_entries[origin] = entry
    classification = {
        origin: entry["classification"] for origin, entry in audit_entries.items()
    }
    unresolved = sorted(
        origin for origin, value in classification.items() if value == UNRESOLVED
    )
    if unresolved:
        raise ValueError(
            f"{len(unresolved)} origins have no raw symbol, first is {unresolved[0]!r}"
        )

    origins: list[dict[str, Any]] = []
    counts = {DISTINCT: 0, REPEATED: 0, SINGLETON: 0}
    ground_truth_origins = {group["origin"] for group in ground_truth["origins"]}
    unknown_audit_origins = sorted(set(audit_entries) - ground_truth_origins)
    if unknown_audit_origins:
        raise ValueError(
            f"audit covers unknown origin {unknown_audit_origins[0]!r}"
        )
    for group in ground_truth["origins"]:
        members = sorted(group["members"])
        audit_entry = audit_entries.get(group["origin"])
        if audit_entry is not None and sorted(audit_entry["members"]) != members:
            raise ValueError(f"audit members disagree for origin {group['origin']!r}")
        label = classification.get(group["origin"], SINGLETON if len(members) < 2 else None)
        if label is None:
            raise ValueError(f"audit does not cover origin {group['origin']!r}")
        counts[label] += 1
        if label == REPEATED:
            for member in members:
                origins.append(
                    {
                        "origin": repeated_origin_name(member),
                        "members": [member],
                        "classification": REPEATED,
                        "source_origin": group["origin"],
                    }
                )
        else:
            origins.append(
                {
                    "origin": group["origin"],
                    "members": members,
                    "classification": label,
                }
            )

    origins.sort(key=lambda item: item["origin"])
    positive = [group for group in origins if len(group["members"]) > 1]
    return {
        "artifact": CORRECTED_GT_ARTIFACT,
        "schema_version": CORRECTED_GT_SCHEMA_VERSION,
        "case": ground_truth.get("case"),
        "build": ground_truth.get("build"),
        "profile": ground_truth.get("profile"),
        "provenance": {
            "ground_truth_sha256": ground_truth_sha256,
            "audit_sha256": audit_sha256,
            "source_provenance": ground_truth.get("provenance"),
        },
        "summary": {
            "source_origin_counts": counts,
            "member_count": sum(len(group["members"]) for group in origins),
            "origin_count": len(origins),
            "multimember_origin_count": len(positive),
            "same_origin_pair_count": sum(
                len(group["members"]) * (len(group["members"]) - 1) // 2
                for group in positive
            ),
        },
        "origins": origins,
        "symbols": ground_truth.get("symbols", {}),
    }


def correct_ground_truth_files(
    ground_truth_path: str | Path,
    audit_path: str | Path,
) -> dict[str, Any]:
    return build_corrected_ground_truth(
        json.loads(Path(ground_truth_path).read_text(encoding="utf-8")),
        json.loads(Path(audit_path).read_text(encoding="utf-8")),
        ground_truth_sha256=sha256_file(ground_truth_path),
        audit_sha256=sha256_file(audit_path),
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split codegen-duplicate origins into singletons for scoring."
    )
    parser.add_argument("ground_truth")
    parser.add_argument("audit")
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = correct_ground_truth_files(args.ground_truth, args.audit)
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
    print(f"member_count={summary['member_count']}")
    print(f"multimember_origin_count={summary['multimember_origin_count']}")
    print(f"same_origin_pair_count={summary['same_origin_pair_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
