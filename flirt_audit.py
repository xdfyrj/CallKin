"""Audit direct Oxidizer FLIRT labels against a scoring-only all-Rust catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from gt_extractor import (
    all_rust_catalog_sha256,
    load_all_rust_catalog,
)
from oxidizer_adapter import load_label_artifact
from paths import (
    BUILD_PROFILES,
    DEFAULT_BUILD,
    DEFAULT_PROFILE,
    all_rust_catalog_for,
    flirt_audit_for,
    oxidizer_labels_for,
    split_case_build,
)


FLIRT_AUDIT_SCHEMA_VERSION = 2
STANDARD_LIBRARY_OWNERS = frozenset({"core", "alloc", "std"})


def _canonical_sha256(data: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _catalog_members(catalog: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    origin_by_member: dict[str, str] = {}
    for group in catalog["origins"]:
        for member in group["members"]:
            origin_by_member[member] = group["origin"]
    return origin_by_member, dict(catalog["owners"])


def _is_standard_library_owner(owner: str) -> bool:
    return owner in STANDARD_LIBRARY_OWNERS


def _family_rows(
    catalog: dict[str, Any],
    known_seed_members: set[str],
) -> list[dict[str, Any]]:
    rows = []
    for group in catalog["origins"]:
        members = group["members"]
        known = sorted(member for member in members if member in known_seed_members)
        unknown = sorted(member for member in members if member not in known_seed_members)
        if not known or not unknown:
            continue
        rows.append({
            "origin": group["origin"],
            "known_direct_flirt_instances": len(known),
            "unknown_instances": len(unknown),
            "cross_boundary_same_family_pair_count": len(known) * len(unknown),
            "known_members": known,
            "unknown_members": unknown,
        })
    return rows


def build_flirt_audit(
    *,
    catalog: dict[str, Any],
    labels: dict[str, Any],
) -> dict[str, Any]:
    """Build evaluation-only direct-FLIRT and mixed-family measurements."""
    identity = ("case", "build", "profile", "provenance")
    for key in identity:
        if catalog[key] != labels[key]:
            raise ValueError(
                f"all-Rust catalog/Oxidizer labels {key} mismatch: "
                f"{catalog[key]!r} != {labels[key]!r}"
            )
    if labels["stripped_sha256"] != catalog["provenance"]["stripped_sha256"]:
        raise ValueError("Oxidizer labels stripped hash differs from catalog provenance")

    origin_by_member, owner_by_member = _catalog_members(catalog)
    direct_by_address = {
        match["address"]: match
        for match in labels["matches"]
        if match["evidence"] == "direct-flirt"
    }
    # Catalog and labels use the same CallKin FUN_<linked-address> ID convention.
    # Build that link once from the label address rather than assuming an ID bias.
    direct_by_member = {
        member: match
        for address, match in direct_by_address.items()
        if (member := _member_id_for_address(
            address,
            origin_by_member,
            id_bias=catalog["id_bias"],
        )) is not None
    }
    known_seed_members = {
        member
        for member, match in direct_by_member.items()
        if _is_standard_library_owner(match["owner"])
    }

    standard_true_positive = 0
    standard_false_positive = 0
    standard_false_negative = 0
    standard_true_negative = 0
    correct_identity_count = 0
    incorrectly_labeled_members = []
    for member, match in direct_by_member.items():
        correct = (
            match["canonical_origin"] == origin_by_member[member]
            and match["owner"] == owner_by_member[member]
        )
        if correct:
            correct_identity_count += 1
        else:
            incorrectly_labeled_members.append({
                "member": member,
                "label_origin": match["canonical_origin"],
                "catalog_origin": origin_by_member[member],
                "label_owner": match["owner"],
                "catalog_owner": owner_by_member[member],
            })

    for member, actual_owner in owner_by_member.items():
        predicted_standard = member in known_seed_members
        actual_standard = _is_standard_library_owner(actual_owner)
        if predicted_standard and actual_standard:
            standard_true_positive += 1
        elif predicted_standard:
            standard_false_positive += 1
        elif actual_standard:
            standard_false_negative += 1
        else:
            standard_true_negative += 1

    family_rows = _family_rows(catalog, known_seed_members)
    drop_rows = [
        row for row in family_rows
        if "drop_in_place" in row["origin"]
    ]

    return {
        "schema_version": FLIRT_AUDIT_SCHEMA_VERSION,
        "case": catalog["case"],
        "build": catalog["build"],
        "profile": catalog["profile"],
        "provenance": catalog["provenance"],
        "all_rust_catalog_sha256": all_rust_catalog_sha256(catalog),
        "oxidizer_labels_sha256": _canonical_sha256(labels),
        "direct_flirt": {
            "raw_graph_joined_match_count": len(labels["matches"]),
            "catalog_joined_match_count": len(direct_by_member),
            "catalog_unmatched_count": len(labels["matches"]) - len(direct_by_member),
            "unmatched_address_count": sum(
                match["evidence"] == "direct-flirt"
                for match in labels["unmatched_addresses"]
            ),
            "std_classification": {
                "true_positive": standard_true_positive,
                "false_positive": standard_false_positive,
                "false_negative": standard_false_negative,
                "true_negative": standard_true_negative,
                "precision": _ratio(
                    standard_true_positive,
                    standard_true_positive + standard_false_positive,
                ),
                "recall": _ratio(
                    standard_true_positive,
                    standard_true_positive + standard_false_negative,
                ),
            },
            "exact_identity": {
                "matched_member_count": len(direct_by_member),
                "correct_match_count": correct_identity_count,
                "incorrect_match_count": len(incorrectly_labeled_members),
                "precision": _ratio(correct_identity_count, len(direct_by_member)),
                "catalog_member_coverage": _ratio(
                    correct_identity_count,
                    len(origin_by_member),
                ),
                "incorrect_labels": sorted(
                    incorrectly_labeled_members,
                    key=lambda item: item["member"],
                ),
            },
        },
        "mixed_families": {
            "family_count": len(family_rows),
            "cross_boundary_same_family_pair_count": sum(
                row["cross_boundary_same_family_pair_count"]
                for row in family_rows
            ),
            "families": family_rows,
        },
        "drop_in_place_families": drop_rows,
    }


def _member_id_for_address(
    address: str,
    origin_by_member: dict[str, str],
    *,
    id_bias: int,
) -> str | None:
    value = int(address, 0)
    suffix = f"{value + id_bias:08x}"
    candidate = f"FUN_{suffix}"
    return candidate if candidate in origin_by_member else None


def write_flirt_audit(data: dict[str, Any], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit direct Oxidizer FLIRT labels against all-Rust symbols."
    )
    parser.add_argument("stem", help="case stem, for example billing-client")
    parser.add_argument("--build", default=DEFAULT_BUILD)
    parser.add_argument("--profile", choices=BUILD_PROFILES, default=DEFAULT_PROFILE)
    parser.add_argument("--catalog", help="override all-Rust catalog path")
    parser.add_argument("--labels", help="override Oxidizer label path")
    parser.add_argument("--output", help="override audit JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        case, build = split_case_build(args.stem, args.build)
        catalog = load_all_rust_catalog(
            args.catalog or all_rust_catalog_for(case, build, args.profile)
        )
        labels = load_label_artifact(
            args.labels or oxidizer_labels_for(case, build, args.profile)
        )
        audit = build_flirt_audit(catalog=catalog, labels=labels)
        output = args.output or flirt_audit_for(case, build, args.profile)
        write_flirt_audit(audit, output)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    standard = audit["direct_flirt"]["std_classification"]
    identity = audit["direct_flirt"]["exact_identity"]
    mixed = audit["mixed_families"]
    print(
        "direct FLIRT labels: "
        f"raw={audit['direct_flirt']['raw_graph_joined_match_count']} "
        f"catalog={audit['direct_flirt']['catalog_joined_match_count']} "
        f"catalog-unmatched={audit['direct_flirt']['catalog_unmatched_count']}"
    )
    print(
        "std classification P/R: "
        f"{standard['precision']}/{standard['recall']}"
    )
    print(
        "exact identity: "
        f"{identity['correct_match_count']}/{identity['matched_member_count']} "
        f"(coverage={identity['catalog_member_coverage']})"
    )
    print(
        "known-unknown mixed families: "
        f"{mixed['family_count']} "
        f"(cross-boundary pairs={mixed['cross_boundary_same_family_pair_count']})"
    )
    print(f"wrote: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
