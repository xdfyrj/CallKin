"""Audit direct Oxidizer FLIRT labels against a scoring-only all-Rust catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from gt_extractor import (
    all_rust_catalog_sha256,
    load_all_rust_catalog,
    validate_all_rust_catalog,
)
from graph_projector import function_id
from oxidizer_adapter import load_label_artifact, validate_label_artifact
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


def _exact_label(member: str, label: Mapping[str, Any], origin_by_member: Mapping[str, str], owner_by_member: Mapping[str, str]) -> bool:
    return (
        member in origin_by_member
        and label.get("canonical_origin") == origin_by_member[member]
        and label.get("owner") == owner_by_member[member]
    )


def _prediction_members(
    prediction: Mapping[str, Any],
    key: str,
) -> dict[str, Mapping[str, Any]]:
    values = prediction.get(key)
    if not isinstance(values, list):
        raise ValueError(f"family label propagation {key} must be a list")
    result: dict[str, Mapping[str, Any]] = {}
    for item in values:
        if not isinstance(item, Mapping) or not isinstance(item.get("member"), str):
            raise ValueError(f"family label propagation {key} contains an invalid member")
        member = item["member"]
        if member in result:
            raise ValueError(f"family label propagation {key} contains duplicate member {member!r}")
        result[member] = item
    return result


def _score_upper_bound(
    catalog: Mapping[str, Any],
    correct_direct_members: set[str],
    all_direct_members: set[str],
) -> dict[str, Any]:
    """Measure perfect-family propagation opportunity without changing predictions."""
    rows = []
    for group in catalog["origins"]:
        members = sorted(group["members"])
        known = sorted(set(members) & correct_direct_members)
        unknown = sorted(set(members) - all_direct_members)
        if not known or not unknown:
            continue
        rows.append({
            "origin": group["origin"],
            "known_direct_flirt_instances": len(known),
            "unknown_instances": len(unknown),
            "newly_propagatable_member_count": len(unknown),
            "cross_boundary_same_family_pair_count": len(known) * len(unknown),
            "known_members": known,
            "unknown_members": unknown,
        })
    return {
        "mixed_family_count": len(rows),
        "cross_boundary_member_count": sum(item["unknown_instances"] for item in rows),
        "newly_propagatable_member_count": sum(
            item["newly_propagatable_member_count"] for item in rows
        ),
        "cross_boundary_same_family_pair_count": sum(
            item["cross_boundary_same_family_pair_count"] for item in rows
        ),
        "families": rows,
    }


def score_family_label_propagation(
    catalog: Mapping[str, Any],
    labels: Mapping[str, Any],
    prediction: Mapping[str, Any],
    *,
    oxidizer_labels_sha256: str,
) -> dict[str, Any]:
    """Score a GT-free propagation artifact against the all-Rust catalog.

    This function is evaluation-only.  The prediction builder does not call
    it and does not accept a catalog or ground-truth input.
    """
    from family_label_propagation import validate_propagation_artifact

    validate_all_rust_catalog(catalog)
    validate_propagation_artifact(prediction)
    labels = validate_label_artifact(dict(labels))
    if (
        not isinstance(oxidizer_labels_sha256, str)
        or len(oxidizer_labels_sha256) != 64
        or any(character not in "0123456789abcdef" for character in oxidizer_labels_sha256)
    ):
        raise ValueError("oxidizer_labels_sha256 must be a SHA-256 digest")

    for key in ("case", "build", "profile"):
        if prediction.get(key) != catalog.get(key):
            raise ValueError(f"catalog/propagation {key} mismatch")
    prediction_provenance = prediction.get("provenance") or {}
    if prediction_provenance.get("stripped_sha256") != catalog["provenance"].get("stripped_sha256"):
        raise ValueError("catalog/propagation stripped hash mismatch")
    if prediction_provenance.get("id_bias") != catalog.get("id_bias"):
        raise ValueError("catalog/propagation id_bias mismatch")
    for key in ("case", "build", "profile"):
        if labels.get(key) != catalog.get(key):
            raise ValueError(f"catalog/Oxidizer labels {key} mismatch")
    if labels.get("stripped_sha256") != catalog["provenance"].get("stripped_sha256"):
        raise ValueError("catalog/Oxidizer labels stripped hash mismatch")
    if prediction_provenance.get("oxidizer_labels_sha256") != oxidizer_labels_sha256:
        raise ValueError("prediction/Oxidizer labels raw-file SHA-256 mismatch")

    expected_direct = sorted(
        (
            {
                "member": function_id(int(match["address"], 0), id_bias=prediction_provenance["id_bias"]),
                "address": match["address"],
                "mapped_address": match["mapped_address"],
                "canonical_origin": match["canonical_origin"],
                "owner": match["owner"],
                "evidence": "direct-flirt",
            }
            for match in labels["matches"]
        ),
        key=lambda item: (item["member"], item["address"]),
    )
    actual_direct = [
        {key: item[key] for key in (
            "member", "address", "mapped_address", "canonical_origin", "owner", "evidence",
        )}
        for item in prediction["direct_labels"]
    ]
    if actual_direct != expected_direct:
        raise ValueError("prediction direct baseline differs from Oxidizer direct labels")

    origin_by_member, owner_by_member = _catalog_members(dict(catalog))
    direct = _prediction_members(prediction, "direct_labels")
    propagated = _prediction_members(prediction, "propagated_labels")
    direct_known = set(direct) & set(origin_by_member)
    propagated_known = set(propagated) & set(origin_by_member)
    unknown_propagated = sorted(set(propagated) - set(origin_by_member))
    if unknown_propagated:
        raise ValueError(
            f"propagated member is absent from the scoring catalog: {unknown_propagated[0]!r}"
        )
    direct_correct_members = {
        member for member in direct_known
        if _exact_label(member, direct[member], origin_by_member, owner_by_member)
    }
    propagated_correct_members = {
        member for member in propagated_known
        if _exact_label(member, propagated[member], origin_by_member, owner_by_member)
    }
    propagated_wrong_family_members = {
        member for member in propagated_known
        if not _exact_label(member, propagated[member], origin_by_member, owner_by_member)
    }
    family_ids_with_wrong_member = {
        propagated[member].get("family")
        for member in propagated_wrong_family_members
        if propagated[member].get("family") is not None
    }
    combined = set(direct) | set(propagated)
    combined_known = combined & set(origin_by_member)
    combined_correct_members = {
        member for member in combined_known
        if _exact_label(
            member,
            direct.get(member) or propagated[member],
            origin_by_member,
            owner_by_member,
        )
    }
    direct_incorrect_count = len(direct_known) - len(direct_correct_members)
    propagated_incorrect_count = len(propagated_known) - len(propagated_correct_members)
    catalog_count = len(origin_by_member)
    direct_precision = _ratio(len(direct_correct_members), len(direct_known))
    combined_precision = _ratio(len(combined_correct_members), len(combined_known))
    direct_coverage = _ratio(len(direct_correct_members), catalog_count)
    combined_coverage = _ratio(len(combined_correct_members), catalog_count)
    conflict_count = len(prediction.get("conflicts", []))
    eligible_count = sum(
        isinstance(item, Mapping) and item.get("status") == "eligible"
        for item in prediction.get("families", [])
    )
    upper_bound = _score_upper_bound(catalog, direct_correct_members, set(direct))
    metrics = {
        "catalog_member_count": catalog_count,
        "direct_correct_count": len(direct_correct_members),
        "direct_incorrect_count": direct_incorrect_count,
        "direct_unknown_count": len(set(direct) - set(origin_by_member)),
        "propagated_correct_count": len(propagated_correct_members),
        "propagated_incorrect_count": propagated_incorrect_count,
        "newly_correct_member_count": len(propagated_correct_members - direct_correct_members),
        "wrongly_propagated_member_count": propagated_incorrect_count,
        "wrongly_propagated_family_count": len(family_ids_with_wrong_member),
        "conflict_family_count": conflict_count,
        "eligible_family_count": eligible_count,
        "direct_catalog_coverage": direct_coverage,
        "combined_catalog_coverage": combined_coverage,
        "direct_precision": direct_precision,
        "combined_precision": combined_precision,
    }
    direct_report = {
        "predicted_member_count": len(direct),
        "catalog_member_count": len(direct_known),
        "correct_count": len(direct_correct_members),
        "incorrect_count": direct_incorrect_count,
        "unknown_count": len(set(direct) - set(origin_by_member)),
        "precision": direct_precision,
        "catalog_coverage": direct_coverage,
        "correct_members": sorted(direct_correct_members),
    }
    propagated_report = {
        "predicted_member_count": len(propagated),
        "catalog_member_count": len(propagated_known),
        "correct_count": len(propagated_correct_members),
        "incorrect_count": propagated_incorrect_count,
        "precision": _ratio(len(propagated_correct_members), len(propagated_known)),
        "correct_members": sorted(propagated_correct_members),
        "wrong_family_members": sorted(propagated_wrong_family_members),
    }
    combined_report = {
        "predicted_member_count": len(combined),
        "catalog_member_count": len(combined_known),
        "correct_count": len(combined_correct_members),
        "incorrect_count": len(combined_known) - len(combined_correct_members),
        "precision": combined_precision,
        "catalog_coverage": combined_coverage,
        "newly_correct_member_count": len(propagated_correct_members - direct_correct_members),
    }
    report = {
        "schema_version": 1,
        "artifact": "v1-family-label-propagation-evaluation",
        "case": catalog["case"],
        "build": catalog["build"],
        "profile": catalog["profile"],
        "provenance": {
            "all_rust_catalog_sha256": all_rust_catalog_sha256(dict(catalog)),
            "propagation_stripped_sha256": prediction_provenance["stripped_sha256"],
            "oxidizer_labels_sha256": prediction_provenance.get("oxidizer_labels_sha256"),
        },
        "direct": direct_report,
        "propagated": propagated_report,
        "combined": combined_report,
        "metrics": metrics,
        "gt_upper_bound": upper_bound,
    }
    return report


def build_flirt_audit(
    *,
    catalog: dict[str, Any],
    labels: dict[str, Any],
    prediction: Mapping[str, Any] | None = None,
    oxidizer_labels_sha256: str | None = None,
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

    output = {
        "schema_version": FLIRT_AUDIT_SCHEMA_VERSION,
        "case": catalog["case"],
        "build": catalog["build"],
        "profile": catalog["profile"],
        "provenance": catalog["provenance"],
        "all_rust_catalog_sha256": all_rust_catalog_sha256(catalog),
        "oxidizer_labels_content_sha256": _canonical_sha256(labels),
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
    if prediction is not None:
        if oxidizer_labels_sha256 is None:
            raise ValueError("raw Oxidizer labels SHA-256 is required to score a prediction")
        output["family_label_propagation"] = score_family_label_propagation(
            catalog,
            labels,
            prediction,
            oxidizer_labels_sha256=oxidizer_labels_sha256,
        )
    return output


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
    parser.add_argument(
        "--prediction",
        help="optional F10 family-label propagation artifact to score",
    )
    parser.add_argument("--output", help="override audit JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        case, build = split_case_build(args.stem, args.build)
        catalog = load_all_rust_catalog(
            args.catalog or all_rust_catalog_for(case, build, args.profile)
        )
        labels_path = args.labels or oxidizer_labels_for(case, build, args.profile)
        labels = load_label_artifact(labels_path)
        prediction = None
        if args.prediction:
            prediction = json.loads(Path(args.prediction).read_text(encoding="utf-8"))
        audit = build_flirt_audit(
            catalog=catalog,
            labels=labels,
            prediction=prediction,
            oxidizer_labels_sha256=hashlib.sha256(Path(labels_path).read_bytes()).hexdigest(),
        )
        output = args.output or flirt_audit_for(case, build, args.profile)
        write_flirt_audit(audit, output)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    standard = audit["direct_flirt"]["std_classification"]
    identity = audit["direct_flirt"]["exact_identity"]
    mixed = audit["mixed_families"]
    print(json.dumps(audit, indent=2, sort_keys=True, ensure_ascii=False))
    print(
        "direct FLIRT labels: "
        f"raw={audit['direct_flirt']['raw_graph_joined_match_count']} "
        f"catalog={audit['direct_flirt']['catalog_joined_match_count']} "
        f"catalog-unmatched={audit['direct_flirt']['catalog_unmatched_count']}",
        file=sys.stderr,
    )
    print(
        "std classification P/R: "
        f"{standard['precision']}/{standard['recall']}",
        file=sys.stderr,
    )
    print(
        "exact identity: "
        f"{identity['correct_match_count']}/{identity['matched_member_count']} "
        f"(coverage={identity['catalog_member_coverage']})",
        file=sys.stderr,
    )
    print(
        "known-unknown mixed families: "
        f"{mixed['family_count']} "
        f"(cross-boundary pairs={mixed['cross_boundary_same_family_pair_count']})",
        file=sys.stderr,
    )
    print(f"wrote: {output}", file=sys.stderr)
    if "family_label_propagation" in audit:
        metrics = audit["family_label_propagation"]["metrics"]
        print(
            "family label propagation: "
            f"direct={metrics['direct_correct_count']}/{metrics['direct_correct_count'] + metrics['direct_incorrect_count']} "
            f"propagated={metrics['propagated_correct_count']}/{metrics['propagated_correct_count'] + metrics['propagated_incorrect_count']} "
            f"newly-correct={metrics['newly_correct_member_count']}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
