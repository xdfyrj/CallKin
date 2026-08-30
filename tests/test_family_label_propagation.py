from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from family_label_propagation import (  # noqa: E402
    DEFAULT_ID_BIAS,
    build_propagation_artifact,
    build_propagation_files,
    validate_propagation_artifact,
)
from flirt_audit import build_flirt_audit, score_family_label_propagation  # noqa: E402
from graph_projector import function_id  # noqa: E402


STRIPPED = "a" * 64


def _sha(data):
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _build(family, labels, rescue=None, *, family_sha=None, labels_sha=None, rescue_sha=None, **kwargs):
    return build_propagation_artifact(
        family,
        labels,
        rescue,
        family_artifact_sha256=family_sha or _sha(family),
        oxidizer_labels_sha256=labels_sha or _sha(labels),
        rescue_artifact_sha256=(rescue_sha or _sha(rescue)) if rescue is not None else None,
        **kwargs,
    )


def _family(*, accepted=None, universe=None):
    accepted = accepted or {
        "F1": ["FUN_00100000", "FUN_00100020", "FUN_00100040"],
        "F2": ["FUN_00100060", "FUN_00100080"],
    }
    universe = universe or sorted({m for members in accepted.values() for m in members} | {"FUN_001000a0"})
    clusters = [
        {"id": name, "status": "accepted", "members": list(members)}
        for name, members in accepted.items()
    ]
    if "FUN_001000a0" in universe:
        clusters.append({"id": "P", "status": "provisional", "members": ["FUN_001000a0"]})
    target = list(universe)
    return {
        "schema_version": 1,
        "artifact": "v1-family-grouping",
        "case": "demo",
        "build": "O3S",
        "profile": "plain",
        "scope": "rust-nonstd",
        "config": {},
        "provenance": {
            "build_id": "test",
            "source_sha256": "c" * 64,
            "non_stripped_sha256": "d" * 64,
            "stripped_sha256": STRIPPED,
            "raw_graph_sha256": "b" * 64,
            "body_evidence_sha256": "e" * 64,
            "candidate_selection_sha256": "f" * 64,
            "projection_config_sha256": "1" * 64,
            "anchor_policy": "test-anchor",
            "edge_policy": "test-edge",
        },
        "universe": {
            "target_count": len(target),
            "target_ids": target,
            "complete_body_count": len(target),
            "incomplete_ids": [],
        },
        "clusters": clusters,
        "status_members": {
            "accepted": sorted(set(target) - {"FUN_001000a0"}),
            "provisional": ["FUN_001000a0"] if "FUN_001000a0" in target else [],
            "unresolved": [],
            "abstain": [],
        },
        "abstain_reasons": {},
        "pair_decisions": [],
        "blocked_merges": [],
        "metrics": {},
    }


def _match(address, origin, owner):
    return {
        "address": hex(address),
        "mapped_address": hex(address + 0x400000),
        "name": f"{owner}::{origin}",
        "canonical_origin": origin,
        "owner": owner,
        "evidence": "direct-flirt",
    }


def _labels(matches):
    return {
        "schema_version": 1,
        "case": "demo",
        "build": "O3S",
        "profile": "plain",
        "provenance": {
            "build_id": "test",
            "source_sha256": "c" * 64,
            "non_stripped_sha256": "d" * 64,
            "stripped_sha256": STRIPPED,
        },
        "stripped_sha256": STRIPPED,
        "raw_graph_sha256": "b" * 64,
        "analysis": {
            "input": "stripped-only",
            "address_space": "ELF linked virtual address",
            "boundary_oracle": "CallKin raw graph symbol-boundary oracle",
            "seed_policy": "direct-flirt-only",
        },
        "tool": {"oxidizer_commit": "test"},
        "execution": {
            "timeout_seconds": None,
            "memory_limit_mb": None,
            "cache_reused": False,
        },
        "matches": matches,
        "propagated_wrappers": [],
        "cleanup_heuristics": [],
        "unmatched_addresses": [],
    }


def _rescue(family, final):
    family_sha = hashlib.sha256(
        json.dumps(family, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return {
        "artifact": "v1-family-rescue",
        "schema_version": 1,
        "rescue_rule_version": "f7-rescue-v1",
        "case": family["case"],
        "build": family["build"],
        "profile": family["profile"],
        "scope": family["scope"],
        "ground_truth": {"used_for": "not used"},
        "provenance": {
            "family_artifact_sha256": family_sha,
            "candidate_artifact_sha256": "2" * 64,
            "body_evidence_sha256": "e" * 64,
            "raw_graph_sha256": "b" * 64,
        },
        "verified_provenance": {
            "stripped_sha256": STRIPPED,
            "body_evidence_sha256": "e" * 64,
            "raw_graph_sha256": "b" * 64,
            "candidate_selection_sha256": "f" * 64,
            "projection_config_sha256": "1" * 64,
            "anchor_policy": "test-anchor",
            "edge_policy": "test-edge",
            "target_count": len(family["universe"]["target_ids"]),
        },
        "budget": {
            "max_component_members": 128,
            "max_comparisons": 10000,
            "max_alignment_cells": 50000000,
        },
        "summary": {
            "strict_accepted_fragment_count": 2,
            "strict_accepted_member_count": 5,
            "component_count": 0,
            "accepted_component_count": 0,
            "rejected_component_count": 0,
            "budget_blocked_component_count": 0,
            "rejection_reasons": {},
            "reserved_comparisons": 0,
            "reserved_alignment_cells": 0,
            "final_family_count": len(final),
            "rescued_family_count": sum(item.get("origin") == "rescued" for item in final),
        },
        "strict_partition": [
            {"id": "F1", "members": ["FUN_00100000", "FUN_00100020", "FUN_00100040"]},
            {"id": "F2", "members": ["FUN_00100060", "FUN_00100080"]},
        ],
        "final_partition": [
            {**item, "origin": item.get("origin", "rescued")}
            for item in final
        ],
        "components": [],
    }, family_sha


def test_one_seed_propagates_to_all_unlabeled_siblings_and_preserves_provenance():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    artifact = _build(family, labels)

    assert [item["member"] for item in artifact["direct_labels"]] == [function_id(0, id_bias=DEFAULT_ID_BIAS)]
    assert [item["member"] for item in artifact["propagated_labels"]] == [
        "FUN_00100020",
        "FUN_00100040",
    ]
    assert artifact["propagated_labels"][0]["family"] == "F1"
    assert artifact["propagated_labels"][0]["seed_members"] == ["FUN_00100000"]
    assert artifact["propagated_labels"][0]["provenance"]["id_bias"] == DEFAULT_ID_BIAS
    validate_propagation_artifact(artifact)


def test_agreeing_seeds_record_both_seed_ids():
    family = _family()
    labels = _labels([
        _match(0, "origin_a", "crate_a"),
        _match(0x20, "origin_a", "crate_a"),
    ])
    artifact = _build(family, labels)
    assert artifact["propagated_labels"][0]["seed_members"] == [
        "FUN_00100000",
        "FUN_00100020",
    ]


def test_conflicting_seeds_propagate_nothing_and_record_one_conflict():
    family = _family()
    labels = _labels([
        _match(0, "origin_a", "crate_a"),
        _match(0x20, "origin_b", "crate_b"),
    ])
    artifact = _build(family, labels)
    assert artifact["propagated_labels"] == []
    assert len(artifact["conflicts"]) == 1
    assert artifact["conflicts"][0]["family"] == "F1"


def test_zero_seed_and_direct_seed_are_not_duplicated():
    family = _family()
    labels = _labels([_match(0x20, "origin_a", "crate_a")])
    artifact = _build(family, labels)
    assert [item["member"] for item in artifact["propagated_labels"]] == ["FUN_00100000", "FUN_00100040"]
    assert "FUN_00100020" not in {item["member"] for item in artifact["propagated_labels"]}
    assert not any(item["family"] == "F2" for item in artifact["propagated_labels"])


def test_nonaccepted_cluster_is_ignored_and_unknown_seed_is_counted():
    family = _family()
    labels = _labels([
        _match(0xC0, "outside", "crate_x"),
        _match(0x60, "origin_b", "crate_b"),
    ])
    artifact = _build(family, labels)
    outside = next(item for item in artifact["direct_labels"] if item["member"] == "FUN_001000c0")
    assert outside["in_universe"] is False
    assert artifact["opportunity"]["direct_seed_outside_universe_count"] == 1
    assert artifact["propagated_labels"] == [
        {
            **artifact["propagated_labels"][0],
        }
    ]
    assert artifact["propagated_labels"][0]["family"] == "F2"


def test_rescue_final_partition_replaces_strict_fragments():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    rescue, family_sha = _rescue(
        family,
        [{"id": "F1+F2", "members": ["FUN_00100000", "FUN_00100020", "FUN_00100040", "FUN_00100060", "FUN_00100080"]}],
    )
    artifact = _build(
        family,
        labels,
        rescue,
        family_sha=family_sha,
    )
    assert artifact["method"] == "rescue"
    assert {item["family"] for item in artifact["propagated_labels"]} == {"F1+F2"}


def test_rescue_candidate_sha_may_differ_from_strict_family_candidate_sha():
    family = _family()
    family["provenance"]["candidate_artifact_sha256"] = "3" * 64
    labels = _labels([_match(0, "origin_a", "crate_a")])
    rescue, family_sha = _rescue(
        family,
        [
            {"id": "F1", "members": family["clusters"][0]["members"], "origin": "strict"},
            {"id": "F2", "members": family["clusters"][1]["members"], "origin": "strict"},
        ],
    )

    artifact = _build(family, labels, rescue, family_sha=family_sha)

    assert artifact["method"] == "rescue"
    assert artifact["provenance"]["rescue_artifact_sha256"] == _sha(rescue)


def test_rescue_body_and_raw_graph_hashes_still_match_verified_provenance():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    final = [
        {"id": "F1", "members": family["clusters"][0]["members"], "origin": "strict"},
        {"id": "F2", "members": family["clusters"][1]["members"], "origin": "strict"},
    ]
    for key in ("body_evidence_sha256", "raw_graph_sha256"):
        rescue, family_sha = _rescue(family, final)
        rescue["provenance"][key] = "9" * 64
        try:
            _build(family, labels, rescue, family_sha=family_sha)
        except ValueError as exc:
            assert key in str(exc)
        else:
            raise AssertionError(f"rescue {key} mismatch was accepted")


def test_case_build_profile_and_hash_mismatches_fail_closed():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    for key, value in (("case", "other"), ("build", "O3KS"), ("profile", "min")):
        mutated = copy.deepcopy(labels)
        mutated[key] = value
        try:
            _build(family, mutated)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{key} mismatch was accepted")

    mutated = copy.deepcopy(labels)
    mutated["stripped_sha256"] = "9" * 64
    try:
        _build(family, mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("stripped hash mismatch was accepted")


def test_duplicate_member_and_nondefault_bias():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])

    duplicate = copy.deepcopy(family)
    duplicate["clusters"][1]["members"] = ["FUN_00100000", "FUN_00100080"]
    try:
        _build(duplicate, labels)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate family member was accepted")

    biased = _build(
        _family(accepted={"F": ["FUN_00000000", "FUN_00000020"]}, universe=["FUN_00000000", "FUN_00000020"]),
        _labels([_match(0, "origin", "crate")]),
        id_bias=0,
    )
    assert biased["provenance"]["id_bias"] == 0
    assert biased["direct_labels"][0]["member"] == "FUN_00000000"


def test_prediction_api_does_not_accept_ground_truth_or_symbol_names():
    params = set(inspect.signature(build_propagation_artifact).parameters)
    assert not params & {"ground_truth", "gt", "symbols", "symbol_names", "catalog"}


def test_scoring_reports_direct_propagated_and_gt_upper_bound_metrics():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    labels_sha = _sha(labels)
    prediction = _build(family, labels, labels_sha=labels_sha)
    catalog = {
        "schema_version": 1,
        "case": "demo",
        "build": "O3S",
        "profile": "plain",
        "scope": "all-rust",
        "root_namespace": "demo",
        "id_bias": DEFAULT_ID_BIAS,
        "provenance": {
            "build_id": "test",
            "source_sha256": "c" * 64,
            "non_stripped_sha256": "d" * 64,
            "stripped_sha256": STRIPPED,
        },
        "source": "demo",
        "origins": [
            {"origin": "origin_a", "members": ["FUN_00100000", "FUN_00100020", "FUN_00100040"]},
            {"origin": "origin_b", "members": ["FUN_00100060", "FUN_00100080"]},
        ],
        "symbols": {
            member: [member] for member in [
                "FUN_00100000", "FUN_00100020", "FUN_00100040", "FUN_00100060", "FUN_00100080"
            ]
        },
        "owners": {
            member: owner for member, owner in [
                ("FUN_00100000", "crate_a"), ("FUN_00100020", "crate_a"),
                ("FUN_00100040", "crate_a"), ("FUN_00100060", "crate_b"),
                ("FUN_00100080", "crate_b"),
            ]
        },
        "cross_origin_aliases": [],
    }
    report = score_family_label_propagation(
        catalog, labels, prediction, oxidizer_labels_sha256=labels_sha
    )
    assert report["direct"]["correct_count"] == 1
    assert report["propagated"]["correct_count"] == 2
    assert report["metrics"]["newly_correct_member_count"] == 2
    assert report["gt_upper_bound"]["mixed_family_count"] == 1


def _catalog(*, owner_a="crate_a", include=(
    "FUN_00100000", "FUN_00100020", "FUN_00100040", "FUN_00100060", "FUN_00100080"
)):
    include = set(include)
    origins = []
    for origin, members in (
        ("origin_a", ["FUN_00100000", "FUN_00100020", "FUN_00100040"]),
        ("origin_b", ["FUN_00100060", "FUN_00100080"]),
    ):
        selected = [member for member in members if member in include]
        if selected:
            origins.append({"origin": origin, "members": selected})
    members = sorted(include)
    return {
        "schema_version": 1,
        "case": "demo",
        "build": "O3S",
        "profile": "plain",
        "scope": "all-rust",
        "root_namespace": "demo",
        "id_bias": DEFAULT_ID_BIAS,
        "provenance": {
            "build_id": "test",
            "source_sha256": "c" * 64,
            "non_stripped_sha256": "d" * 64,
            "stripped_sha256": STRIPPED,
        },
        "source": "demo",
        "origins": origins,
        "symbols": {member: [member] for member in members},
        "owners": {
            member: (owner_a if member < "FUN_00100060" else "crate_b")
            for member in members
        },
        "cross_origin_aliases": [],
    }


def test_evaluation_provenance_distinguishes_identical_strict_and_rescue_metrics():
    family = _family()
    labels = _labels([])
    labels_sha = _sha(labels)
    strict = _build(family, labels, labels_sha=labels_sha)
    rescue, family_sha = _rescue(
        family,
        [
            {"id": "F1", "members": family["clusters"][0]["members"], "origin": "strict"},
            {"id": "F2", "members": family["clusters"][1]["members"], "origin": "strict"},
        ],
    )
    rescued = _build(
        family,
        labels,
        rescue,
        family_sha=family_sha,
        labels_sha=labels_sha,
    )

    strict_report = score_family_label_propagation(
        _catalog(),
        labels,
        strict,
        oxidizer_labels_sha256=labels_sha,
        family_label_propagation_sha256="4" * 64,
    )
    rescue_report = score_family_label_propagation(
        _catalog(),
        labels,
        rescued,
        oxidizer_labels_sha256=labels_sha,
        family_label_propagation_sha256="5" * 64,
    )

    for key in ("direct", "propagated", "combined", "metrics", "gt_upper_bound"):
        assert strict_report[key] == rescue_report[key]
    assert strict_report["provenance"]["family_label_propagation_sha256"] == "4" * 64
    assert rescue_report["provenance"]["family_label_propagation_sha256"] == "5" * 64
    assert strict_report["provenance"]["method"] == "strict"
    assert rescue_report["provenance"]["method"] == "rescue"
    assert strict_report != rescue_report


def test_raw_labels_sha_binds_prediction_to_scoring():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    prediction = _build(family, labels, labels_sha="7" * 64)
    try:
        score_family_label_propagation(
            _catalog(), labels, prediction, oxidizer_labels_sha256="8" * 64
        )
    except ValueError as exc:
        assert "SHA-256" in str(exc) or "hash" in str(exc)
    else:
        raise AssertionError("a different raw labels file was accepted for scoring")


def test_scoring_reconstructs_and_compares_exact_direct_baseline():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    labels_sha = _sha(labels)
    prediction = _build(family, labels, labels_sha=labels_sha)
    prediction["direct_labels"][0]["canonical_origin"] = "other"
    first = next(item for item in prediction["families"] if item["id"] == "F1")
    first["canonical_origin"] = "other"
    first["seed_labels"][0]["canonical_origin"] = "other"
    for item in prediction["propagated_labels"]:
        if item["family"] == "F1":
            item["canonical_origin"] = "other"
    try:
        score_family_label_propagation(
            _catalog(), labels, prediction, oxidizer_labels_sha256=labels_sha
        )
    except ValueError as exc:
        assert "direct" in str(exc)
    else:
        raise AssertionError("a semantically different direct baseline was accepted")


def test_owner_only_propagation_mismatch_counts_as_wrong_family():
    family = _family()
    labels = _labels([_match(0, "origin_a", "wrong_owner")])
    labels_sha = _sha(labels)
    prediction = _build(family, labels, labels_sha=labels_sha)
    report = score_family_label_propagation(
        _catalog(), labels, prediction, oxidizer_labels_sha256=labels_sha
    )
    assert report["metrics"]["wrongly_propagated_member_count"] == 2
    assert report["metrics"]["wrongly_propagated_family_count"] == 1


def test_gt_upper_bound_uses_only_correct_direct_seeds():
    family = _family()
    labels = _labels([_match(0, "wrong_origin", "crate_a")])
    labels_sha = _sha(labels)
    prediction = _build(family, labels, labels_sha=labels_sha)
    report = score_family_label_propagation(
        _catalog(), labels, prediction, oxidizer_labels_sha256=labels_sha
    )
    assert report["gt_upper_bound"]["mixed_family_count"] == 0
    assert report["gt_upper_bound"]["newly_propagatable_member_count"] == 0


def test_gt_upper_bound_does_not_overwrite_an_incorrect_direct_label():
    family = _family()
    labels = _labels([
        _match(0, "origin_a", "crate_a"),
        _match(0x20, "wrong_origin", "crate_a"),
    ])
    labels_sha = _sha(labels)
    prediction = _build(family, labels, labels_sha=labels_sha)
    report = score_family_label_propagation(
        _catalog(), labels, prediction, oxidizer_labels_sha256=labels_sha
    )
    upper = report["gt_upper_bound"]
    assert upper["newly_propagatable_member_count"] == 1
    assert upper["families"][0]["unknown_members"] == ["FUN_00100040"]


def test_unknown_propagated_member_fails_closed():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    labels_sha = _sha(labels)
    prediction = _build(family, labels, labels_sha=labels_sha)
    try:
        score_family_label_propagation(
            _catalog(include=("FUN_00100000", "FUN_00100020")),
            labels,
            prediction,
            oxidizer_labels_sha256=labels_sha,
        )
    except ValueError as exc:
        assert "propagated" in str(exc)
    else:
        raise AssertionError("an unknown propagated member was accepted")


def test_eligible_requires_an_unlabeled_sibling_and_reports_selected_overlap():
    family = _family()
    labels = _labels([
        _match(0, "origin_a", "crate_a"),
        _match(0x20, "origin_a", "crate_a"),
        _match(0x40, "origin_a", "crate_a"),
        _match(0xA0, "provisional", "crate_x"),
    ])
    artifact = _build(family, labels)
    first = next(item for item in artifact["families"] if item["id"] == "F1")
    assert first["status"] == "fully-labeled"
    assert artifact["opportunity"]["eligible_family_count"] == 0
    assert artifact["opportunity"]["direct_seed_in_universe_count"] == 4
    assert artifact["opportunity"]["direct_seed_in_selected_partition_count"] == 3


def test_prediction_schema_and_derived_fields_are_exact():
    artifact = _build(_family(), _labels([_match(0, "origin_a", "crate_a")]))
    extra = copy.deepcopy(artifact)
    extra["unexpected"] = True
    stale = copy.deepcopy(artifact)
    stale["opportunity"]["propagated_member_count"] += 1
    wrong_status = copy.deepcopy(artifact)
    wrong_status["families"][0]["status"] = "no-seed"
    for invalid in (extra, stale, wrong_status):
        try:
            validate_propagation_artifact(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid prediction schema/derived state was accepted")


def test_f6_schema_status_members_and_f7_version_are_required():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    for mutate in (
        lambda value: value.pop("status_members"),
        lambda value: value.update({"unexpected": True}),
        lambda value: value["status_members"]["accepted"].pop(),
    ):
        invalid = copy.deepcopy(family)
        mutate(invalid)
        try:
            _build(invalid, labels)
        except ValueError:
            pass
        else:
            raise AssertionError("an invalid F6 schema/status_members was accepted")

    rescue, family_sha = _rescue(
        family,
        [
            {"id": "F1", "members": family["clusters"][0]["members"], "origin": "strict"},
            {"id": "F2", "members": family["clusters"][1]["members"], "origin": "strict"},
        ],
    )
    rescue.pop("rescue_rule_version")
    try:
        _build(family, labels, rescue, family_sha=family_sha)
    except ValueError:
        pass
    else:
        raise AssertionError("an F7 artifact without its rescue version was accepted")


def test_output_order_is_independent_of_input_order():
    family = _family()
    labels = _labels([
        _match(0, "origin_a", "crate_a"),
        _match(0x20, "different", "crate_b"),
        _match(0x60, "origin_b", "crate_b"),
    ])
    reversed_family = copy.deepcopy(family)
    reversed_family["clusters"].reverse()
    for cluster in reversed_family["clusters"]:
        cluster["members"].reverse()
    reversed_labels = copy.deepcopy(labels)
    reversed_labels["matches"].reverse()
    hashes = {"family_sha": "4" * 64, "labels_sha": "5" * 64}
    assert _build(family, labels, **hashes) == _build(
        reversed_family, reversed_labels, **hashes
    )


def test_file_api_records_raw_byte_hashes_and_cli_stdout_is_json():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        family_path = root / "family.json"
        labels_path = root / "labels.json"
        family_path.write_text(json.dumps(family, indent=4) + "\n", encoding="utf-8")
        labels_path.write_text(json.dumps(labels, separators=(",", ":")), encoding="utf-8")
        artifact = build_propagation_files(family_path, labels_path)
        assert artifact["provenance"]["family_artifact_sha256"] == hashlib.sha256(
            family_path.read_bytes()
        ).hexdigest()
        assert artifact["provenance"]["oxidizer_labels_sha256"] == hashlib.sha256(
            labels_path.read_bytes()
        ).hexdigest()
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parents[1] / "analysis" / "v1_family_label_propagation.py"),
                "--family-artifact", str(family_path),
                "--oxidizer-labels", str(labels_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
        assert json.loads(completed.stdout)["artifact"] == "v1-family-label-propagation"
        assert "method=" in completed.stderr


def test_scoring_cli_rejects_a_different_raw_labels_artifact():
    family = _family()
    labels = _labels([_match(0, "origin_a", "crate_a")])
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        family_path = root / "family.json"
        original_labels_path = root / "labels-original.json"
        different_labels_path = root / "labels-different.json"
        catalog_path = root / "catalog.json"
        prediction_path = root / "prediction.json"
        output_path = root / "audit.json"
        family_path.write_text(json.dumps(family), encoding="utf-8")
        original_labels_path.write_text(json.dumps(labels), encoding="utf-8")
        different_labels_path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
        catalog_path.write_text(json.dumps(_catalog()), encoding="utf-8")
        prediction = build_propagation_files(family_path, original_labels_path)
        prediction_path.write_text(json.dumps(prediction), encoding="utf-8")
        command = [
            sys.executable,
            str(Path(__file__).parents[1] / "flirt_audit.py"),
            "demo",
            "--catalog", str(catalog_path),
            "--prediction", str(prediction_path),
            "--output", str(output_path),
        ]
        success = subprocess.run(
            [*command, "--labels", str(original_labels_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert success.returncode == 0, success.stderr
        assert json.loads(success.stdout)["family_label_propagation"]["artifact"] == (
            "v1-family-label-propagation-evaluation"
        )
        assert "family label propagation:" in success.stderr
        completed = subprocess.run(
            [*command, "--labels", str(different_labels_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 1
        assert "raw-file SHA-256 mismatch" in completed.stderr


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("family label propagation tests PASS")
