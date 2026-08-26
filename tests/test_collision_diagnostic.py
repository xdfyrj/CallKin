from __future__ import annotations

import json
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.f45_collision import (  # noqa: E402
    build_collision_report,
    build_partition_artifact,
    build_arg_parser,
    cluster_id_for_members,
    _validate_requested_partition_config,
    _score_components,
    _cfg_features,
)
from body_similarity import parse_body  # noqa: E402
from paths import f45_partition_for, f45_result_for  # noqa: E402


def _body(item_id: str, mnemonic: str):
    instructions = [
        {
            "offset": 0,
            "size": 1,
            "mnemonic_class": mnemonic,
            "operands": ["REG64"],
            "control_flow": "fallthrough",
            "branch_target_offset": None,
            "slots": [],
            "constants": [1 if mnemonic == "MOV" else 2],
        },
        {
            "offset": 1,
            "size": 1,
            "mnemonic_class": "RET",
            "operands": [],
            "control_flow": "return",
            "branch_target_offset": None,
            "slots": [],
            "constants": [],
        },
    ]
    return parse_body({
        "id": item_id,
        "size": 2,
        "instructions": [],
        "normalized_instructions": instructions,
        "cfg_edges": [],
        "blocks": [{
            "label": "B0",
            "start_offset": 0,
            "end_offset": 2,
            "instruction_offsets": [0, 1],
        }],
        "quality": {
            "complete_decode": True,
            "opaque_indirect_jumps": 0,
        },
    })


def _body_artifact(bodies):
    functions = []
    for body in bodies.values():
        functions.append({
            "id": body.id,
            "size": body.size,
            "instructions": [],
            "normalized_instructions": list(body.instructions),
            "cfg_edges": list(body.edges),
            "blocks": list(body.blocks),
            "quality": body.quality,
        })
    return {
        "schema_version": 2,
        "case": "collision",
        "build": "O3S",
        "profile": "plain",
        "scope": "subject",
        "provenance": {
            "stripped_sha256": "a" * 64,
            "candidate_selection_sha256": "b" * 64,
            "raw_graph_sha256": "c" * 64,
        },
        "functions": functions,
    }


def test_cfg_features_ignore_opcode_but_detect_shape_change():
    same_shape = _cfg_features(_body("FUN_A", "MOV"), _body("FUN_B", "NOP"))
    if same_shape["cfg_block_count_ratio"] != 1.0:
        raise AssertionError(same_shape)
    if same_shape["cfg_edge_count_ratio"] != 1.0:
        raise AssertionError(same_shape)
    if same_shape["cfg_color_multiset_jaccard"] != 1.0:
        raise AssertionError(same_shape)
    different_shape = parse_body({
        "id": "FUN_BRANCH",
        "size": 2,
        "instructions": [],
        "normalized_instructions": list(_body("TMP", "MOV").instructions),
        "cfg_edges": [{"source": "B0", "target": "B1", "kind": "fallthrough"}],
        "blocks": [
            {"label": "B0", "start_offset": 0, "end_offset": 1,
             "instruction_offsets": [0]},
            {"label": "B1", "start_offset": 1, "end_offset": 2,
             "instruction_offsets": [1]},
        ],
        "quality": {"complete_decode": True, "opaque_indirect_jumps": 0},
    })
    changed = _cfg_features(_body("FUN_A", "MOV"), different_shape)
    if changed["cfg_block_count_ratio"] >= 1.0 or changed["cfg_edge_count_ratio"] >= 1.0:
        raise AssertionError(changed)


def test_score_conditions_use_the_declared_feature_layers():
    comparison = {
        "instruction_count_ratio": 0.91,
        "mnemonic_multiset_jaccard": 0.92,
        "mnemonic_ngram_jaccard": 0.93,
        "sequence_ratio": 0.94,
        "aligned_block_ratio": 0.95,
        "aligned_instruction_ratio": 0.96,
        "edge_consistency": 0.97,
        "cfg_block_count_ratio": 0.98,
        "cfg_edge_count_ratio": 0.99,
        "cfg_color_multiset_jaccard": 0.88,
        "constant_slot_consistency": 0.77,
        "call_slot_shape_consistency": 0.66,
        "data_reference_consistency": 0.55,
        # This diagnostic value must not affect any declared condition.
        "operand_slot_consistency": 0.01,
    }
    scores = _score_components(comparison)
    if scores != {
        "structure_only": 0.88,
        "slot_only": 0.55,
        "combined": 0.55,
    }:
        raise AssertionError(scores)


def test_f45_cli_defaults_to_c212_configuration():
    args = build_arg_parser().parse_args(["ripgrep-main"])
    if args.mode != "out-in" or args.track != "angr":
        raise AssertionError((args.mode, args.track))
    if args.candidate_scope != "rust-nonstd" or args.anchor_policy != "role":
        raise AssertionError((args.candidate_scope, args.anchor_policy))
    partition_path = f45_partition_for("ripgrep-main")
    result_path = f45_result_for("ripgrep-main")
    for path in (partition_path, result_path):
        if "angr.rust-nonstd.role.out-in" not in path:
            raise AssertionError(path)


def test_partition_config_cannot_be_relabelled_as_canonical():
    partition = build_partition_artifact(
        case="collision",
        build="O3S",
        profile="plain",
        mode="full",
        clusters={"old": ["FUN_A"]},
        source={
            "analysis": {
                "track": "direct",
                "candidate_scope": "subject",
                "anchor_policy": "address",
            },
        },
    )
    try:
        _validate_requested_partition_config(
            partition,
            track="angr",
            candidate_scope="rust-nonstd",
            anchor_policy="role",
            mode="out-in",
        )
    except ValueError as exc:
        if "partition/mode mismatch" not in str(exc):
            raise AssertionError(exc)
    else:
        raise AssertionError("non-canonical partition configuration was accepted")


def test_cluster_id_is_order_independent_and_partition_hides_old_name():
    first = cluster_id_for_members(["FUN_B", "FUN_A"])
    second = cluster_id_for_members(["FUN_A", "FUN_B"])
    if first != second or not first.startswith("cluster_"):
        raise AssertionError((first, second))

    artifact = build_partition_artifact(
        case="collision",
        build="O3S",
        profile="plain",
        mode="full",
        clusters={"C212": ["FUN_B", "FUN_A"]},
    )
    cluster = artifact["clusters"][0]
    if cluster["id"] != first or cluster["members"] != ["FUN_A", "FUN_B"]:
        raise AssertionError(cluster)
    if "C212" in json.dumps(artifact, sort_keys=True):
        raise AssertionError("temporary V0 cluster name leaked into artifact")


def test_collision_report_scores_all_pairs_and_keeps_mistake_examples():
    bodies = {
        "FUN_A": _body("FUN_A", "MOV"),
        "FUN_B": _body("FUN_B", "MOV"),
        "FUN_C": _body("FUN_C", "MOV"),
        "FUN_D": _body("FUN_D", "NOP"),
    }
    members = list(bodies)
    partition = build_partition_artifact(
        case="collision",
        build="O3S",
        profile="plain",
        mode="full",
        clusters={"C212": members},
        source={
            "analysis": {
                "candidate_scope": "subject",
                "raw_graph_sha256": "c" * 64,
                "candidate_selection_sha256": "b" * 64,
            },
        },
    )
    gt = {
        "case": "collision",
        "build": "O3S",
        "profile": "plain",
        "scope": "subject",
        "provenance": {"stripped_sha256": "a" * 64},
        "origins": [
            {"origin": "origin_a", "members": ["FUN_A", "FUN_B"]},
            {"origin": "origin_b", "members": ["FUN_C", "FUN_D"]},
        ],
    }
    report = build_collision_report(
        partition=partition,
        body_artifact=_body_artifact(bodies),
        ground_truth=gt,
        cluster_id=partition["clusters"][0]["id"],
        threshold=0.8,
        expected_same_pairs=2,
        expected_different_pairs=4,
        examples_per_type=3,
    )
    if report["pair_count"] != 6:
        raise AssertionError(report["pair_count"])
    if report["ground_truth"]["same_origin_pairs"] != 2:
        raise AssertionError(report["ground_truth"])
    if report["ground_truth"]["origin_count"] != 2:
        raise AssertionError(report["ground_truth"])
    found_fp = False
    found_fn = False
    for condition in ("structure_only", "slot_only", "combined"):
        scores = report["conditions"][condition]
        if scores["tp"] + scores["fp"] + scores["fn"] + scores["tn"] != 6:
            raise AssertionError(scores)
        found_fp |= bool(scores["false_positive_examples"])
        found_fn |= bool(scores["false_negative_examples"])
        if scores["score_distribution"]["positive"]["count"] != 2:
            raise AssertionError(scores["score_distribution"])
    if not found_fp or not found_fn:
        raise AssertionError((found_fp, found_fn))
    if json.loads(json.dumps(report)) != report:
        raise AssertionError("collision report is not JSON-safe")

    for key in ("raw_graph_sha256", "candidate_selection_sha256"):
        mismatched = json.loads(json.dumps(_body_artifact(bodies)))
        mismatched["provenance"][key] = "d" * 64
        try:
            build_collision_report(
                partition=partition,
                body_artifact=mismatched,
                ground_truth=gt,
                cluster_id=partition["clusters"][0]["id"],
                threshold=0.8,
                expected_same_pairs=2,
                expected_different_pairs=4,
            )
        except ValueError as exc:
            if f"{key} mismatch" not in str(exc):
                raise AssertionError(exc)
        else:
            raise AssertionError(f"partition/body {key} mismatch was accepted")


CHECKS = {
    "partition_hash": test_cluster_id_is_order_independent_and_partition_hides_old_name,
    "structure_only": test_cfg_features_ignore_opcode_but_detect_shape_change,
    "feature_layers": test_score_conditions_use_the_declared_feature_layers,
    "cli_defaults": test_f45_cli_defaults_to_c212_configuration,
    "config_guard": test_partition_config_cannot_be_relabelled_as_canonical,
    "collision_report": test_collision_report_scores_all_pairs_and_keeps_mistake_examples,
}


def main() -> int:
    requested = sys.argv[1:] or list(CHECKS)
    for name in requested:
        check = CHECKS.get(name)
        if check is None:
            print(f"FAIL unknown collision diagnostic check: {name}")
            return 1
        try:
            check()
        except Exception as exc:
            print(f"FAIL {name}: {exc}")
            return 1
    print("F4.5 collision diagnostic PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
