from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.v1_feasibility import build_feasibility_report
from body_similarity import (
    FunctionBody,
    compare_bodies,
    load_body_evidence,
    parse_body,
)


def instruction(
    mnemonic_class: str,
    *,
    operands: tuple[str, ...] = ("REG64", "stack64"),
    control_flow: str = "fallthrough",
    branch_target_offset: int | None = None,
    slots: tuple[dict, ...] = (),
    constants: tuple[int, ...] = (),
) -> dict:
    return {
        "offset": 0,
        "size": 1,
        "mnemonic_class": mnemonic_class,
        "operands": list(operands),
        "control_flow": control_flow,
        "branch_target_offset": branch_target_offset,
        "slots": list(slots),
        "constants": list(constants),
    }


def simple_body(item_id: str, mnemonic_class: str) -> FunctionBody:
    instructions = [
            instruction(mnemonic_class),
            instruction("RET", control_flow="return"),
    ]
    for offset, item in enumerate(instructions):
        item["offset"] = offset
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


def check_identical_and_different_bodies() -> int:
    left = simple_body("FUN_A", "MOV")
    right = simple_body("FUN_B", "MOV")
    same = compare_bodies(left, right)
    if same.aligned_instruction_ratio != 1.0 or same.edge_consistency != 1.0:
        print(f"FAIL identical body evidence: {same.to_dict()!r}")
        return 1

    other = simple_body("FUN_C", "NOP")
    different = compare_bodies(left, other)
    if different.sequence_ratio >= same.sequence_ratio:
        print(f"FAIL different body did not lose sequence evidence: {different.to_dict()!r}")
        return 1
    return 0


def branch_body(item_id: str, first_mnemonic: str) -> FunctionBody:
    instructions = [
        instruction(first_mnemonic),
        instruction(
            "JCC",
            operands=("local_block_target",),
            control_flow="conditional_branch",
            branch_target_offset=3,
        ),
        instruction(first_mnemonic),
        instruction("RET", control_flow="return"),
    ]
    for index, item in enumerate(instructions):
        item["offset"] = (0, 1, 3, 6)[index]
        if index == 1:
            item["branch_target_offset"] = 6
    return parse_body({
        "id": item_id,
        "size": 7,
        "instructions": [],
        "normalized_instructions": instructions,
        "cfg_edges": [
            {"source": "B0", "target": "B1", "kind": "fallthrough"},
            {"source": "B0", "target": "B2", "kind": "conditional_target"},
        ],
        "blocks": [
            {"label": "B0", "start_offset": 0, "end_offset": 1,
             "instruction_offsets": [0, 1]},
            {"label": "B1", "start_offset": 3, "end_offset": 6,
             "instruction_offsets": [3]},
            {"label": "B2", "start_offset": 6, "end_offset": 7,
             "instruction_offsets": [6]},
        ],
        "quality": {
            "complete_decode": True,
            "opaque_indirect_jumps": 0,
        },
    })


def linear_body(item_id: str) -> FunctionBody:
    instructions = [
        instruction("MOV"),
        instruction("MOV"),
        instruction("RET", control_flow="return"),
    ]
    for offset, item in enumerate(instructions):
        item["offset"] = offset
    return parse_body({
        "id": item_id,
        "size": 3,
        "instructions": [],
        "normalized_instructions": instructions,
        "cfg_edges": [{"source": "B0", "target": "B1", "kind": "fallthrough"}],
        "blocks": [
            {"label": "B0", "start_offset": 0, "end_offset": 2,
             "instruction_offsets": [0, 1]},
            {"label": "B1", "start_offset": 2, "end_offset": 3,
             "instruction_offsets": [2]},
        ],
        "quality": {
            "complete_decode": True,
            "opaque_indirect_jumps": 0,
        },
    })


def check_cfg_edge_evidence() -> int:
    left = branch_body("FUN_LEFT", "MOV")
    identical = compare_bodies(left, branch_body("FUN_RIGHT", "MOV"))
    if identical.edge_consistency != 1.0:
        print(f"FAIL matching CFG was not consistent: {identical.to_dict()!r}")
        return 1

    altered = compare_bodies(left, linear_body("FUN_ALTERED"))
    if not 0.0 < altered.edge_consistency < identical.edge_consistency:
        print(f"FAIL unmatched CFG successor was not penalized: {altered.to_dict()!r}")
        return 1
    return 0


def check_edge_mapping_uses_common_coordinate_space() -> int:
    from body_similarity import FunctionBody, _edge_consistency

    blocks = tuple(
        {"label": label, "instruction_offsets": []}
        for label in ("B0", "B1", "B2")
    )
    first = FunctionBody(
        "FIRST",
        3,
        (),
        (
            {"source": "B0", "target": "B1", "kind": "conditional_target"},
            {"source": "B0", "target": "B2", "kind": "fallthrough"},
        ),
        blocks,
        {"complete_decode": True},
    )
    second = FunctionBody(
        "SECOND",
        3,
        (),
        (
            {"source": "B0", "target": "B2", "kind": "conditional_target"},
            {"source": "B0", "target": "B1", "kind": "fallthrough"},
        ),
        blocks,
        {"complete_decode": True},
    )
    mapping = [("B0", "B0"), ("B1", "B2"), ("B2", "B1")]
    score = _edge_consistency(first, second, mapping)
    if score != 1.0:
        print(f"FAIL isomorphic remapped CFG was penalized: {score!r}")
        return 1
    return 0


def check_call_targets_are_suppressed() -> int:
    from body_evidence import DecodedInstruction, normalize_instruction

    def direct_call(target: int) -> DecodedInstruction:
        return DecodedInstruction(
            offset=0,
            size=5,
            mnemonic="call",
            operand_text=f"0x{target:x}",
            operand_kinds=("immediate",),
            groups=("call",),
        )

    first_raw = direct_call(0x1000)
    second_raw = direct_call(0x2000)
    first = normalize_instruction(first_raw, function_address=0x400000)
    second = normalize_instruction(second_raw, function_address=0x400000)
    if first.token != second.token or first.token != "CALL call_target":
        print(f"FAIL call skeleton changed by target address: {first.token!r}")
        return 1
    if second_raw.operand_text == first_raw.operand_text:
        print("FAIL test did not create different raw call targets")
        return 1
    if first.slots[0].value is not None or second.slots[0].value is not None:
        print("FAIL normalized evidence leaked concrete call targets")
        return 1
    if first.constants or second.constants:
        print("FAIL call target leaked into numeric constant skeleton")
        return 1
    return 0


def _artifact() -> dict:
    stripped_sha = "a" * 64
    return {
        "schema_version": 2,
        "case": "tiny",
        "build": "O3S",
        "profile": "plain",
        "scope": "rust-nonstd",
        "provenance": {
            "stripped_sha256": stripped_sha,
            "candidate_selection_sha256": "b" * 64,
            "raw_graph_sha256": "c" * 64,
        },
        "functions": [
            _function_data("FUN_A", "MOV"),
            _function_data("FUN_B", "MOV"),
            _function_data("FUN_X", "NOP"),
            _function_data("FUN_Y", "NOP"),
        ],
    }


def _function_data(item_id: str, mnemonic_class: str) -> dict:
    instructions = [
        instruction(mnemonic_class),
        instruction(
            "RET" if mnemonic_class == "NOP" else "XOR",
            operands=() if mnemonic_class == "NOP" else ("reg64", "reg64"),
            control_flow="fallthrough",
        ),
        instruction("RET", control_flow="return"),
    ]
    for offset, item in enumerate(instructions):
        item["offset"] = offset
    return {
        "id": item_id,
        "address": "0x400000",
        "size": 3,
        "byte_sha256": hashlib.sha256(item_id.encode()).hexdigest(),
        "instructions": [],
        "normalized_instructions": instructions,
        "cfg_edges": [],
        "blocks": [{
            "label": "B0",
            "start_offset": 0,
            "end_offset": 3,
            "instruction_offsets": [0, 1, 2],
        }],
        "summary": {},
        "quality": {
            "complete_decode": True,
            "opaque_indirect_jumps": 0,
        },
    }


def check_feasibility_report_separates_tiny_diagnostic() -> int:
    artifact = _artifact()
    ground_truth = {
        "case": "tiny",
        "build": "O3S",
        "profile": "plain",
        "scope": "rust-nonstd",
        "provenance": {"stripped_sha256": "a" * 64},
        "origins": [
            {"origin": "same", "members": ["FUN_A", "FUN_B"]},
            {"origin": "other", "members": ["FUN_X", "FUN_Y"]},
        ],
    }
    report = build_feasibility_report(
        artifact=artifact,
        ground_truth=ground_truth,
        positive_origins={"same"},
        negatives_per_family=4,
        body_evidence_sha256="d" * 64,
    )
    primary = report["distributions"]["aligned_instruction_ratio"]
    if primary["positive"]["count"] != 1 or primary["negative"]["count"] != 4:
        print(f"FAIL diagnostic pair universe: {primary!r}")
        return 1
    if (
        not report["primary_separated"]
        or not report["secondary_separated"]
        or not report["separated"]
        or report["decision"] != "primary-metric-separated"
        or primary["positive"]["min"] <= primary["negative"]["p95"]
    ):
        print(f"FAIL tiny feasibility did not separate: {report['decision']!r}")
        return 1
    if json.loads(json.dumps(report)) != report:
        print("FAIL feasibility report is not JSON-safe")
        return 1
    return 0


def check_feasibility_cli_default_output_path() -> int:
    import analysis.v1_feasibility as feasibility

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        body_path = root / "body.json"
        gt_path = root / "gt.json"
        body_path.write_text(
            json.dumps(_artifact()),
            encoding="utf-8",
        )
        gt_path.write_text(
            json.dumps({
                "case": "tiny",
                "build": "O3S",
                "profile": "plain",
                "scope": "rust-nonstd",
                "provenance": {"stripped_sha256": "a" * 64},
                "origins": [
                    {"origin": "same", "members": ["FUN_A", "FUN_B"]},
                    {"origin": "other", "members": ["FUN_X", "FUN_Y"]},
                ],
            }),
            encoding="utf-8",
        )
        previous = Path.cwd()
        os.chdir(root)
        try:
            result = feasibility.main([
                "tiny",
                "--body-evidence", str(body_path),
                "--ground-truth", str(gt_path),
                "--positive-origin", "same",
                "--negatives-per-family", "0",
            ])
        finally:
            os.chdir(previous)
        expected = root / "results/tiny/plain/v1.feasibility.json"
        if result != 0 or not expected.exists():
            print(f"FAIL default feasibility output path: rc={result}, path={expected}")
            return 1
    return 0


def check_duplicate_body_ids_rejected() -> int:
    artifact = _artifact()
    artifact["functions"].append(dict(artifact["functions"][0]))
    try:
        load_body_evidence(artifact)
    except ValueError as exc:
        if "duplicate body function id" in str(exc):
            return 0
        print(f"FAIL duplicate body id raised the wrong error: {exc}")
        return 1
    print("FAIL duplicate body ids were silently overwritten")
    return 1


def check_feasibility_scope_mismatch_rejected() -> int:
    artifact = _artifact()
    ground_truth = {
        "case": "tiny",
        "build": "O3S",
        "profile": "plain",
        "scope": "subject",
        "provenance": {"stripped_sha256": "a" * 64},
        "origins": [
            {"origin": "same", "members": ["FUN_A", "FUN_B"]},
            {"origin": "other", "members": ["FUN_X", "FUN_Y"]},
        ],
    }
    try:
        build_feasibility_report(
            artifact=artifact,
            ground_truth=ground_truth,
            positive_origins={"same"},
            negatives_per_family=0,
            body_evidence_sha256="d" * 64,
        )
    except ValueError as exc:
        if "scope mismatch" in str(exc):
            return 0
        print(f"FAIL scope mismatch raised the wrong error: {exc}")
        return 1
    print("FAIL body evidence and GT with different scopes were joined")
    return 1


CHECKS = {
    "body_metrics": check_identical_and_different_bodies,
    "cfg_edge_metrics": check_cfg_edge_evidence,
    "edge_mapping_coordinates": check_edge_mapping_uses_common_coordinate_space,
    "call_target_suppression": check_call_targets_are_suppressed,
    "feasibility_report": check_feasibility_report_separates_tiny_diagnostic,
    "feasibility_default_output": check_feasibility_cli_default_output_path,
    "duplicate_body_ids": check_duplicate_body_ids_rejected,
    "feasibility_scope_mismatch": check_feasibility_scope_mismatch_rejected,
}


def main() -> int:
    requested = sys.argv[1:] or list(CHECKS)
    for name in requested:
        check = CHECKS.get(name)
        if check is None:
            print(f"FAIL unknown body similarity check: {name}")
            return 1
        if check() != 0:
            print(f"FAILED {name}")
            return 1
    print("body similarity and V1 feasibility PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
