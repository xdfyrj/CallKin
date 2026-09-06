from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.v1_retrieval_miss import audit_retrieval  # noqa: E402
from body_similarity import parse_body  # noqa: E402
from v1_candidates import CandidatePair, PairKey, build_candidate_artifact  # noqa: E402


def _body(item_id: str, mnemonics: list[str], *, block_count: int = 1):
    instructions = [
        {
            "offset": index,
            "size": 1,
            "mnemonic_class": mnemonic,
            "operands": [],
            "control_flow": "return" if mnemonic == "RET" else "fallthrough",
            "branch_target_offset": None,
            "slots": [],
            "constants": [],
        }
        for index, mnemonic in enumerate(mnemonics)
    ]
    blocks = []
    for block_index in range(block_count):
        start = block_index * max(1, len(instructions) // block_count)
        end = (
            len(instructions)
            if block_index == block_count - 1
            else (block_index + 1) * max(1, len(instructions) // block_count)
        )
        blocks.append({
            "label": f"B{block_index}",
            "start_offset": start,
            "end_offset": end,
            "instruction_offsets": list(range(start, end)),
        })
    return parse_body({
        "id": item_id,
        "size": len(instructions),
        "instructions": [],
        "normalized_instructions": instructions,
        "cfg_edges": [],
        "blocks": blocks,
        "quality": {
            "complete_decode": True,
            "opaque_indirect_jumps": 0,
        },
    })


def _inputs():
    bodies = {
        "FUN_A": _body("FUN_A", ["MOV", "ADD", "RET"]),
        "FUN_B": _body("FUN_B", ["MOV", "ADD", "RET"]),
        "FUN_C": _body("FUN_C", ["MOV", "SUB", "RET"], block_count=2),
        "FUN_D": _body("FUN_D", ["XOR", "RET"]),
    }
    pair = CandidatePair(
        pair=PairKey.make("FUN_A", "FUN_B"),
        reasons={"body_top_k", "same_final_color"},
        cheap_score=1.0,
        body_rank=1,
    )
    candidate = build_candidate_artifact(
        case="case",
        build="O3S",
        profile="plain",
        scope="rust-nonstd",
        bodies=bodies,
        pairs=[pair],
        top_k=64,
        provenance={"stripped_sha256": "a" * 64},
        relation={"mode": "out-in"},
    )
    ground_truth = {
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "provenance": {"stripped_sha256": "a" * 64},
        "origins": [
            {"origin": "origin_read", "members": ["FUN_A", "FUN_B", "FUN_C"]},
            {"origin": "origin_other", "members": ["FUN_D"]},
        ],
    }
    relation = {
        "mode": "out-in",
        "final_groups": [["FUN_A", "FUN_B"], ["FUN_C"], ["FUN_D"]],
        "prior_round_groups": [
            (1, [["FUN_A", "FUN_B", "FUN_C"], ["FUN_D"]]),
        ],
        "final_round": 2,
    }
    return candidate, ground_truth, bodies, relation


def test_miss_audit_reports_family_coverage_and_member_gaps():
    candidate, ground_truth, bodies, relation = _inputs()
    report = audit_retrieval(
        candidate,
        ground_truth,
        bodies,
        relation_context=relation,
    )
    assert report["artifact"] == "v1-retrieval-miss-audit"
    assert report["metrics"]["family_count"] == 2
    assert report["metrics"]["same_origin_pair_count"] == 3
    assert report["metrics"]["found_same_origin_pair_count"] == 1
    assert report["metrics"]["missed_same_origin_pair_count"] == 2
    assert report["metrics"]["candidate_pair_recall"] == 1 / 3
    assert report["metrics"]["member_without_candidate_count"] == 2
    assert report["metrics"]["multimember_family_count"] == 1
    assert report["metrics"]["multimember_member_count"] == 3
    assert report["metrics"]["member_without_same_origin_candidate_count"] == 1
    assert report["metrics"]["same_origin_member_coverage"] == 2 / 3
    assert report["metrics"]["connected_family_rate"] == 0.0

    family = next(
        item for item in report["families"] if item["origin"] == "origin_read"
    )
    assert family["member_count"] == 3
    assert family["members_without_candidate"] == ["FUN_C"]
    assert family["members_without_same_origin_candidate"] == ["FUN_C"]
    assert family["same_origin_member_coverage"] == 2 / 3
    assert family["found_pair_count"] == 1
    assert family["missed_pair_count"] == 2
    assert family["candidate_graph_connected"] is False
    assert family["same_exact_mnemonic_hash_pair_count"] == 1
    assert family["missed_pair_body_summary"]["count"] == 2
    assert "median" in family["missed_pair_body_summary"]["size_difference"]
    assert "p75" in family["missed_pair_body_summary"]["size_difference"]
    assert "p90" in family["missed_pair_body_summary"]["size_difference"]


def test_miss_audit_records_source_and_wl_features_for_each_pair():
    candidate, ground_truth, bodies, relation = _inputs()
    report = audit_retrieval(
        candidate,
        ground_truth,
        bodies,
        relation_context=relation,
    )
    family = next(
        item for item in report["families"] if item["origin"] == "origin_read"
    )
    pairs = {tuple(item["pair"]): item for item in family["pairs"]}
    found = pairs[("FUN_A", "FUN_B")]
    assert found["found"] is True
    assert found["retrieval_sources"] == ["body_top_k", "same_final_color"]
    assert found["same_final_color"] is True
    assert found["same_prior_color"] is True
    assert found["exact_mnemonic_hash_equal"] is True
    assert found["body"]["mnemonic_ngram_jaccard"] == 1.0

    missed = pairs[("FUN_B", "FUN_C")]
    assert missed["found"] is False
    assert missed["retrieval_sources"] == []
    assert missed["same_final_color"] is False
    assert missed["same_prior_color"] is True
    assert missed["exact_mnemonic_hash_equal"] is False
    assert missed["body"]["block_count_difference"] == 1


def test_miss_audit_reports_exact_mnemonic_collision_totals():
    candidate, ground_truth, bodies, relation = _inputs()
    bodies["FUN_E"] = _body("FUN_E", ["MOV", "ADD", "RET"])
    ground_truth["origins"][1]["members"].append("FUN_E")
    candidate = build_candidate_artifact(
        case="case",
        build="O3S",
        profile="plain",
        scope="rust-nonstd",
        bodies=bodies,
        pairs=[
            CandidatePair(
                pair=PairKey.make("FUN_A", "FUN_B"),
                reasons={"body_top_k"},
                cheap_score=1.0,
                body_rank=1,
            )
        ],
        top_k=64,
        provenance={"stripped_sha256": "a" * 64},
        relation={"mode": "out-in"},
    )

    report = audit_retrieval(
        candidate,
        ground_truth,
        bodies,
        relation_context=relation,
    )

    assert report["metrics"]["largest_exact_mnemonic_bucket_size"] == 3
    assert report["metrics"]["exact_mnemonic_all_pair_count"] == 3
    assert report["metrics"]["exact_mnemonic_cross_origin_pair_count"] == 2


def main() -> int:
    test_miss_audit_reports_family_coverage_and_member_gaps()
    test_miss_audit_records_source_and_wl_features_for_each_pair()
    test_miss_audit_reports_exact_mnemonic_collision_totals()
    print("V1 retrieval miss audit PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
