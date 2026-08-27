from __future__ import annotations

import json
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import parse_body  # noqa: E402
from v1_candidates import (  # noqa: E402
    PairKey,
    _cheap_profile_signature,
    _symmetric_top_k,
    build_candidate_artifact,
    build_cheap_profiles,
    cheap_body_similarity,
    generate_candidate_pairs,
)


def _body(item_id: str, mnemonics: list[str], constants: list[int] | None = None):
    constants = list(constants or [])
    instructions = [
        {
            "offset": index,
            "size": 1,
            "mnemonic_class": mnemonic,
            "operands": [],
            "control_flow": "return" if mnemonic == "RET" else "fallthrough",
            "branch_target_offset": None,
            "slots": [],
            "constants": constants if index == 0 else [],
        }
        for index, mnemonic in enumerate(mnemonics)
    ]
    return parse_body({
        "id": item_id,
        "size": len(instructions),
        "instructions": [],
        "normalized_instructions": instructions,
        "cfg_edges": [],
        "blocks": [{
            "label": "B0",
            "start_offset": 0,
            "end_offset": len(instructions),
            "instruction_offsets": list(range(len(instructions))),
        }],
        "quality": {
            "complete_decode": True,
            "opaque_indirect_jumps": 0,
        },
    })


def test_pair_key_is_canonical_and_rejects_self_pairs():
    assert PairKey.make("FUN_B", "FUN_A") == PairKey("FUN_A", "FUN_B")
    try:
        PairKey.make("FUN_A", "FUN_A")
    except ValueError as exc:
        assert "self pair" in str(exc)
    else:
        raise AssertionError("self pair was accepted")


def test_top_k_union_deduplicates_reasons_and_does_not_make_group_cartesian_product():
    bodies = {
        f"FUN_{index:02d}": _body(
            f"FUN_{index:02d}",
            ["MOV", "RET"],
            constants=[1],
        )
        for index in range(12)
    }
    pairs = generate_candidate_pairs(
        bodies,
        top_k=2,
        final_groups=[list(bodies)],
        prior_round_groups=[(1, [list(bodies)])],
    )
    if len(pairs) >= len(bodies) * (len(bodies) - 1) // 2:
        raise AssertionError("top-k retrieval generated the full Cartesian product")
    by_key = {item.pair: item for item in pairs}
    assert len(by_key) == len(pairs)
    assert any("body_top_k" in item.reasons for item in pairs)
    assert any("same_final_color" in item.reasons for item in pairs)
    assert any("same_prior_round_color" in item.reasons for item in pairs)
    for item in pairs:
        assert item.pair.left < item.pair.right
        assert item.reasons == set(item.reasons)


def test_body_top_k_reaches_a_graph_abstained_function_and_exact_hash_is_only_a_reason():
    bodies = {
        "FUN_A": _body("FUN_A", ["MOV", "RET"], constants=[1]),
        "FUN_B": _body("FUN_B", ["MOV", "RET"], constants=[1]),
        "FUN_X": _body("FUN_X", ["MOV", "RET"], constants=[1]),
    }
    pairs = generate_candidate_pairs(
        bodies,
        top_k=1,
        final_groups=[["FUN_A", "FUN_B"]],
    )
    abstained_pair = next(
        item for item in pairs
        if "FUN_X" in (item.pair.left, item.pair.right)
    )
    assert "body_top_k" in abstained_pair.reasons
    assert "same_exact_mnemonic_hash" in abstained_pair.reasons


def test_candidate_artifact_is_deterministic_and_contains_the_full_target_universe():
    bodies = {
        "FUN_B": _body("FUN_B", ["MOV", "RET"], constants=[1]),
        "FUN_A": _body("FUN_A", ["MOV", "RET"], constants=[1]),
    }
    pairs = generate_candidate_pairs(bodies, top_k=1)
    artifact = build_candidate_artifact(
        case="case",
        build="O3S",
        profile="plain",
        scope="rust-nonstd",
        bodies=bodies,
        pairs=pairs,
        top_k=1,
        provenance={"stripped_sha256": "a" * 64},
    )
    assert artifact["universe"]["target_ids"] == ["FUN_A", "FUN_B"]
    assert artifact["universe"]["target_count"] == 2
    assert artifact["pairs"] == sorted(
        artifact["pairs"], key=lambda item: (item["first"], item["second"])
    )
    assert json.loads(json.dumps(artifact)) == artifact


def test_grouped_top_k_matches_individual_pair_scoring():
    bodies = {
        f"FUN_{index:02d}": _body(
            f"FUN_{index:02d}",
            ["MOV", "RET"] if index % 2 == 0 else ["ADD", "RET"],
            constants=[index % 3],
        )
        for index in range(12)
    }
    profiles = build_cheap_profiles(bodies)
    members = sorted(bodies)
    expected = _symmetric_top_k(
        members,
        top_k=3,
        score=lambda first, second: cheap_body_similarity(
            profiles[first], profiles[second]
        ),
    )
    grouped = _symmetric_top_k(
        members,
        top_k=3,
        score=lambda first, second: cheap_body_similarity(
            profiles[first], profiles[second]
        ),
        group_key=lambda member: _cheap_profile_signature(profiles[member]),
    )
    assert grouped == expected


def main() -> int:
    tests = [
        test_pair_key_is_canonical_and_rejects_self_pairs,
        test_top_k_union_deduplicates_reasons_and_does_not_make_group_cartesian_product,
        test_body_top_k_reaches_a_graph_abstained_function_and_exact_hash_is_only_a_reason,
        test_candidate_artifact_is_deterministic_and_contains_the_full_target_universe,
        test_grouped_top_k_matches_individual_pair_scoring,
    ]
    for test in tests:
        test()
    print("V1 candidate generator PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
