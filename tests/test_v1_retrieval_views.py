from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import parse_body  # noqa: E402
from v1_candidates import (  # noqa: E402
    build_multiview_candidate_artifact,
    generate_multiview_candidate_pairs,
    validate_candidate_artifact,
)
from v1_retrieval_views import (  # noqa: E402
    MULTI_VIEW_NAMES,
    build_cfg_profiles,
    build_relation_profiles,
    build_token_profiles,
    cfg_similarity,
    relation_similarity,
    token_similarity,
)


def _body(
    item_id: str,
    instructions: list[dict],
    *,
    blocks: list[dict] | None = None,
    edges: list[dict] | None = None,
):
    if blocks is None:
        blocks = [{
            "label": "B0",
            "start_offset": instructions[0]["offset"] if instructions else 0,
            "end_offset": instructions[-1]["offset"] + 1 if instructions else 0,
            "instruction_offsets": [item["offset"] for item in instructions],
        }]
    return parse_body({
        "id": item_id,
        "size": sum(item.get("size", 1) for item in instructions),
        "instructions": [],
        "normalized_instructions": instructions,
        "cfg_edges": edges or [],
        "blocks": blocks,
        "quality": {
            "complete_decode": True,
            "opaque_indirect_jumps": 0,
        },
    })


def _mov_ret(item_id: str, *, offset: int = 0, width: str = "64"):
    return _body(item_id, [
        {
            "offset": offset,
            "size": 3,
            "mnemonic_class": "MOV",
            "operands": [f"reg{width}", f"mem{width}"],
            "control_flow": "fallthrough",
            "branch_target_offset": None,
            "slots": [],
            "constants": [],
        },
        {
            "offset": offset + 3,
            "size": 1,
            "mnemonic_class": "RET",
            "operands": [],
            "control_flow": "return",
            "branch_target_offset": None,
            "slots": [],
            "constants": [],
        },
    ])


def test_token_view_ignores_offsets_but_keeps_operand_shape():
    bodies = {
        "FUN_A": _mov_ret("FUN_A", offset=0),
        "FUN_B": _mov_ret("FUN_B", offset=100),
        "FUN_C": _mov_ret("FUN_C", width="32"),
    }
    profiles = build_token_profiles(bodies)
    assert token_similarity(profiles["FUN_A"], profiles["FUN_B"]) == 1.0
    assert token_similarity(profiles["FUN_A"], profiles["FUN_C"]) < 1.0


def test_cfg_view_uses_topology_and_not_block_labels():
    common_instructions = [
        {
            "offset": 0,
            "size": 1,
            "mnemonic_class": "CMP",
            "operands": ["reg64", "reg64"],
            "control_flow": "conditional",
            "branch_target_offset": 2,
            "slots": [],
            "constants": [],
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
    body_a = _body(
        "FUN_A",
        common_instructions,
        blocks=[
            {"label": "B0", "start_offset": 0, "end_offset": 1, "instruction_offsets": [0]},
            {"label": "B1", "start_offset": 1, "end_offset": 2, "instruction_offsets": [1]},
        ],
        edges=[{"kind": "fallthrough", "source": "B0", "target": "B1"}],
    )
    body_b = _body(
        "FUN_B",
        common_instructions,
        blocks=[
            {"label": "X", "start_offset": 0, "end_offset": 1, "instruction_offsets": [0]},
            {"label": "Y", "start_offset": 1, "end_offset": 2, "instruction_offsets": [1]},
        ],
        edges=[{"kind": "fallthrough", "source": "X", "target": "Y"}],
    )
    body_c = _mov_ret("FUN_C")
    profiles = build_cfg_profiles({"FUN_A": body_a, "FUN_B": body_b, "FUN_C": body_c})
    assert cfg_similarity(profiles["FUN_A"], profiles["FUN_B"]) == 1.0
    assert cfg_similarity(profiles["FUN_A"], profiles["FUN_C"]) < 1.0


def test_relation_view_does_not_read_body_profiles():
    profiles = build_relation_profiles(
        ["FUN_A", "FUN_B", "FUN_C"],
        final_groups=[["FUN_A", "FUN_B"], ["FUN_C"]],
        prior_round_groups=[(1, [["FUN_A", "FUN_B"], ["FUN_C"]])],
        final_round=2,
        out_signatures={
            "FUN_A": (("FUN_C", 1),),
            "FUN_B": (("FUN_C", 1),),
            "FUN_C": (),
        },
        in_signatures={
            "FUN_A": (),
            "FUN_B": (),
            "FUN_C": (("FUN_A", 1), ("FUN_B", 1)),
        },
    )
    assert relation_similarity(profiles["FUN_A"], profiles["FUN_B"]) == 1.0
    assert relation_similarity(profiles["FUN_A"], profiles["FUN_C"]) < 1.0

    reordered = build_relation_profiles(
        ["FUN_A", "FUN_B", "FUN_C"],
        final_groups=[["FUN_C"], ["FUN_B", "FUN_A"]],
        prior_round_groups=[(1, [["FUN_C"], ["FUN_B", "FUN_A"]])],
        final_round=2,
        out_signatures={
            "FUN_A": (("FUN_C", 1),),
            "FUN_B": (("FUN_C", 1),),
            "FUN_C": (),
        },
        in_signatures={
            "FUN_A": (),
            "FUN_B": (),
            "FUN_C": (("FUN_A", 1), ("FUN_B", 1)),
        },
    )
    assert profiles["FUN_A"] == reordered["FUN_A"]


def test_empty_views_do_not_turn_missing_evidence_into_a_match():
    empty = _body("EMPTY", [])
    body = _mov_ret("BODY")
    token_profiles = build_token_profiles({"EMPTY": empty, "BODY": body})
    cfg_profiles = build_cfg_profiles({"EMPTY": empty, "BODY": body})
    relation_profiles = build_relation_profiles(["EMPTY", "BODY"])

    assert token_similarity(token_profiles["EMPTY"], token_profiles["EMPTY"]) == 0.0
    assert cfg_similarity(cfg_profiles["EMPTY"], cfg_profiles["EMPTY"]) == 0.0
    assert relation_similarity(
        relation_profiles["EMPTY"], relation_profiles["EMPTY"]
    ) == 0.0


def test_relation_view_does_not_create_candidates_without_evidence():
    bodies = {
        "FUN_A": _mov_ret("FUN_A"),
        "FUN_B": _mov_ret("FUN_B", offset=100),
        "FUN_C": _mov_ret("FUN_C", offset=200),
    }
    pairs = generate_multiview_candidate_pairs(
        bodies,
        top_k=1,
        views=("relation",),
    )
    assert pairs == []


def test_relation_abstained_member_is_not_forced_into_top_k():
    bodies = {
        "FUN_A": _mov_ret("FUN_A"),
        "FUN_B": _mov_ret("FUN_B", offset=100),
        "FUN_C": _mov_ret("FUN_C", offset=200),
    }
    pairs = generate_multiview_candidate_pairs(
        bodies,
        top_k=1,
        views=("relation",),
        final_groups=[["FUN_A", "FUN_B"]],
        prior_round_groups=[(1, [["FUN_A", "FUN_B"]])],
        final_round=2,
    )
    assert {
        tuple(item.pair.to_list()) for item in pairs
    } == {("FUN_A", "FUN_B")}
    assert all(
        "FUN_C" not in item.pair.to_list() for item in pairs
    )
    assert all(
        value["score"] > 0.0
        for item in pairs
        for value in item.views.values()
        if value is not None
    )


def test_relation_view_preserves_distinct_anchor_classes():
    profiles = build_relation_profiles(
        ["FUN_A", "FUN_B"],
        final_groups=[["FUN_A", "FUN_B"]],
        final_round=1,
        out_signatures={
            "FUN_A": (("ANCHOR_ROOT", 1),),
            "FUN_B": (("ANCHOR_OUT", 1),),
        },
        anchor_classes={
            "ANCHOR_ROOT": "ROLE:root",
            "ANCHOR_OUT": "ROLE:outgoing",
        },
    )
    assert profiles["FUN_A"].out_signature != profiles["FUN_B"].out_signature
    assert relation_similarity(profiles["FUN_A"], profiles["FUN_B"]) < 1.0


def test_multiview_union_records_independent_view_scores():
    bodies = {
        "FUN_A": _mov_ret("FUN_A"),
        "FUN_B": _mov_ret("FUN_B", offset=100),
        "FUN_C": _mov_ret("FUN_C", width="32"),
    }
    pairs = generate_multiview_candidate_pairs(
        bodies,
        top_k=1,
        views=("composite", "token", "cfg", "relation"),
        final_groups=[["FUN_A", "FUN_B"], ["FUN_C"]],
        prior_round_groups=[(1, [["FUN_A", "FUN_B"], ["FUN_C"]])],
        final_round=2,
        out_signatures={"FUN_A": (), "FUN_B": (), "FUN_C": ()},
        in_signatures={"FUN_A": (), "FUN_B": (), "FUN_C": ()},
    )
    assert pairs
    assert any("token_top_k" in item.reasons for item in pairs)
    assert all(set(item.views) == {"composite", "token", "cfg", "relation"} for item in pairs)
    assert all(
        any(value is not None for value in item.views.values())
        for item in pairs
    )

    artifact = build_multiview_candidate_artifact(
        case="case",
        build="O3S",
        profile="plain",
        scope="rust-nonstd",
        bodies=bodies,
        pairs=pairs,
        top_k=1,
        views=("composite", "token", "cfg", "relation"),
        provenance={"stripped_sha256": "a" * 64},
        relation={"mode": "out-in"},
    )
    assert artifact["schema_version"] == 2
    assert artifact["artifact"] == "v1-multiview-candidate-pairs"
    validate_candidate_artifact(artifact)


def test_multiview_generation_is_deterministic_under_input_reordering():
    bodies = {
        "FUN_A": _mov_ret("FUN_A"),
        "FUN_B": _mov_ret("FUN_B", offset=100),
        "FUN_C": _mov_ret("FUN_C", width="32"),
    }
    kwargs = {
        "top_k": 1,
        "views": ("composite", "token", "cfg", "relation"),
        "final_groups": [["FUN_A", "FUN_B"], ["FUN_C"]],
        "prior_round_groups": [(1, [["FUN_A", "FUN_B"], ["FUN_C"]])],
        "final_round": 2,
        "out_signatures": {"FUN_A": (), "FUN_B": (), "FUN_C": ()},
        "in_signatures": {"FUN_A": (), "FUN_B": (), "FUN_C": ()},
    }
    first = generate_multiview_candidate_pairs(bodies, **kwargs)
    second = generate_multiview_candidate_pairs(
        dict(reversed(list(bodies.items()))),
        **kwargs,
    )
    assert [item.to_dict() for item in first] == [item.to_dict() for item in second]


def test_multi_view_names_exclude_composite_baseline():
    assert MULTI_VIEW_NAMES == ("token", "cfg", "relation")
    assert "composite" not in MULTI_VIEW_NAMES


def main() -> int:
    tests = [
        test_token_view_ignores_offsets_but_keeps_operand_shape,
        test_cfg_view_uses_topology_and_not_block_labels,
        test_relation_view_does_not_read_body_profiles,
        test_empty_views_do_not_turn_missing_evidence_into_a_match,
        test_relation_view_does_not_create_candidates_without_evidence,
        test_relation_abstained_member_is_not_forced_into_top_k,
        test_relation_view_preserves_distinct_anchor_classes,
        test_multiview_union_records_independent_view_scores,
        test_multiview_generation_is_deterministic_under_input_reordering,
        test_multi_view_names_exclude_composite_baseline,
    ]
    for test in tests:
        test()
    print("V1 retrieval views PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
