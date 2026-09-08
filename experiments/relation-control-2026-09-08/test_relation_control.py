"""Tiny protocol checks for the relation-control selection and replay helpers."""

from __future__ import annotations

import copy
import builtins
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from body_similarity import parse_body
from relation_control import (  # noqa: E402
    BodyFeatureCache,
    cost_summary,
    make_control_artifact,
    pair_stratum,
    select_control_pairs,
    strata_counts,
    run_f6_pair,
)
from v1_candidates import PairKey
from v1_engine import PairPolicyConfig, pair_features_from_bodies


def body(
    function_id: str,
    *,
    complete: bool = True,
    opaque: int = 0,
    instructions: int = 2,
):
    normalized = [
        {
            "offset": index,
            "size": 1,
            "mnemonic_class": "MOV" if index + 1 < instructions else "RET",
            "operands": [],
            "control_flow": "fallthrough" if index + 1 < instructions else "return",
            "branch_target_offset": None,
            "slots": [
                {
                    "kind": "data",
                    "status": "resolved",
                    "value": "DATA_SLOT",
                    "resolver": "fixture",
                }
            ],
            "constants": [],
        }
        for index in range(instructions)
    ]
    return parse_body(
        {
            "id": function_id,
            "size": instructions,
            "instructions": [],
            "normalized_instructions": normalized,
            "cfg_edges": [],
            "blocks": [
                {
                    "label": "B0",
                    "start_offset": 0,
                    "end_offset": instructions,
                    "instruction_offsets": list(range(instructions)),
                }
            ],
            "quality": {
                "complete_decode": complete,
                "opaque_indirect_jumps": opaque,
            },
        }
    )


def candidate_pair(first: str, second: str, *, token: float, cfg: float):
    pair = PairKey.make(first, second)
    return {
        "pair": pair.to_list(),
        "first": pair.left,
        "second": pair.right,
        "reasons": ["cfg_top_k", "token_top_k"],
        "views": {
            "cfg": {"rank": 1, "score": cfg},
            "token": {"rank": 1, "score": token},
        },
        "last_shared_round": None,
        "same_out_signature": None,
        "same_in_signature": None,
        "same_final_color": None,
        "same_prior_color": None,
    }


def candidate_artifact(records, target_ids):
    return {
        "schema_version": 2,
        "artifact": "v1-multiview-candidate-pairs",
        "case": "toy",
        "build": "O3S",
        "profile": "plain",
        "scope": "subject",
        "config": {
            "top_k": 16,
            "view_top_k": {"token": 16, "cfg": 16},
            "views": ["token", "cfg"],
            "view_profiles": {
                "token": "token-v2-no-sequence",
                "cfg": "cfg-v2-digested-topology",
            },
        },
        "provenance": {},
        "universe": {
            "target_count": len(target_ids),
            "complete_body_count": len(target_ids),
            "incomplete_ids": [],
            "target_ids": sorted(target_ids),
        },
        "pairs": list(records),
    }


def policy():
    return PairPolicyConfig(
        structure_match_threshold=0.95,
        slot_match_threshold=1.0,
        max_comparison_count=100,
        max_alignment_cell_budget=1000,
    )


def test_strata_split_eligibility_and_cost_bins():
    bodies = {
        "A": body("A", instructions=2),
        "B": body("B", instructions=2),
        "C": body("C", opaque=1),
        "D": body("D", complete=False),
    }
    assert pair_stratum(PairKey.make("A", "B"), bodies) == (
        "complete/noopaque",
        (2, 0),
    )
    assert pair_stratum(PairKey.make("A", "C"), bodies) == (
        "abstain",
        ("opaque",),
    )
    assert pair_stratum(PairKey.make("C", "D"), bodies) == (
        "abstain",
        ("incomplete", "opaque"),
    )
    counts = strata_counts(
        [
            {"pair": ["A", "B"]},
            {"pair": ["A", "C"]},
            {"pair": ["C", "D"]},
        ],
        bodies,
    )
    assert counts[("complete/noopaque", (2, 0))] == 1
    assert counts[("abstain", ("opaque",))] == 1
    assert counts[("abstain", ("incomplete", "opaque"))] == 1


def test_controls_are_reproducible_and_body_score_sorted_without_gt():
    bodies = {name: body(name) for name in "ABCDEF"}
    records = [
        candidate_pair("A", name, token=score, cfg=score - 0.1)
        for name, score in zip("BCDEF", (0.7, 0.9, 0.8, 0.6, 0.95))
    ]
    body2 = candidate_artifact(records, bodies)
    treatment = candidate_artifact(records[:2], bodies)
    selected_a = select_control_pairs(
        body2,
        treatment,
        bodies,
        seed="relation-control-2026-09-08/0",
    )
    selected_b = select_control_pairs(
        body2,
        treatment,
        bodies,
        seed="relation-control-2026-09-08/0",
    )
    assert selected_a == selected_b
    assert selected_a["quotas"] == {("complete/noopaque", (2, 0)): 2}
    assert all(
        len(selected_a[name]) == sum(selected_a["quotas"].values())
        for name in ("random", "body-score")
    )
    assert ["A", "F"] in [record["pair"] for record in selected_a["body-score"]]
    assert "ground_truth" not in selected_a


def test_control_choice_ignores_adversarial_labels_and_relation_flags():
    bodies = {name: body(name) for name in "ABCDEF"}
    records = [
        candidate_pair("A", name, token=score, cfg=score - 0.1)
        for name, score in zip("BCDEF", (0.7, 0.9, 0.8, 0.6, 0.95))
    ]
    body2 = candidate_artifact(records, bodies)
    treatment = candidate_artifact(records[:2], bodies)
    baseline = select_control_pairs(body2, treatment, bodies, seed="seed")
    adversarial_body2 = copy.deepcopy(body2)
    adversarial_treatment = copy.deepcopy(treatment)
    adversarial_body2["provenance"]["audit_labels"] = {
        "ground_truth": [["A", "B"]],
        "linkage": [["A", "C"]],
    }
    for artifact in (adversarial_body2, adversarial_treatment):
        for record in artifact["pairs"]:
            record["same_final_color"] = True
            record["same_prior_color"] = False
            record["same_out_signature"] = True
            record["same_in_signature"] = False
    original_open = builtins.open
    builtins.open = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("selection attempted a file read")
    )
    try:
        adversarial = select_control_pairs(
            adversarial_body2,
            adversarial_treatment,
            bodies,
            seed="seed",
        )
    finally:
        builtins.open = original_open
    assert adversarial["quotas"] == baseline["quotas"]
    for arm in ("random", "body-score"):
        assert [record["pair"] for record in adversarial[arm]] == [
            record["pair"] for record in baseline[arm]
        ]


def test_control_artifact_preserves_body2_views_and_quota():
    bodies = {name: body(name) for name in "ABC"}
    records = [candidate_pair("A", "B", token=0.9, cfg=0.8)]
    source = candidate_artifact(records, bodies)
    control = make_control_artifact(source, records, "body-score", {"quota": 1})
    assert control["config"]["views"] == ["token", "cfg"]
    assert control["universe"] == source["universe"]
    assert control["pairs"] == records
    assert control["provenance"]["relation_control"]["arm"] == "body-score"


def test_cached_and_uncached_f6_have_same_partition_and_cost():
    bodies = {"A": body("A"), "B": body("B"), "C": body("C")}
    records = [
        candidate_pair("A", "B", token=0.9, cfg=0.8),
        candidate_pair("B", "C", token=0.8, cfg=0.7),
    ]
    artifact = candidate_artifact(records, bodies)
    fresh, fresh_cache = run_f6_pair(artifact, bodies, policy())
    feature_cache = BodyFeatureCache(
        bodies,
        {PairKey.make("A", "B"): pair_features_from_bodies(bodies["A"], bodies["B"])},
    )
    replay, replay_cache = run_f6_pair(
        artifact,
        bodies,
        policy(),
        feature_cache=feature_cache,
    )
    assert fresh["clusters"] == replay["clusters"]
    assert fresh["status_members"] == replay["status_members"]
    assert fresh["metrics"] == replay["metrics"]
    assert fresh_cache == replay_cache
    assert fresh["metrics"]["candidate_detailed_comparison_count"] == 2
    assert fresh["metrics"]["on_demand_comparison_count"] == 1


def test_on_demand_budget_shortage_keeps_blocked_merge():
    bodies = {"A": body("A"), "B": body("B"), "C": body("C")}
    records = [
        candidate_pair("A", "B", token=0.9, cfg=0.8),
        candidate_pair("B", "C", token=0.8, cfg=0.7),
    ]
    artifact = candidate_artifact(records, bodies)
    limited = PairPolicyConfig(
        structure_match_threshold=0.95,
        slot_match_threshold=1.0,
        max_comparison_count=2,
        max_alignment_cell_budget=1000,
    )
    result, _ = run_f6_pair(artifact, bodies, limited)
    assert result["metrics"]["candidate_detailed_comparison_count"] == 2
    assert result["metrics"]["on_demand_comparison_count"] == 0
    assert result["metrics"]["budget_blocked_merge_count"] == 1


def test_cached_features_strip_old_relation_flags_and_recharge_budget():
    bodies = {"A": body("A"), "B": body("B")}
    records = [candidate_pair("A", "B", token=0.9, cfg=0.8)]
    records[0]["same_final_color"] = True
    artifact = candidate_artifact(records, bodies)
    raw = pair_features_from_bodies(bodies["A"], bodies["B"], records[0])
    raw = raw.__class__(**{**raw.__dict__, "same_final_color": False})
    cache = BodyFeatureCache(bodies, {raw.pair: raw})
    result, _ = run_f6_pair(artifact, bodies, policy(), feature_cache=cache)
    feature = result["pair_decisions"][0]["features"]
    assert feature["same_final_color"] is True
    assert result["metrics"]["candidate_detailed_comparison_count"] == 1
    assert result["metrics"]["candidate_alignment_cells"] == 4
    assert cost_summary(result)["actual_comparisons"] == 1


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_"):
            value()
    print("relation-control tiny checks PASS")
