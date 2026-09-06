from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import parse_body  # noqa: E402
from v1_candidates import (  # noqa: E402
    MultiViewCandidatePair,
    PairKey,
    build_multiview_candidate_artifact,
)
from v1_engine import (  # noqa: E402
    ABSTAIN,
    MATCH,
    REJECT,
    UNKNOWN,
    PairFeatures,
    PairPolicyConfig,
    PairEvidenceCache,
    build_family_artifact,
    classify_pair,
    family_id_for_members,
    pair_features_from_bodies,
)


def _body(item_id: str, *, constant: int | None, complete: bool = True):
    slots = []
    if constant is not None:
        slots.append({
            "kind": "data",
            "value": "DATA_SLOT",
            "status": "resolved",
            "resolver": "fixture",
        })
    instruction = {
        "offset": 0,
        "size": 1,
        "mnemonic_class": "MOV",
        "operands": [],
        "control_flow": "fallthrough",
        "branch_target_offset": None,
        "slots": slots,
        "constants": [] if constant is None else [constant],
    }
    ret = {
        "offset": 1,
        "size": 1,
        "mnemonic_class": "RET",
        "operands": [],
        "control_flow": "return",
        "branch_target_offset": None,
        "slots": [],
        "constants": [],
    }
    return parse_body({
        "id": item_id,
        "size": 2,
        "instructions": [],
        "normalized_instructions": [instruction, ret],
        "cfg_edges": [],
        "blocks": [{
            "label": "B0",
            "start_offset": 0,
            "end_offset": 2,
            "instruction_offsets": [0, 1],
        }],
        "quality": {
            "complete_decode": complete,
            "opaque_indirect_jumps": 0,
        },
    })


def _config():
    return PairPolicyConfig(
        structure_match_threshold=0.8,
        slot_match_threshold=0.8,
        structure_reject_threshold=None,
    )


def _candidate_pair(first: str, second: str):
    pair = PairKey.make(first, second)
    return {
        "pair": pair.to_list(),
        "first": pair.left,
        "second": pair.right,
        "reasons": ["body_top_k"],
        "cheap_score": 1.0,
        "body_rank": 1,
        "relation_rank": None,
        "last_shared_round": None,
        "same_out_signature": None,
        "same_in_signature": None,
        "same_final_color": None,
        "same_prior_color": None,
    }


def test_empty_empty_slots_are_unknown_evidence_not_one():
    features = pair_features_from_bodies(
        _body("FUN_A", constant=None),
        _body("FUN_B", constant=None),
    )
    assert features.constant_similarity is None
    assert features.data_reference_similarity is None
    assert classify_pair(features, _config()) == UNKNOWN


def test_data_or_constant_mismatch_is_unknown_not_reject():
    features = pair_features_from_bodies(
        _body("FUN_A", constant=1),
        _body("FUN_B", constant=2),
    )
    assert features.structure_score == 1.0
    assert features.constant_similarity == 0.0
    assert classify_pair(features, _config()) == UNKNOWN


def test_incomplete_body_abstains():
    features = pair_features_from_bodies(
        _body("FUN_A", constant=1, complete=False),
        _body("FUN_B", constant=1),
    )
    assert features.both_complete is False
    assert classify_pair(features, _config()) == ABSTAIN


def test_opaque_indirect_cfg_abstains_by_default():
    first = _body("FUN_A", constant=1)
    second = _body("FUN_B", constant=1)
    second.quality["opaque_indirect_jumps"] = 1
    features = pair_features_from_bodies(first, second)
    assert features.opaque_indirect_jumps == 1
    assert classify_pair(features, _config()) == ABSTAIN
    cache = PairEvidenceCache(
        {"FUN_A": first, "FUN_B": second},
        [_candidate_pair("FUN_A", "FUN_B")],
        _config(),
    )
    evaluation = cache.get_evaluation("FUN_A", "FUN_B")
    assert evaluation.decision == ABSTAIN
    assert cache.abstain_comparisons == 1
    assert cache.candidate_comparisons == 0

    candidate = {
        "schema_version": 1,
        "artifact": "v1-candidate-pairs",
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "scope": "subject",
        "config": {
            "top_k": 1,
            "body_profile": "mnemonic+size+block",
            "ngram_size": 3,
        },
        "provenance": {},
        "universe": {
            "target_count": 2,
            "complete_body_count": 2,
            "incomplete_ids": [],
            "target_ids": ["FUN_A", "FUN_B"],
        },
        "pairs": [_candidate_pair("FUN_A", "FUN_B")],
    }
    report = build_family_artifact(
        candidate_artifact=candidate,
        bodies={"FUN_A": first, "FUN_B": second},
        config=_config(),
    )
    assert report["status_members"]["abstain"] == ["FUN_B"]
    assert report["status_members"]["unresolved"] == ["FUN_A"]
    assert report["abstain_reasons"] == {
        "FUN_B": "opaque_indirect_jump",
    }
    assert report["metrics"]["abstain_comparison_count"] == 1
    assert report["metrics"]["candidate_detailed_comparison_count"] == 0


def test_cache_memoizes_on_demand_comparisons():
    bodies = {
        "FUN_A": _body("FUN_A", constant=1),
        "FUN_B": _body("FUN_B", constant=1),
    }
    cache = PairEvidenceCache(bodies, candidate_pairs=[], config=_config())
    assert cache.get_or_compare("FUN_A", "FUN_B") == MATCH
    assert cache.get_or_compare("FUN_B", "FUN_A") == MATCH
    assert cache.on_demand_comparisons == 1
    assert cache.cache_hits == 1


def test_complete_link_does_not_merge_a_match_chain_when_cross_pair_is_unknown():
    bodies = {
        "FUN_A": _body("FUN_A", constant=1),
        "FUN_B": _body("FUN_B", constant=1),
        "FUN_C": _body("FUN_C", constant=2),
    }
    candidate = {
        "schema_version": 1,
        "artifact": "v1-candidate-pairs",
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "scope": "subject",
        "config": {
            "top_k": 1,
            "body_profile": "mnemonic+size+block",
            "ngram_size": 3,
        },
        "provenance": {},
        "universe": {
            "target_count": 3,
            "complete_body_count": 3,
            "incomplete_ids": [],
            "target_ids": ["FUN_A", "FUN_B", "FUN_C"],
        },
        "pairs": [
            _candidate_pair("FUN_A", "FUN_B"),
            _candidate_pair("FUN_B", "FUN_C"),
        ],
    }

    def provider(pair: PairKey):
        common = dict(
            pair=pair,
            structure_score=1.0,
            aligned_instruction_ratio=1.0,
            sequence_ratio=1.0,
            mnemonic_multiset_jaccard=1.0,
            constant_similarity=1.0,
            call_shape_similarity=None,
            data_reference_similarity=1.0,
            same_final_color=None,
            same_prior_color=None,
            same_out_signature=None,
            same_in_signature=None,
            both_complete=True,
            opaque_indirect_jumps=0,
        )
        if pair == PairKey("FUN_A", "FUN_C"):
            common["constant_similarity"] = 0.0
        return PairFeatures(**common)

    report = build_family_artifact(
        candidate_artifact=candidate,
        bodies=bodies,
        config=_config(),
        feature_provider=provider,
    )
    accepted = [item for item in report["clusters"] if item["status"] == "accepted"]
    assert all(len(item["members"]) < 3 for item in accepted)
    assert set(report["status_members"]["accepted"]) == {"FUN_A", "FUN_B"}
    assert set(report["status_members"]["provisional"]) == {"FUN_C"}
    assert report["status_members"]["abstain"] == []


def test_family_id_and_all_cross_pairs_match_are_deterministic():
    assert family_id_for_members(["FUN_B", "FUN_A"]) == family_id_for_members(
        ["FUN_A", "FUN_B"]
    )
    bodies = {
        "FUN_A": _body("FUN_A", constant=1),
        "FUN_B": _body("FUN_B", constant=1),
        "FUN_C": _body("FUN_C", constant=1),
    }
    candidate = {
        "schema_version": 1,
        "artifact": "v1-candidate-pairs",
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "scope": "subject",
        "config": {
            "top_k": 2,
            "body_profile": "mnemonic+size+block",
            "ngram_size": 3,
        },
        "provenance": {},
        "universe": {
            "target_count": 3,
            "complete_body_count": 3,
            "incomplete_ids": [],
            "target_ids": ["FUN_A", "FUN_B", "FUN_C"],
        },
        "pairs": [
            _candidate_pair("FUN_B", "FUN_A"),
            _candidate_pair("FUN_C", "FUN_A"),
        ],
    }
    report = build_family_artifact(
        candidate_artifact=candidate,
        bodies=bodies,
        config=_config(),
    )
    accepted = [item for item in report["clusters"] if item["status"] == "accepted"]
    assert accepted[0]["members"] == ["FUN_A", "FUN_B", "FUN_C"]
    assert all(
        decision["decision"] == MATCH
        for decision in report["pair_decisions"]
        if decision["pair"] in (["FUN_A", "FUN_B"], ["FUN_A", "FUN_C"], ["FUN_B", "FUN_C"])
    )


def test_f6_consumes_multiview_candidate_artifact():
    bodies = {
        "FUN_A": _body("FUN_A", constant=1),
        "FUN_B": _body("FUN_B", constant=1),
    }
    pair = MultiViewCandidatePair(
        pair=PairKey.make("FUN_A", "FUN_B"),
        views={"token": {"score": 1.0, "rank": 1}},
        reasons={"token_top_k"},
    )
    candidate = build_multiview_candidate_artifact(
        case="case",
        build="O3S",
        profile="plain",
        scope="subject",
        bodies=bodies,
        pairs=[pair],
        top_k=1,
        views=("token",),
        provenance={},
    )
    report = build_family_artifact(
        candidate_artifact=candidate,
        bodies=bodies,
        config=_config(),
    )
    accepted = [item for item in report["clusters"] if item["status"] == "accepted"]
    assert accepted[0]["members"] == ["FUN_A", "FUN_B"]


def main() -> int:
    tests = [
        test_empty_empty_slots_are_unknown_evidence_not_one,
        test_data_or_constant_mismatch_is_unknown_not_reject,
        test_incomplete_body_abstains,
        test_opaque_indirect_cfg_abstains_by_default,
        test_cache_memoizes_on_demand_comparisons,
        test_complete_link_does_not_merge_a_match_chain_when_cross_pair_is_unknown,
        test_family_id_and_all_cross_pairs_match_are_deterministic,
        test_f6_consumes_multiview_candidate_artifact,
    ]
    for test in tests:
        test()
    print("V1 family engine PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
