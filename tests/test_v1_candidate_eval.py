from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.v1_candidate_eval import (  # noqa: E402
    evaluate_candidate_artifact,
    evaluate_candidate_sweep,
)
from analysis.v1_pair_eval import (  # noqa: E402
    evaluate_family_artifact,
    select_development_policy,
)
from v1_candidates import CandidatePair, PairKey, build_candidate_artifact  # noqa: E402


def _candidate_artifact(top_k: int):
    members = ["FUN_A", "FUN_B"] + [f"FUN_{index:03d}" for index in range(98)]
    pair = CandidatePair(
        pair=PairKey.make("FUN_A", "FUN_B"),
        reasons={"body_top_k"},
        body_rank=1,
    )
    return build_candidate_artifact(
        case="case",
        build="O3S",
        profile="plain",
        scope="subject",
        bodies={
            member: type("Body", (), {"complete": True})()
            for member in members
        },
        pairs=[pair],
        top_k=top_k,
        provenance={
            "stripped_sha256": "a" * 64,
            "body_evidence_sha256": "b" * 64,
            "candidate_selection_sha256": "c" * 64,
            "raw_graph_sha256": "d" * 64,
            "projection_config_sha256": "e" * 64,
            "fixture_sha256": "f" * 64,
            "track": "angr",
            "anchor_policy": "role",
        },
        relation={"mode": "out-in"},
    )


def _ground_truth():
    return {
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "provenance": {"stripped_sha256": "a" * 64},
        "origins": [
            {"origin": "origin_a", "members": ["FUN_A", "FUN_B"]},
            *[
                {"origin": f"origin_{index:03d}", "members": [f"FUN_{index:03d}"]}
                for index in range(98)
            ],
        ],
    }


def test_candidate_evaluation_uses_one_adjacency_pass():
    report = evaluate_candidate_artifact(_candidate_artifact(8), _ground_truth())
    metrics = report["metrics"]
    assert metrics["total_pair_count"] == 4950
    assert metrics["same_origin_pair_count"] == 1
    assert metrics["candidate_same_origin_pair_count"] == 1
    assert metrics["candidate_pair_recall"] == 1.0
    assert report["gate_b"]["passed"] is True


def test_candidate_sweep_selects_smallest_gate_passing_top_k():
    report = evaluate_candidate_sweep(
        {8: _candidate_artifact(8), 16: _candidate_artifact(16)},
        _ground_truth(),
    )
    assert report["selection"]["selected_top_k"] == 8
    assert report["selection"]["gate_b_passed"] is True
    assert [item["top_k"] for item in report["runs"]] == [8, 16]


def test_candidate_sweep_rejects_provenance_mismatch():
    first = _candidate_artifact(8)
    second = _candidate_artifact(16)
    second["provenance"]["raw_graph_sha256"] = "x" * 64
    try:
        evaluate_candidate_sweep({8: first, 16: second}, _ground_truth())
    except ValueError as exc:
        assert "same binary/configuration" in str(exc)
    else:
        raise AssertionError("provenance mismatch was accepted")


def test_mixed_accepted_cluster_is_not_counted_as_correct_family_coverage():
    pair_decisions = [
        {"pair": ["FUN_A", "FUN_B"], "decision": "match"},
        {"pair": ["FUN_A", "FUN_C"], "decision": "match"},
        {"pair": ["FUN_B", "FUN_C"], "decision": "match"},
    ]
    artifact = {
        "schema_version": 1,
        "artifact": "v1-family-grouping",
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "scope": "subject",
        "config": {},
        "provenance": {"stripped_sha256": "a" * 64},
        "universe": {
            "target_count": 3,
            "target_ids": ["FUN_A", "FUN_B", "FUN_C"],
        },
        "clusters": [{
            "id": "family_mixed",
            "status": "accepted",
            "members": ["FUN_A", "FUN_B", "FUN_C"],
        }],
        "status_members": {
            "accepted": ["FUN_A", "FUN_B", "FUN_C"],
            "provisional": [],
            "unresolved": [],
            "abstain": [],
        },
        "pair_decisions": pair_decisions,
        "blocked_merges": [],
        "metrics": {},
    }
    ground_truth = {
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "provenance": {"stripped_sha256": "a" * 64},
        "origins": [
            {"origin": "origin_a", "members": ["FUN_A", "FUN_B"]},
            {"origin": "origin_b", "members": ["FUN_C"]},
        ],
    }
    report = evaluate_family_artifact(artifact, ground_truth)
    by_origin = {
        item["origin"]: item for item in report["accepted_family_coverage"]
    }
    assert by_origin["origin_a"]["accepted_participation_count"] == 2
    assert by_origin["origin_a"]["correctly_accepted_member_count"] == 0
    assert by_origin["origin_a"]["exact_family_recovered"] is False
    assert report["metrics"]["correctly_accepted_member_count"] == 0


def test_development_threshold_selection_combines_multiple_cases():
    feature = {
        "pair": ["FUN_A", "FUN_B"],
        "structure_score": 1.0,
        "aligned_instruction_ratio": 1.0,
        "sequence_ratio": 1.0,
        "mnemonic_multiset_jaccard": 1.0,
        "constant_similarity": 1.0,
        "call_shape_similarity": None,
        "data_reference_similarity": None,
        "same_final_color": None,
        "same_prior_color": None,
        "same_out_signature": None,
        "same_in_signature": None,
        "both_complete": True,
        "opaque_indirect_jumps": 0,
    }

    def family(case: str):
        return {
            "schema_version": 1,
            "artifact": "v1-family-grouping",
            "case": case,
            "build": "O3S",
            "profile": "plain",
            "scope": "subject",
            "config": {},
            "provenance": {"stripped_sha256": "a" * 64},
            "universe": {"target_count": 2, "target_ids": ["FUN_A", "FUN_B"]},
            "clusters": [],
            "status_members": {
                "accepted": [],
                "provisional": [],
                "unresolved": ["FUN_A", "FUN_B"],
                "abstain": [],
            },
            "pair_decisions": [{
                "pair": ["FUN_A", "FUN_B"],
                "decision": "unknown",
                "features": feature,
                "source": "candidate",
            }],
            "blocked_merges": [],
            "metrics": {},
        }

    def truth(case: str):
        return {
            "case": case,
            "build": "O3S",
            "profile": "plain",
            "provenance": {"stripped_sha256": "a" * 64},
            "origins": [{"origin": "origin_a", "members": ["FUN_A", "FUN_B"]}],
        }

    selected = select_development_policy(
        [family("dev-a"), family("dev-b")],
        [truth("dev-a"), truth("dev-b")],
    )
    assert selected["selection_split"] == "development"
    assert selected["development_pair_count"] == 2
    assert len(selected["development_cases"]) == 2
    assert selected["policy"]["source"] == "development-grid"


def main() -> int:
    test_candidate_evaluation_uses_one_adjacency_pass()
    test_candidate_sweep_selects_smallest_gate_passing_top_k()
    test_candidate_sweep_rejects_provenance_mismatch()
    test_mixed_accepted_cluster_is_not_counted_as_correct_family_coverage()
    test_development_threshold_selection_combines_multiple_cases()
    print("V1 candidate evaluation PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
