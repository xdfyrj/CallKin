from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.v1_multiview_eval import evaluate_multiview_artifacts  # noqa: E402
from v1_candidates import (  # noqa: E402
    MultiViewCandidatePair,
    PairKey,
    build_multiview_candidate_artifact,
)


def _artifact(view: str, pairs: list[MultiViewCandidatePair]):
    return build_multiview_candidate_artifact(
        case="case",
        build="O3S",
        profile="plain",
        scope="rust-nonstd",
        bodies={
            member: type("Body", (), {"complete": True})()
            for member in ("FUN_A", "FUN_B", "FUN_C")
        },
        pairs=pairs,
        top_k=1,
        views=(view,),
        provenance={"stripped_sha256": "a" * 64},
        relation={"mode": "out-in"},
    )


def _pair(first: str, second: str, view: str):
    return MultiViewCandidatePair(
        pair=PairKey.make(first, second),
        views={view: {"score": 1.0, "rank": 1}},
        reasons={f"{view}_top_k"},
    )


def test_multiview_evaluator_reports_each_view_and_union():
    token = _artifact("token", [_pair("FUN_A", "FUN_B", "token")])
    cfg = _artifact("cfg", [_pair("FUN_A", "FUN_C", "cfg")])
    union = build_multiview_candidate_artifact(
        case="case",
        build="O3S",
        profile="plain",
        scope="rust-nonstd",
        bodies={
            member: type("Body", (), {"complete": True})()
            for member in ("FUN_A", "FUN_B", "FUN_C")
        },
        pairs=[
            MultiViewCandidatePair(
                pair=PairKey.make("FUN_A", "FUN_B"),
                views={"token": {"score": 1.0, "rank": 1}, "cfg": None},
                reasons={"token_top_k"},
            ),
            MultiViewCandidatePair(
                pair=PairKey.make("FUN_A", "FUN_C"),
                views={"token": None, "cfg": {"score": 1.0, "rank": 1}},
                reasons={"cfg_top_k"},
            ),
        ],
        top_k=1,
        views=("token", "cfg"),
        provenance={"stripped_sha256": "a" * 64},
        relation={"mode": "out-in"},
    )
    ground_truth = {
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "provenance": {"stripped_sha256": "a" * 64},
        "origins": [
            {"origin": "origin_ab", "members": ["FUN_A", "FUN_B"]},
            {"origin": "origin_c", "members": ["FUN_C"]},
        ],
    }

    report = evaluate_multiview_artifacts(
        {"token": token, "cfg": cfg, "union": union},
        ground_truth,
    )
    by_name = {item["name"]: item for item in report["variants"]}
    assert by_name["token"]["metrics"]["candidate_pair_recall"] == 1.0
    assert by_name["cfg"]["metrics"]["candidate_pair_recall"] == 0.0
    assert by_name["union"]["metrics"]["candidate_pair_recall"] == 1.0
    assert by_name["union"]["metrics"]["candidate_pair_count"] == 2
    assert by_name["token"]["views"] == ["token"]


def test_multiview_evaluator_rejects_mixed_provenance():
    token = _artifact("token", [_pair("FUN_A", "FUN_B", "token")])
    cfg = _artifact("cfg", [_pair("FUN_A", "FUN_C", "cfg")])
    cfg["provenance"] = {"stripped_sha256": "b" * 64}
    ground_truth = {
        "case": "case",
        "build": "O3S",
        "profile": "plain",
        "origins": [
            {"origin": "origin_ab", "members": ["FUN_A", "FUN_B"]},
        ],
    }
    try:
        evaluate_multiview_artifacts(
            {"token": token, "cfg": cfg},
            ground_truth,
        )
    except ValueError as exc:
        assert "same" in str(exc) or "identity" in str(exc)
    else:
        raise AssertionError("mixed provenance was accepted")


def main() -> int:
    test_multiview_evaluator_reports_each_view_and_union()
    test_multiview_evaluator_rejects_mixed_provenance()
    print("V1 multiview evaluation PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
