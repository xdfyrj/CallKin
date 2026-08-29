"""V0 scored on the V1 universe with the V1 labels."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.v0_linkage_eval import (  # noqa: E402
    check_same_analysis,
    evaluate_v0,
    select_v0_run,
    v0_predicted_pairs,
    v0_target_ids,
)


ROOT = Path(__file__).resolve().parents[1]
STRIPPED = "a" * 64
ANALYSIS = {
    "track": "angr",
    "candidate_scope": "rust-nonstd",
    "anchor_policy": "role",
    "raw_graph_sha256": "b" * 64,
    "candidate_selection_sha256": "c" * 64,
    "projection_config_sha256": "d" * 64,
    "edge_policy": ["direct-immediate"],
}


def _run(clusters=None, abstentions=None, **overrides):
    record = {
        "mode": "out-in",
        "case": "demo",
        "build": "O3S",
        "profile": "plain",
        "provenance": {"stripped_sha256": STRIPPED},
        "analysis": dict(ANALYSIS),
        "clusters": clusters if clusters is not None else [
            {"cluster": "C1", "members": [{"id": "A"}, {"id": "B"}]},
            {"cluster": "C2", "members": [{"id": "C"}]},
        ],
        "abstentions": abstentions if abstentions is not None else [{"id": "D"}],
    }
    record.update(overrides)
    return record


def _v1(target_ids=("A", "B", "C", "D"), **overrides):
    record = {
        "case": "demo",
        "build": "O3S",
        "profile": "plain",
        "scope": "rust-nonstd",
        "provenance": {
            "stripped_sha256": STRIPPED,
            **{key: value for key, value in ANALYSIS.items()
               if key != "candidate_scope"},
        },
        "universe": {"target_ids": list(target_ids)},
    }
    record.update(overrides)
    return record


def _expect(callable_, expected: str):
    try:
        callable_()
    except ValueError as exc:
        assert expected in str(exc), str(exc)
    else:
        raise AssertionError(f"expected a refusal mentioning {expected!r}")


def test_only_the_out_in_run_is_used():
    result = {"results": [_run(), _run(mode="out")]}
    assert select_v0_run(result)["mode"] == "out-in"
    _expect(lambda: select_v0_run({"results": [_run(mode="out")]}), "exactly one")


def test_the_universe_is_clusters_plus_abstentions():
    assert v0_target_ids(_run()) == ["A", "B", "C", "D"]


def test_a_function_listed_twice_is_refused():
    run = _run(clusters=[{"cluster": "C1", "members": [{"id": "A"}, {"id": "A"}]}])
    _expect(lambda: v0_target_ids(run), "more than once")


def test_singletons_and_abstentions_predict_nothing():
    # Only the two-member cluster contributes a pair.
    assert v0_predicted_pairs(_run()) == {("A", "B")}


def test_mismatched_analysis_is_refused():
    _expect(
        lambda: check_same_analysis(_run(profile="min"), _v1()),
        "disagree on profile",
    )
    _expect(
        lambda: check_same_analysis(
            _run(provenance={"stripped_sha256": "e" * 64}), _v1()
        ),
        "disagree on stripped_sha256",
    )
    _expect(
        lambda: check_same_analysis(
            _run(analysis={**ANALYSIS, "raw_graph_sha256": "f" * 64}), _v1()
        ),
        "raw_graph_sha256",
    )
    _expect(
        lambda: check_same_analysis(_run(), _v1(scope="subject")),
        "candidate_scope",
    )


def test_a_different_universe_is_refused():
    _expect(
        lambda: evaluate_v0(
            {"results": [_run()]},
            _v1(target_ids=("A", "B", "C")),
            {"case": "demo", "build": "O3S", "profile": "plain", "origins": []},
            {"case": "demo", "build": "O3S", "profile": "plain", "addresses": {}},
        ),
        "target universes differ",
    )


def test_v1_grouping_is_never_read():
    # No clusters, no pair_decisions: only universe and provenance are used.
    report = evaluate_v0(
        {"results": [_run()]},
        _v1(),
        {"case": "demo", "build": "O3S", "profile": "plain", "origins": []},
        {
            "case": "demo", "build": "O3S", "profile": "plain",
            "addresses": {
                name: {"origins": ["O"], "identities": [f"M{name}"]}
                for name in ("A", "B", "C", "D")
            },
        },
    )

    assert report["predicted_pair_count"] == 1
    assert report["universe"]["target_count"] == 4
    assert report["universe"]["total_pair_count"] == 6
    primary = report["linkage_metrics"]["primary"]
    # All four share origin O with distinct identities: 6 positives, 1 found.
    assert (primary["TP"], primary["FP"], primary["FN"]) == (1, 0, 5)


def _regression(case: str, expected: dict[str, int]):
    v0_result = ROOT.parent / "v0-engine-py" / "results" / case / "plain" / (
        "angr.role.out-in.json"
    )
    v1 = ROOT / "results" / case / "plain" / f"{case}.O3S.v1.consensus3.k16.families.json"
    gt = ROOT.parent / "v0-engine-py" / "ground_truth" / "rust-nonstd" / "plain" / (
        f"{case}.O3S.gt.json"
    )
    audit = ROOT / "results" / case / "plain" / f"{case}.O3S.gt-mangled-audit.json"
    if not all(path.exists() for path in (v0_result, v1, gt, audit)):
        return
    read = lambda path: json.loads(path.read_text(encoding="utf-8"))  # noqa: E731
    report = evaluate_v0(read(v0_result), read(v1), read(gt), read(audit))
    primary = report["linkage_metrics"]["primary"]
    for name, value in expected.items():
        assert primary[name] == value, (case, name, primary[name], value)


def test_ripgrep_regression():
    _regression("ripgrep-main", {"TP": 302, "FP": 57162, "FN": 3555, "TN": 6992815})


def test_fd_regression():
    _regression("fd", {"TP": 1843, "FP": 4554, "FN": 1337, "TN": 2441597})


def main() -> int:
    test_only_the_out_in_run_is_used()
    test_the_universe_is_clusters_plus_abstentions()
    test_a_function_listed_twice_is_refused()
    test_singletons_and_abstentions_predict_nothing()
    test_mismatched_analysis_is_refused()
    test_a_different_universe_is_refused()
    test_v1_grouping_is_never_read()
    test_ripgrep_regression()
    test_fd_regression()
    print("V0 linkage evaluation PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
