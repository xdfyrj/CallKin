"""Small scorer checks that fail on label, clipping, or join regressions."""

from __future__ import annotations

import importlib.util
from pathlib import Path


_PATH = Path(__file__).with_name("score_novel_source.py")
_SPEC = importlib.util.spec_from_file_location("novel_score", _PATH)
assert _SPEC and _SPEC.loader
score = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(score)


def _labels():
    addresses = {
        "a": {"origins": ["pkg::one"], "identities": ["ia"]},
        "b": {"origins": ["pkg::one"], "identities": ["ib"]},
        "c": {"origins": ["pkg::one"], "identities": ["ia"]},
        "d": {"origins": ["pkg::two", "pkg::three"], "identities": ["id"]},
        "e": {"origins": [], "identities": ["ie"]},
        "f": {"origins": ["pkg::two"], "identities": ["if"]},
    }
    return {"addresses": addresses}, addresses


def test_linkage_neutral_counts_and_confusion():
    audit, _ = _labels()
    prediction = {
        "universe": {"target_ids": list("abcdef")},
        "clusters": [{"status": "accepted", "members": list("abcdf")}],
    }
    result = score.metrics(prediction, {"origins": []}, audit)
    assert (result["TP"], result["FP"], result["FN"]) == (2, 3, 0)
    assert result["neutral_pairs"]["duplicate-neutral"] == 1
    assert result["neutral_pairs"]["ambiguous-neutral"] == 4


def test_clip_records_cross_boundary_and_zero_positive():
    audit, _ = _labels()
    prediction = {
        "universe": {"target_ids": list("abcdef")},
        "clusters": [{"status": "accepted", "members": ["a", "b", "f"]}],
    }
    clipped = score.clip_prediction(prediction, {"a", "b"})
    assert clipped["clusters"][0]["members"] == ["a", "b"]
    empty = score.clip_prediction(prediction, set())
    result = score.metrics(empty, {"origins": []}, audit)
    assert result["target_count"] == 0 and result["positive_pairs"] == 0
    assert result["recall"] is None and result["macro_origin_recall"] is None and result["exact_group_rate"] is None
    assert score._mask_diagnostics(prediction, {"a", "b"}) == {
        "cross_boundary_cluster_count": 1,
        "mask_members_in_mixed_clusters": 2,
        "outside_members_in_mixed_clusters": 1,
    }


def test_join_rejects_universe_mismatch():
    audit, _ = _labels()
    try:
        score._validate_label_universe({"origins": [{"origin": "pkg::one", "members": ["a"]}]}, audit, ("a", "b"))
    except ValueError as exc:
        assert "universe mismatch" in str(exc)
    else:
        raise AssertionError("universe mismatch was accepted")


if __name__ == "__main__":
    for name in ("test_linkage_neutral_counts_and_confusion", "test_clip_records_cross_boundary_and_zero_positive", "test_join_rejects_universe_mismatch"):
        globals()[name]()
    print("PASS: novel scorer checks")
