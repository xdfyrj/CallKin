from __future__ import annotations

import copy
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.gt_mangled_audit import (  # noqa: E402
    AUDIT_ARTIFACT,
    DISTINCT,
    REPEATED,
    UNRESOLVED,
)
from analysis.v1_corrected_gt import (  # noqa: E402
    SINGLETON,
    build_corrected_ground_truth,
    repeated_origin_name,
)


GROUND_TRUTH = {
    "case": "demo",
    "build": "O3S",
    "profile": "plain",
    "provenance": {"stripped_sha256": "c" * 64},
    "origins": [
        {"origin": "demo::doc_short", "members": ["FUN_00200000", "FUN_00200010"]},
        {"origin": "demo::search_reader", "members": ["FUN_00200020", "FUN_00200030"]},
        {"origin": "demo::only_once", "members": ["FUN_00200040"]},
    ],
    "symbols": {"FUN_00200000": ["demo::doc_short"]},
}


def _audit(entries):
    return {
        "artifact": AUDIT_ARTIFACT,
        "case": "demo",
        "build": "O3S",
        "profile": "plain",
        "provenance": {"ground_truth_sha256": "a" * 64},
        "origins": entries,
    }


AUDIT = _audit(
    [
        {
            "classification": REPEATED,
            "origin": "demo::doc_short",
            "members": ["FUN_00200000", "FUN_00200010"],
            "raw_symbols": ["_ZN4demo10doc_short17hAAAAAAAAAAAAAAAAE"],
        },
        {
            "classification": DISTINCT,
            "origin": "demo::search_reader",
            "members": ["FUN_00200020", "FUN_00200030"],
            "raw_symbols": [
                "_ZN4demo13search_reader17h1111111111111111E",
                "_ZN4demo13search_reader17h2222222222222222E",
            ],
        },
    ]
)


def _corrected(ground_truth=GROUND_TRUTH, audit=AUDIT):
    return build_corrected_ground_truth(
        ground_truth,
        audit,
        ground_truth_sha256="a" * 64,
        audit_sha256="b" * 64,
    )


def test_repeated_family_becomes_singletons_and_distinct_survives():
    corrected = _corrected()
    by_origin = {group["origin"]: group for group in corrected["origins"]}

    assert by_origin[repeated_origin_name("FUN_00200000")]["members"] == ["FUN_00200000"]
    assert by_origin[repeated_origin_name("FUN_00200010")]["members"] == ["FUN_00200010"]
    assert "demo::doc_short" not in by_origin
    assert by_origin["demo::search_reader"]["members"] == ["FUN_00200020", "FUN_00200030"]
    assert by_origin["demo::only_once"]["members"] == ["FUN_00200040"]


def test_member_universe_is_preserved_and_repeated_pairs_are_gone():
    corrected = _corrected()
    source_members = sorted(
        member for group in GROUND_TRUTH["origins"] for member in group["members"]
    )
    corrected_members = sorted(
        member for group in corrected["origins"] for member in group["members"]
    )

    assert corrected_members == source_members
    assert corrected["summary"]["member_count"] == len(source_members)
    # only search_reader keeps a positive pair; doc_short contributed one before
    assert corrected["summary"]["same_origin_pair_count"] == 1
    assert corrected["summary"]["multimember_origin_count"] == 1
    assert corrected["summary"]["source_origin_counts"] == {
        DISTINCT: 1,
        REPEATED: 1,
        SINGLETON: 1,
    }


def test_inputs_are_not_mutated_and_hashes_propagate():
    ground_truth = copy.deepcopy(GROUND_TRUTH)
    audit = copy.deepcopy(AUDIT)
    before = (copy.deepcopy(ground_truth), copy.deepcopy(audit))

    corrected = _corrected(ground_truth, audit)

    assert (ground_truth, audit) == before
    assert corrected["provenance"]["ground_truth_sha256"] == "a" * 64
    assert corrected["provenance"]["audit_sha256"] == "b" * 64
    assert corrected["provenance"]["source_provenance"] == GROUND_TRUTH["provenance"]


def test_unresolved_origin_is_rejected():
    audit = _audit(
        [
            {
                "classification": UNRESOLVED,
                "origin": "demo::doc_short",
                "members": ["FUN_00200000", "FUN_00200010"],
                "raw_symbols": [],
            },
            AUDIT["origins"][1],
        ]
    )
    try:
        _corrected(audit=audit)
    except ValueError as exc:
        assert "raw symbol" in str(exc)
    else:
        raise AssertionError("an unresolved origin was accepted")


def test_uncovered_multimember_origin_is_rejected():
    audit = _audit([AUDIT["origins"][0]])
    try:
        _corrected(audit=audit)
    except ValueError as exc:
        assert "search_reader" in str(exc)
    else:
        raise AssertionError("an uncovered origin was accepted")


def test_stale_audit_hash_is_rejected():
    audit = copy.deepcopy(AUDIT)
    audit["provenance"]["ground_truth_sha256"] = "f" * 64
    try:
        _corrected(audit=audit)
    except ValueError as exc:
        assert "ground truth hash" in str(exc)
    else:
        raise AssertionError("an audit for a different ground truth was accepted")


def test_audit_members_must_match_ground_truth_members():
    audit = copy.deepcopy(AUDIT)
    audit["origins"][0]["members"] = ["FUN_00200000", "FUN_00200040"]
    try:
        _corrected(audit=audit)
    except ValueError as exc:
        assert "members" in str(exc)
    else:
        raise AssertionError("an audit with stale members was accepted")


def main() -> int:
    test_repeated_family_becomes_singletons_and_distinct_survives()
    test_member_universe_is_preserved_and_repeated_pairs_are_gone()
    test_inputs_are_not_mutated_and_hashes_propagate()
    test_unresolved_origin_is_rejected()
    test_uncovered_multimember_origin_is_rejected()
    test_stale_audit_hash_is_rejected()
    test_audit_members_must_match_ground_truth_members()
    print("V1 corrected ground truth PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
