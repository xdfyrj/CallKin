from __future__ import annotations

import copy
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.gt_mangled_audit import (  # noqa: E402
    DISTINCT,
    REPEATED,
    UNRESOLVED,
    address_from_function_id,
    build_audit,
    classify_members,
    raw_symbols_by_member,
)


DUP = "_ZN4demo10doc_short17hAAAAAAAAAAAAAAAAE"
GEN_A = "_ZN4demo13search_reader17h1111111111111111E"
GEN_B = "_ZN4demo13search_reader17h2222222222222222E"


def _ground_truth(origins):
    return {
        "case": "demo",
        "build": "O3S",
        "profile": "plain",
        "provenance": {"non_stripped_sha256": "b" * 64},
        "origins": origins,
    }


def test_address_from_function_id_inverts_the_bias():
    assert address_from_function_id("FUN_00200000") == 0x100000
    assert address_from_function_id("FUN_00200010") == 0x100010


def test_same_raw_symbol_at_different_addresses_is_repeated():
    raw = {0x100000: frozenset({DUP}), 0x100010: frozenset({DUP})}
    members = ["FUN_00200000", "FUN_00200010"]
    assert classify_members(raw_symbols_by_member(members, raw)) == REPEATED


def test_different_hash_under_one_origin_is_distinct():
    raw = {0x100000: frozenset({GEN_A}), 0x100010: frozenset({GEN_B})}
    members = ["FUN_00200000", "FUN_00200010"]
    assert classify_members(raw_symbols_by_member(members, raw)) == DISTINCT


def test_missing_raw_symbol_is_unresolved():
    raw = {0x100000: frozenset({GEN_A})}
    members = ["FUN_00200000", "FUN_00200010"]
    assert classify_members(raw_symbols_by_member(members, raw)) == UNRESOLVED


def test_matching_alias_sets_stay_repeated():
    both = frozenset({DUP, "_ZN4demo10doc_short17hAAAAAAAAAAAAAAAAE.llvm.1"})
    raw = {0x100000: both, 0x100010: both}
    members = ["FUN_00200000", "FUN_00200010"]
    assert classify_members(raw_symbols_by_member(members, raw)) == REPEATED


def test_audit_reports_counts_provenance_and_skips_singletons():
    ground_truth = _ground_truth(
        [
            {"origin": "demo::doc_short", "members": ["FUN_00200000", "FUN_00200010"]},
            {"origin": "demo::search_reader", "members": ["FUN_00200020", "FUN_00200030"]},
            {"origin": "demo::only_once", "members": ["FUN_00200040"]},
        ]
    )
    raw = {
        0x100000: frozenset({DUP}),
        0x100010: frozenset({DUP}),
        0x100020: frozenset({GEN_A}),
        0x100030: frozenset({GEN_B}),
        0x100040: frozenset({"_ZN4demo9only_once17h3333333333333333E"}),
    }
    before = copy.deepcopy(ground_truth)

    audit = build_audit(
        ground_truth,
        raw,
        ground_truth_sha256="a" * 64,
        binary_sha256="b" * 64,
    )

    assert ground_truth == before, "the audit must not mutate the ground truth"
    assert [entry["origin"] for entry in audit["origins"]] == [
        "demo::doc_short",
        "demo::search_reader",
    ]
    assert audit["summary"]["family_counts"] == {REPEATED: 1, DISTINCT: 1, UNRESOLVED: 0}
    assert audit["summary"]["member_counts"] == {REPEATED: 2, DISTINCT: 2, UNRESOLVED: 0}
    assert audit["provenance"]["ground_truth_sha256"] == "a" * 64
    assert audit["provenance"]["non_stripped_sha256"] == "b" * 64
    duplicate = audit["origins"][0]
    assert duplicate["classification"] == REPEATED
    assert duplicate["raw_symbols"] == [DUP]
    assert duplicate["raw_symbols_by_member"] == {
        "FUN_00200000": [DUP],
        "FUN_00200010": [DUP],
    }
    assert audit["origins"][1]["raw_symbols"] == [GEN_A, GEN_B]


def test_audit_rejects_a_binary_that_does_not_match_ground_truth():
    ground_truth = _ground_truth(
        [{"origin": "demo::doc_short", "members": ["FUN_00200000", "FUN_00200010"]}]
    )
    raw = {0x100000: frozenset({DUP}), 0x100010: frozenset({DUP})}
    try:
        build_audit(
            ground_truth,
            raw,
            ground_truth_sha256="a" * 64,
            binary_sha256="c" * 64,
        )
    except ValueError as exc:
        assert "non-stripped binary" in str(exc)
    else:
        raise AssertionError("a mismatched non-stripped binary was accepted")


def main() -> int:
    test_address_from_function_id_inverts_the_bias()
    test_same_raw_symbol_at_different_addresses_is_repeated()
    test_different_hash_under_one_origin_is_distinct()
    test_missing_raw_symbol_is_unresolved()
    test_matching_alias_sets_stay_repeated()
    test_audit_reports_counts_provenance_and_skips_singletons()
    test_audit_rejects_a_binary_that_does_not_match_ground_truth()
    print("GT mangled audit PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
