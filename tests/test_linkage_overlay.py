"""Pair labels and shapes for the linkage overlay.

The rule the whole design rests on: a distinction the binary cannot express is
never counted as a wrong answer.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from linkage_overlay import (  # noqa: E402
    AMBIGUOUS_NEUTRAL,
    CLEAN,
    DUPLICATE_NEUTRAL,
    DUPLICATED,
    FOLDED,
    MIXED,
    NEGATIVE,
    POSITIVE,
    UNRESOLVED,
    UNRESOLVED_NEUTRAL,
    build_origin_linkage,
    canonical_identity,
    label_pair,
    score_labeled_pairs,
    source_origin_label,
)


AUDIT = Path(__file__).resolve().parents[1] / "results" / "ripgrep-main" / "plain" / (
    "ripgrep-main.O3S.gt-mangled-audit.json"
)


def test_only_the_llvm_clone_tail_is_stripped():
    symbol = "_ZN4demo6kernel17hb8a9000000000001E"
    assert canonical_identity(symbol + ".llvm.688443") == symbol
    # The Rust disambiguator itself must survive: it is what separates two
    # monomorphizations of the same generic.
    assert canonical_identity(symbol) == symbol
    assert canonical_identity(symbol).endswith("17hb8a9000000000001E")


def _linkage(identities_by_address):
    return build_origin_linkage("O", identities_by_address, identities_by_address)


def test_the_four_shapes():
    assert _linkage({"A": ["M1"], "B": ["M2"]}).shape == CLEAN
    assert _linkage({"A": ["M1"], "B": ["M1"]}).shape == DUPLICATED
    assert _linkage({"A": ["M1", "M2"], "B": ["M3"]}).shape == FOLDED
    assert _linkage({"A": ["M1", "M2"], "B": ["M1"]}).shape == MIXED
    assert _linkage({"A": [], "B": ["M1"]}).shape == UNRESOLVED


def test_folded_identity_pairs_are_counted_as_unobservable():
    # Three identities on one address can never be told apart: 3 pairs lost.
    assert _linkage({"A": ["M1", "M2", "M3"], "B": ["M4"]}).unobservable_identity_pairs == 3
    assert _linkage({"A": ["M1"], "B": ["M2"]}).unobservable_identity_pairs == 0


ORIGINS = {"A1": ["O"], "A2": ["O"], "B": ["O"], "C": ["P"], "S": ["O", "P"], "U": ["O"]}
IDENTITIES = {"A1": ["M1"], "A2": ["M1"], "B": ["M2"], "C": ["M3"], "S": ["M4"], "U": []}


def _label(left, right):
    return label_pair(
        left, right,
        origins_by_address=ORIGINS,
        identities_by_address=IDENTITIES,
    )


def test_the_worked_example_from_the_design():
    # I(A1) = I(A2) = {M1}, I(B) = {M2}, all three under origin O.
    assert _label("A1", "A2") == DUPLICATE_NEUTRAL
    assert _label("A1", "B") == POSITIVE
    assert _label("A2", "B") == POSITIVE


def test_different_origins_are_negative():
    assert _label("B", "C") == NEGATIVE


def test_an_address_with_several_origins_is_never_judged():
    assert _label("S", "B") == AMBIGUOUS_NEUTRAL
    assert _label("S", "C") == AMBIGUOUS_NEUTRAL


def test_an_address_without_identities_is_neutral():
    assert _label("U", "B") == UNRESOLVED_NEUTRAL


def test_the_secondary_question_credits_duplicates():
    both = dict(origins_by_address=ORIGINS)
    assert source_origin_label("A1", "A2", **both) == POSITIVE
    assert source_origin_label("B", "C", **both) == NEGATIVE
    assert source_origin_label("S", "B", **both) == AMBIGUOUS_NEUTRAL


def test_neutral_pairs_leave_the_denominator():
    pairs = [("A1", "A2"), ("A1", "B"), ("A2", "B"), ("B", "C"), ("S", "B")]
    result = score_labeled_pairs(
        pairs,
        [("A1", "A2"), ("A1", "B")],
        origins_by_address=ORIGINS,
        identities_by_address=IDENTITIES,
    )

    primary = result["primary"]
    # A1-A2 was predicted but is neutral, so it is neither a hit nor a miss.
    assert primary["TP"] == 1 and primary["FP"] == 0
    assert primary["FN"] == 1 and primary["TN"] == 1
    assert primary["scored_pair_count"] == 3
    assert result["label_counts"][DUPLICATE_NEUTRAL] == 1
    assert result["label_counts"][AMBIGUOUS_NEUTRAL] == 1
    assert result["neutral_pair_count"] == 2

    # The same prediction under the weaker question: A1-A2 now counts.
    secondary = result["source_origin"]
    assert secondary["TP"] == 2 and secondary["FP"] == 0
    assert secondary["scored_pair_count"] == 4


def test_ripgrep_overlay_regression():
    if not AUDIT.exists():
        return
    summary = json.loads(AUDIT.read_text(encoding="utf-8"))["summary"]

    assert summary["multimember_origin_count"] == 786
    assert summary["shape_counts"] == {
        CLEAN: 148, DUPLICATED: 624, FOLDED: 14, MIXED: 0, UNRESOLVED: 0,
    }
    assert summary["cross_origin_address_count"] == 14
    # 617 origins were already known to be one mono item at several addresses;
    # canonicalising the .llvm.N tails revealed 7 more.
    assert summary["family_counts"]["repeated_linkage_identity"] == 617
    assert summary["family_counts"]["distinct_linkage_identities"] == 169
    assert summary["shape_counts"][DUPLICATED] == 617 + 7
    assert summary["folded"]["origin_count"] == 14
    assert summary["folded"]["unobservable_identity_pair_count"] == 30


def main() -> int:
    test_only_the_llvm_clone_tail_is_stripped()
    test_the_four_shapes()
    test_folded_identity_pairs_are_counted_as_unobservable()
    test_the_worked_example_from_the_design()
    test_different_origins_are_negative()
    test_an_address_with_several_origins_is_never_judged()
    test_an_address_without_identities_is_neutral()
    test_the_secondary_question_credits_duplicates()
    test_neutral_pairs_leave_the_denominator()
    test_ripgrep_overlay_regression()
    print("linkage overlay PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
