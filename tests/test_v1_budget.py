"""F6 comparison budgets.

Cost is measured in alignment cells: one left normalized instruction paired
with one right one, a deterministic proxy for the O(Ia * Ib) work a comparison
does. Both ceilings cover candidate and on-demand work together.
"""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import FunctionBody  # noqa: E402
from v1_candidates import PairKey  # noqa: E402
from v1_engine import PairEvidenceCache, PairPolicyConfig  # noqa: E402


def _body(identifier: str, count: int, *, complete: bool = True, opaque: int = 0):
    instructions = tuple(
        {
            "offset": offset,
            "mnemonic_class": "MOV",
            "operands": [],
            "control_flow": "none",
        }
        for offset in range(count)
    )
    return FunctionBody(
        id=identifier,
        size=count,
        instructions=instructions,
        edges=(),
        blocks=({"label": "B0", "instruction_offsets": list(range(count))},),
        quality={"complete_decode": complete, "opaque_indirect_jumps": opaque},
    )


def _config(**overrides):
    policy = {"structure_match_threshold": 0.9, "slot_match_threshold": 1.0}
    policy.update(overrides)
    return PairPolicyConfig.from_dict({"policy": policy})


def _cache(bodies, **overrides):
    return PairEvidenceCache(bodies, [], _config(**overrides))


BODIES = {
    "A": _body("A", 10),
    "B": _body("B", 20),
    "C": _body("C", 5),
    "INCOMPLETE": _body("INCOMPLETE", 100, complete=False),
    "OPAQUE": _body("OPAQUE", 100, opaque=3),
}


def test_cost_is_the_product_of_instruction_counts():
    cache = _cache(BODIES)
    assert cache.alignment_cells(PairKey.make("A", "B")) == 200
    assert cache.alignment_cells(PairKey.make("A", "C")) == 50


def test_work_that_costs_no_alignment_is_not_charged():
    cache = _cache(BODIES)
    # An incomplete decode and an opaque indirect jump both abstain without
    # running an alignment, so neither may consume budget.
    assert not cache.would_compare(PairKey.make("A", "INCOMPLETE"))
    assert not cache.would_compare(PairKey.make("A", "OPAQUE"))
    assert cache.would_compare(PairKey.make("A", "B"))

    count, cells = cache.demand([
        PairKey.make("A", "B"),
        PairKey.make("A", "INCOMPLETE"),
        PairKey.make("A", "OPAQUE"),
    ])
    assert (count, cells) == (1, 200)


def test_a_cache_hit_is_not_charged_twice():
    cache = _cache(BODIES)
    pair = PairKey.make("A", "B")
    cache.get_evaluation(pair)
    assert cache.total_comparisons == 1
    assert cache.total_alignment_cells == 200

    cache.get_evaluation(pair)
    assert cache.cache_hits == 1
    assert cache.total_comparisons == 1
    assert cache.total_alignment_cells == 200
    assert not cache.would_compare(pair)
    assert cache.demand([pair]) == (0, 0)


def test_either_ceiling_can_refuse_the_work():
    counted = _cache(BODIES, max_comparison_count=1)
    assert counted.within_budget(1, 10**9)
    assert not counted.within_budget(2, 0)

    celled = _cache(BODIES, max_alignment_cell_budget=200)
    assert celled.within_budget(99, 200)
    assert not celled.within_budget(1, 201)


def test_the_budget_is_shared_across_candidate_and_on_demand_work():
    cache = _cache(BODIES, max_comparison_count=2)
    cache.get_evaluation(PairKey.make("A", "B"))
    cache.get_evaluation(PairKey.make("A", "C"))

    assert cache.total_comparisons == 2
    assert not cache.within_budget(1, 0)
    assert cache.remaining()["remaining_comparisons"] == 0


def test_remaining_reports_none_when_unbounded():
    cache = _cache(BODIES)
    assert cache.remaining() == {
        "remaining_comparisons": None,
        "remaining_alignment_cells": None,
    }


def test_limits_round_trip_and_reject_bad_values():
    config = _config(max_comparison_count=10, max_alignment_cell_budget=1000)
    assert config.max_comparison_count == 10
    assert config.to_dict()["max_alignment_cell_budget"] == 1000

    for bad in (-1, 1.5, True, "10"):
        try:
            _config(max_comparison_count=bad)
        except ValueError as exc:
            assert "max_comparison_count" in str(exc)
        else:
            raise AssertionError(f"{bad!r} was accepted")


def main() -> int:
    test_cost_is_the_product_of_instruction_counts()
    test_work_that_costs_no_alignment_is_not_charged()
    test_a_cache_hit_is_not_charged_twice()
    test_either_ceiling_can_refuse_the_work()
    test_the_budget_is_shared_across_candidate_and_on_demand_work()
    test_remaining_reports_none_when_unbounded()
    test_limits_round_trip_and_reject_bad_values()
    print("F6 comparison budget PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
