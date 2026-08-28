"""F7.3: grouping varying slots into anonymous axes.

The rules are fixed here before any real family is looked at, so a probe cannot
be talked into loosening them after the fact.
"""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from family_template import (  # noqa: E402
    FamilyTemplate,
    TemplateSlot,
    axis_pair_coverage,
    axis_report,
    infer_variation_axes,
)
from slot_overlay import CALL_TARGET, RESOLVED, UNRESOLVED  # noqa: E402


def _slot(offset: int, values: dict[str, object], states=None) -> TemplateSlot:
    return TemplateSlot(
        block="B0",
        offset=offset,
        index=0,
        kind=CALL_TARGET,
        values_by_member=dict(values),
        states_by_member=states or {member: RESOLVED for member in values},
    )


def _template(members, slots) -> FamilyTemplate:
    return FamilyTemplate(
        medoid=members[0],
        members=tuple(members),
        block_roles={"B0": "common"},
        member_specific_blocks={},
        slots=tuple(slots),
    )


def test_slots_that_split_the_members_identically_become_one_axis():
    members = ["M1", "M2", "M3", "M4"]
    # Different target addresses, same split of the members.
    template = _template(members, [
        _slot(0x10, {"M1": "0xa", "M2": "0xa", "M3": "0xb", "M4": "0xb"}),
        _slot(0x20, {"M1": "0xc", "M2": "0xc", "M3": "0xd", "M4": "0xd"}),
    ])

    (axis,) = infer_variation_axes(template)

    assert axis.variant_count == 2
    assert axis.partition == (("M1", "M2"), ("M3", "M4"))
    assert axis.slots == ((0x10, 0, CALL_TARGET), (0x20, 0, CALL_TARGET))
    assert axis.labels == {"M1": 0, "M2": 0, "M3": 1, "M4": 1}


def test_a_full_two_by_three_product_is_detected():
    members = [f"M{index}" for index in range(6)]
    first = {member: ("0xa" if index < 3 else "0xb")
             for index, member in enumerate(members)}
    second = {member: f"0x{index % 3}" for index, member in enumerate(members)}
    template = _template(members, [_slot(0x10, first), _slot(0x20, second)])

    axes = infer_variation_axes(template)
    (pair,) = axis_pair_coverage(axes, members)

    assert sorted(axis.variant_count for axis in axes) == [2, 3]
    assert pair.expected_combinations == 6
    assert pair.observed_combinations == 6
    assert pair.coverage == 1.0
    assert pair.complete and pair.bijective


def test_a_missing_combination_is_not_a_complete_product():
    # Five members over a 2 x 3 grid: one combination never occurs.
    members = ["M1", "M2", "M3", "M4", "M5"]
    first = {"M1": "0xa", "M2": "0xa", "M3": "0xa", "M4": "0xb", "M5": "0xb"}
    second = {"M1": "0x0", "M2": "0x1", "M3": "0x2", "M4": "0x0", "M5": "0x1"}
    template = _template(members, [_slot(0x10, first), _slot(0x20, second)])

    (pair,) = axis_pair_coverage(infer_variation_axes(template), members)

    assert pair.expected_combinations == 6
    assert pair.observed_combinations == 5
    assert pair.coverage == 5 / 6
    assert not pair.complete
    assert not pair.bijective


def test_a_slot_one_member_did_not_resolve_is_no_axis_candidate():
    members = ["M1", "M2", "M3", "M4"]
    template = _template(members, [
        _slot(
            0x10,
            {"M1": "0xa", "M2": "0xa", "M3": "0xb", "M4": None},
            states={"M1": RESOLVED, "M2": RESOLVED, "M3": RESOLVED,
                    "M4": UNRESOLVED},
        ),
        _slot(0x20, {"M1": "0xc", "M2": "0xc", "M3": "0xd", "M4": "0xd"}),
    ])

    axes = infer_variation_axes(template)

    assert len(axes) == 1
    assert axes[0].slots == ((0x20, 0, CALL_TARGET),)


def test_an_invariant_slot_is_not_an_axis():
    members = ["M1", "M2"]
    template = _template(members, [_slot(0x10, {"M1": "0xa", "M2": "0xa"})])

    assert infer_variation_axes(template) == ()
    assert axis_pair_coverage((), members) == ()


def test_the_report_records_axes_and_why_slots_were_excluded():
    members = ["M1", "M2"]
    template = _template(members, [
        _slot(0x10, {"M1": "0xa", "M2": "0xb"}),
        _slot(0x20, {"M1": "0xc", "M2": "0xc"}),
        _slot(
            0x30,
            {"M1": "0xd", "M2": None},
            states={"M1": RESOLVED, "M2": UNRESOLVED},
        ),
    ])

    report = axis_report(template)

    assert report["axis_count"] == 1
    assert report["slot_count"] == 3
    # 0x30 has a single resolved value, so it does not demonstrably vary.
    assert report["varying_slot_count"] == 1
    assert report["observed_by_all_slot_count"] == 2
    reasons = {item["offset"]: item["reason"] for item in report["excluded_slots"]}
    assert reasons == {0x20: "invariant", 0x30: "not_resolved_for_every_member"}


def main() -> int:
    test_slots_that_split_the_members_identically_become_one_axis()
    test_a_full_two_by_three_product_is_detected()
    test_a_missing_combination_is_not_a_complete_product()
    test_a_slot_one_member_did_not_resolve_is_no_axis_candidate()
    test_an_invariant_slot_is_not_an_axis()
    test_the_report_records_axes_and_why_slots_were_excluded()
    print("F7.3 variation axes PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
