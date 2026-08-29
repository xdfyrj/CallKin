"""The compiled negative control for the F7 rescue rule.

`expected_axis04.json` was committed before family_axis_04 was ever built. The
fixture makes a complete, bijective 2 x 2 across two different source origins
whose fragments a relation bridge already joins, so the merge must be refused
by internal fragment support and nothing else.

Ground truth is used only to build the two input fragments and to read the
result. `family_rescue` receives no origin names.

Build the artifacts on the canonical toolchain, then re-run:

    python compile.py family_axis_04 case --build O3S --profile plain
    python gt_extractor.py family_axis_04 --build O3S --profile plain
        --candidate-scope subject
    python binary_extractor.py family_axis_04 --build O3S --profile plain
        --track angr --anchor-policy role --candidate-scope subject
    python body_extractor.py family_axis_04 --build O3S --profile plain
        --candidate-scope subject
        --raw-graph extractions/angr/plain/family_axis_04.O3S.raw.json
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.gt_mangled_audit import (  # noqa: E402
    address_from_function_id,
    raw_symbols_by_member,
    read_raw_function_symbols,
)
from body_similarity import load_body_evidence  # noqa: E402
from family_rescue import (  # noqa: E402
    NO_INTERNAL_SUPPORT,
    Component,
    evaluate_component,
    internal_fragment_support,
)
from family_template import build_family_template, infer_variation_axes, select_medoid  # noqa: E402
from slot_overlay import collect_slot_observations, transfers_by_source  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = Path(__file__).resolve().parent / "fixtures" / "f7_axis_control" / (
    "expected_axis04.json"
)
GT = ROOT / "ground_truth" / "plain" / "family_axis_04.O3S.gt.json"
GT_BIN = ROOT / "gt_bin" / "plain" / "family_axis_04.O3S.gt.bin"
BODY = ROOT / "body_evidence" / "subject" / "plain" / "family_axis_04.O3S.body.json"
RAW = ROOT / "extractions" / "angr" / "plain" / "family_axis_04.O3S.raw.json"
CANDIDATES = ROOT / "results" / "family_axis_04" / "plain" / (
    "family_axis_04.O3S.v1.consensus2.k16.candidates.json"
)


def _expected() -> dict:
    return json.loads(EXPECTED.read_text(encoding="utf-8"))


def _artifacts_present() -> bool:
    return GT.exists() and GT_BIN.exists()


def _full_present() -> bool:
    return _artifacts_present() and all(
        path.exists() for path in (BODY, RAW, CANDIDATES)
    )


def test_expectations_are_self_consistent():
    expected = _expected()
    gates, axes, rescue = expected["gt_gates"], expected["axes"]["combined"], expected["rescue"]

    assert set(gates) == {"left", "right"}
    for name, gate in gates.items():
        assert gate["address_members"] == gate["unique_linkage_identities"] == 2, name
        assert gate["repeated_linkage_identities"] == 0, name
    assert axes["member_count"] == sum(g["address_members"] for g in gates.values()) == 4
    assert axes["expected_combinations"] == (
        axes["variant_counts"][0] * axes["variant_counts"][1] == 4
    ) or axes["expected_combinations"] == 4
    assert axes["observed_combinations"] == 4
    assert axes["complete"] and axes["bijective"]
    # The whole point: structure passes, the bridge passes, the merge is refused.
    assert rescue["relation_bridge"] is True
    assert rescue["internal_fragment_support"] is False
    assert rescue["accepted"] is False
    assert rescue["rejection_reason"] == NO_INTERNAL_SUPPORT


def test_ground_truth_gates():
    if not _artifacts_present():
        return
    expected = _expected()["gt_gates"]
    ground_truth = json.loads(GT.read_text(encoding="utf-8"))
    raw_symbols = read_raw_function_symbols(GT_BIN)
    members_by_origin = {
        group["origin"]: sorted(group["members"]) for group in ground_truth["origins"]
    }

    addresses: dict[str, set[str]] = {}
    for origin, gate in expected.items():
        members = members_by_origin.get(origin)
        assert members is not None, f"{origin} is absent from the ground truth"
        by_member = raw_symbols_by_member(members, raw_symbols)
        unique = len(set().union(*by_member.values())) if by_member else 0
        assert len(members) == gate["address_members"], (origin, len(members))
        assert unique == gate["unique_linkage_identities"], (origin, unique)
        addresses[origin] = set(members)
    # Identical-code folding would void the control entirely.
    assert not (addresses["left"] & addresses["right"])
    assert not ground_truth.get("cross_origin_aliases")


def _load_component():
    ground_truth = json.loads(GT.read_text(encoding="utf-8"))
    by_origin = {
        group["origin"]: tuple(sorted(group["members"]))
        for group in ground_truth["origins"]
    }
    # The harness builds the two fragments; family_rescue never sees an origin.
    fragments = {"L": by_origin["left"], "R": by_origin["right"]}
    members = tuple(sorted(fragments["L"] + fragments["R"]))

    bodies = load_body_evidence(str(BODY))
    transfers = transfers_by_source(json.loads(RAW.read_text(encoding="utf-8")))
    address_of = {member: address_from_function_id(member) for member in members}
    observations = {
        member: collect_slot_observations(
            bodies[member], address_of[member],
            transfers.get(address_of[member], {}),
        )
        for member in members
    }

    candidates = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    bridges = tuple(sorted(
        tuple(sorted(record["pair"]))
        for record in candidates["pairs"]
        if record.get("same_prior_color")
        and len({fragments["L"].__contains__(record["pair"][0]),
                 fragments["L"].__contains__(record["pair"][1])}) == 2
    ))
    component = Component(
        fragments=("L", "R"), members=members, bridge_pairs=bridges
    )
    return component, fragments, bodies, observations


def test_the_structure_is_a_complete_bijective_two_by_two():
    if not _full_present():
        return
    component, fragments, bodies, observations = _load_component()
    expected = _expected()["axes"]["combined"]

    selected = {member: bodies[member] for member in component.members}
    template = build_family_template(
        selected, select_medoid(selected, list(component.members)), observations
    )
    axes = infer_variation_axes(template)

    assert len(component.members) == expected["member_count"]
    assert sorted(axis.variant_count for axis in axes) == sorted(
        expected["variant_counts"]
    )
    support = internal_fragment_support(axes, fragments, component.fragments)
    # Exactly one axis varies inside a fragment; the other only separates them.
    assert sorted(support.values()) == [False, True], support


def test_the_relation_bridge_passes_so_it_cannot_be_what_refuses_the_merge():
    if not _full_present():
        return
    component, _, _, _ = _load_component()
    assert _expected()["rescue"]["relation_bridge"] is True
    assert component.bridge_pairs, "the fixture must supply a relation bridge"


def test_a_false_two_by_two_is_refused_for_missing_internal_support():
    if not _full_present():
        return
    component, fragments, bodies, observations = _load_component()
    expected = _expected()["rescue"]

    evaluate_component(component, fragments, bodies, observations)

    assert component.status == "rejected"
    assert component.reason == expected["rejection_reason"] == NO_INTERNAL_SUPPORT
    assert component.report["selected_basis_status"] == "unique"
    assert component.report["independent_axis_count"] == 2
    (pair,) = [
        item for item in component.report["axis_pairs"]
        if set(component.report["selected_basis"]) == {item["first"], item["second"]}
    ]
    assert pair["complete"] and pair["bijective"]
    assert sorted(component.internal_support.values()) == [False, True]


def main() -> int:
    test_expectations_are_self_consistent()
    test_ground_truth_gates()
    test_the_structure_is_a_complete_bijective_two_by_two()
    test_the_relation_bridge_passes_so_it_cannot_be_what_refuses_the_merge()
    test_a_false_two_by_two_is_refused_for_missing_internal_support()
    if not _artifacts_present():
        print("F7 rescue control PENDING (expectations fixed, artifacts not built)")
    elif _full_present():
        print("F7 rescue control FULL PASS (gates, structure and rejection reason)")
    else:
        print("F7 rescue control GT PASS (rescue not checked: missing body/raw/candidates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
