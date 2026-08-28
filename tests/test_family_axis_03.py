"""Check the compiled F7.3 control fixture against expectations fixed up front.

`expected.json` was committed before `family_axis_03` was ever built. Until the
artifacts exist this reports PENDING and only validates that the expectations
are self-consistent; it never rewrites them from whatever the build produced.

Build the artifacts on a Linux toolchain, then re-run:

    python compile.py family_axis_03 --build O3S --profile plain
    python gt_extractor.py family_axis_03 --build O3S --profile plain
    python body_extractor.py family_axis_03 --build O3S --profile plain
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.gt_mangled_audit import (  # noqa: E402
    REPEATED,
    build_audit,
    raw_symbols_by_member,
    read_raw_function_symbols,
)


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = Path(__file__).resolve().parent / "fixtures" / "f7_axis_control" / "expected.json"
GT = ROOT / "ground_truth" / "plain" / "family_axis_03.O3S.gt.json"
GT_BIN = ROOT / "gt_bin" / "plain" / "family_axis_03.O3S.gt.bin"
BODY = ROOT / "body_evidence" / "subject" / "plain" / "family_axis_03.O3S.body.json"
RAW = ROOT / "extractions" / "angr" / "plain" / "family_axis_03.O3S.raw.json"


def _expected() -> dict:
    return json.loads(EXPECTED.read_text(encoding="utf-8"))


def test_expectations_are_self_consistent():
    expected = _expected()
    assert set(expected["gt_gates"]) == set(expected["axes"])

    for name, gate in expected["gt_gates"].items():
        assert gate["repeated_linkage_identities"] == 0, name
        # A clean control family is one address per mono item.
        assert gate["address_members"] == gate["unique_linkage_identities"], name

    axes = expected["axes"]
    for name in ("complete", "incomplete"):
        counts = axes[name]["variant_counts"]
        assert axes[name]["expected_combinations"] == counts[0] * counts[1], name
    assert axes["complete"]["observed_combinations"] == 6
    assert axes["incomplete"]["observed_combinations"] == 5
    assert axes["complete"]["expected_combinations"] == (
        expected["gt_gates"]["complete"]["address_members"]
    )
    # The absent combination is exactly the gap between the two kernels.
    assert (
        axes["incomplete"]["expected_combinations"]
        - expected["gt_gates"]["incomplete"]["address_members"]
    ) == 1


def _artifacts_present() -> bool:
    return GT.exists() and GT_BIN.exists()


def test_ground_truth_gates():
    if not _artifacts_present():
        return
    expected = _expected()
    ground_truth = json.loads(GT.read_text(encoding="utf-8"))
    raw_symbols = read_raw_function_symbols(GT_BIN)
    members_by_origin = {
        group["origin"]: sorted(group["members"]) for group in ground_truth["origins"]
    }

    audit = build_audit(
        ground_truth,
        raw_symbols,
        ground_truth_sha256="",
        binary_sha256="",
    )
    repeated = {
        entry["origin"]
        for entry in audit["origins"]
        if entry["classification"] == REPEATED
    }

    for origin, gate in expected["gt_gates"].items():
        members = members_by_origin.get(origin)
        assert members is not None, f"{origin} is absent from the ground truth"
        by_member = raw_symbols_by_member(members, raw_symbols)
        unique = len(set().union(*by_member.values())) if by_member else 0
        assert len(members) == gate["address_members"], (
            f"{origin}: {len(members)} addresses, expected "
            f"{gate['address_members']}"
        )
        assert unique == gate["unique_linkage_identities"], (
            f"{origin}: {unique} linkage identities, expected "
            f"{gate['unique_linkage_identities']}"
        )
        assert (origin in repeated) == bool(gate["repeated_linkage_identities"]), origin


def test_axis_expectations():
    if not (_artifacts_present() and BODY.exists() and RAW.exists()):
        return
    from analysis.v1_axis_probe import build_probe

    expected = _expected()["axes"]
    report = build_probe(
        json.loads(BODY.read_text(encoding="utf-8")),
        json.loads(RAW.read_text(encoding="utf-8")),
        json.loads(GT.read_text(encoding="utf-8")),
        sorted(expected),
        provenance={"raw_graph_sha256": ""},
    )
    families = {family["origin"]: family for family in report["families"]}

    for origin, wanted in expected.items():
        family = families[origin]
        counts = sorted(axis["variant_count"] for axis in family["axes"])
        if "axis_count" in wanted:
            assert family["axis_count"] == wanted["axis_count"], origin
        if "variant_counts" in wanted:
            assert counts == sorted(wanted["variant_counts"]), (origin, counts)
        if "varying_call_slots" in wanted:
            slots = sum(len(axis["slots"]) for axis in family["axes"])
            assert slots == wanted["varying_call_slots"], origin
        if "independent_axis_count" in wanted:
            assert family["independent_axis_count"] == wanted["independent_axis_count"]
        if "selected_basis_status" in wanted:
            assert family["selected_basis_status"] == wanted["selected_basis_status"]
        if "selected_basis" in wanted:
            assert family["selected_basis"] == wanted["selected_basis"], origin
        if "observed_combinations" in wanted:
            (pair,) = family["axis_pairs"]
            assert pair["expected_combinations"] == wanted["expected_combinations"]
            assert pair["observed_combinations"] == wanted["observed_combinations"]
            assert pair["complete"] == wanted["complete"]
            assert pair["bijective"] == wanted["bijective"]


def main() -> int:
    test_expectations_are_self_consistent()
    test_ground_truth_gates()
    test_axis_expectations()
    if _artifacts_present():
        print("F7.3 control fixture PASS")
    else:
        print("F7.3 control fixture PENDING (expectations fixed, artifacts not built)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
