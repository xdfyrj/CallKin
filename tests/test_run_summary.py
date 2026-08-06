from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from angr_adapter import AngrCallResolution, merge_angr_resolutions
from candidate_selection import parse_candidate_selection
from graph_evidence import TransferEvidence, make_raw_graph
from graph_projector import project_fixture
from paths import ANGR_TRACK
from provenance import BuildProvenance
from run_summary import (
    build_run_summary,
    compare_ground_truth_profiles,
    execution_summary,
)


PROVENANCE = BuildProvenance(
    build_id="summary-test",
    source_sha256="1" * 64,
    non_stripped_sha256="2" * 64,
    stripped_sha256="3" * 64,
)


def direct(source: int, callsite: int, target: int) -> TransferEvidence:
    return TransferEvidence(
        source=source,
        callsite=callsite,
        instruction=f"call 0x{target:x}",
        kind="call",
        operand_kind="immediate",
        status="resolved",
        target=target,
        resolver="direct-immediate",
        confidence="exact",
    )


def indirect(source: int, callsite: int) -> TransferEvidence:
    return TransferEvidence(
        source=source,
        callsite=callsite,
        instruction="call rax",
        kind="call",
        operand_kind="register",
        status="unresolved",
        target=None,
        resolver=None,
        confidence="unknown",
    )


def main() -> int:
    raw = make_raw_graph(
        case="summary-test",
        build="O3S",
        profile="plain",
        binary_path=sys.executable,
        provenance=PROVENANCE,
        boundary_input_sha256="4" * 64,
        root_address=0x1000,
        functions=[
            {
                "address": f"0x{address:x}",
                "name": f"function_{address:x}",
                "size": 0x100,
                "boundary_source": "symbol-oracle",
                "discovered_by_radare2": address != 0x3000,
            }
            for address in (0x1000, 0x2000, 0x3000, 0x4000)
        ],
        transfers=[
            direct(0x1000, 0x1010, 0x2000),
            indirect(0x2000, 0x2010),
            indirect(0x3000, 0x3010),
            indirect(0x4000, 0x4010),
        ],
        boundary_mode="symbol-extent",
        boundary_mismatches=[
            {
                "id": "FUN_00002000",
                "address": "0x2000",
                "symbol_size": 0x100,
                "radare2_size": 0x80,
            },
            {
                "id": "FUN_00003000",
                "address": "0x3000",
                "symbol_size": 0x100,
                "radare2_size": 0,
            },
        ],
    )
    raw = merge_angr_resolutions(
        raw,
        (
            AngrCallResolution(0x2000, 0x2010, (0x4000,)),
            AngrCallResolution(0x4000, 0x4010, (0x3000,)),
        ),
        angr_version="test",
    )
    selection_data = {
        "case": "summary-test",
        "build": "O3S",
        "profile": "plain",
        "schema_version": 6,
        "provenance": PROVENANCE.to_dict(),
        "source": "test",
        "scope": "rust-nonstd",
        "root_namespace": "summary_test",
        "namespaces": [],
        "excluded_namespaces": ["core", "alloc", "std", "__rustc"],
        "addresses": ["0x2000", "0x3000"],
        "function_bounds": [
            {"address": "0x2000", "size": 0x100},
            {"address": "0x3000", "size": 0x100},
        ],
    }
    selection = parse_candidate_selection(
        selection_data,
        expected_case="summary-test",
        expected_build="O3S",
        expected_profile="plain",
    )
    fixture = project_fixture(
        raw,
        selection=selection,
        track=ANGR_TRACK,
        users_path="users.json",
        id_bias=0,
    )
    gt = {
        "origins": [{
            "origin": "shared",
            "members": ["FUN_00002000", "FUN_00003000"],
        }],
        "symbols": {
            "FUN_00002000": ["summary_test::shared::<i32>"],
            "FUN_00003000": ["summary_test::shared::<u64>"],
        },
    }
    report = SimpleNamespace(pairwise=SimpleNamespace(tp=1, fn=0))
    execution = execution_summary(
        duration_seconds={"total": 1.25},
        warnings=[{"component": "angr", "message": "warning", "count": 2}],
    )
    summary = build_run_summary(
        raw=raw,
        fixture=fixture,
        ground_truth=gt,
        selection=selection,
        reports=(report,),
        execution=execution,
        binary_path=sys.executable,
        id_bias=0,
    )

    indirect_summary = summary["extraction"]["indirect_call_summary"]
    if (
        indirect_summary["all_sources"]["resolved_internal"] != 2
        or indirect_summary["all_sources"]["total"] != 3
        or indirect_summary["candidate_sources"]["resolved_internal"] != 1
        or indirect_summary["candidate_sources"]["total"] != 2
    ):
        print("FAIL run summary indirect count")
        return 1
    impact = summary["candidate_impact"]
    if (
        impact["candidate_outgoing_edges_added"] != 1
        or impact["candidate_incoming_edges_added"] != 1
        or impact["candidates_unchanged"] != 0
    ):
        print(f"FAIL candidate impact: {impact}")
        return 1
    observability = summary["candidate_observability"]
    if (
        observability["reachable_from_root"] != 2
        or observability["fully_isolated"] != 0
        or observability["with_unresolved_indirect_calls"] != 1
    ):
        print(f"FAIL candidate observability: {observability}")
        return 1
    if summary["ground_truth"]["same_family_pair_count"] != 1:
        print("FAIL ground truth summary")
        return 1
    comparison = compare_ground_truth_profiles(
        gt,
        {
            "origins": [{
                "origin": "shared",
                "members": ["FUN_00005000"],
            }],
            "symbols": {
                "FUN_00005000": ["summary_test::shared::<i32>"],
            },
        },
    )
    if (
        comparison["candidate_origins"]["common"] != 1
        or comparison["generic_families"]["plain_only"] != 1
        or comparison["monomorphized_instances"]["common_symbols"] != 1
    ):
        print(f"FAIL profile comparison: {comparison}")
        return 1
    if summary["execution"]["status"] != "completed_with_warnings":
        print("FAIL execution warning status")
        return 1
    boundary = summary["artifact_summary"]["boundary_oracle"]
    if boundary["radare2_missing_count"] != 1 or boundary["size_mismatch_count"] != 1:
        print(f"FAIL boundary summary: {boundary}")
        return 1

    print("run summary diagnostics PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
