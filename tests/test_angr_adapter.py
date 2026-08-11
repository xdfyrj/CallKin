from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from angr_adapter import (
    AngrCallResolution,
    AngrTargetMetadata,
    _target_metadata,
    merge_angr_resolutions,
)
from candidate_selection import parse_candidate_selection
from graph_evidence import (
    ANGR_RAW_GRAPH_BACKEND,
    ANGR_RESOLVER,
    ELF_RELOCATION_RESOLVER,
    TransferEvidence,
    make_raw_graph,
    validate_raw_graph,
)
from graph_projector import project_fixture
from paths import ANGR_TRACK
from provenance import BuildProvenance


PROVENANCE = BuildProvenance(
    build_id="angr-test",
    source_sha256="1" * 64,
    non_stripped_sha256="2" * 64,
    stripped_sha256="3" * 64,
)


def _unresolved(source: int, callsite: int) -> TransferEvidence:
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


def _unresolved_tail(source: int, callsite: int) -> TransferEvidence:
    return TransferEvidence(
        source=source,
        callsite=callsite,
        instruction="jmp rax",
        kind="tail-call",
        operand_kind="register",
        status="unresolved",
        target=None,
        resolver=None,
        confidence="unknown",
    )


def _direct(source: int, callsite: int, target: int) -> TransferEvidence:
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


def _raw_graph():
    addresses = (0x1000, 0x2000, 0x3000, 0x4000)
    return make_raw_graph(
        case="angr-test",
        build="O3S",
        profile="plain",
        binary_path="bin/plain/angr-test.O3S.fixture.bin",
        provenance=PROVENANCE,
        boundary_input_sha256="4" * 64,
        root_address=0x1000,
        functions=[
            {
                "address": f"0x{address:x}",
                "name": f"function_{address:x}",
                "size": 0x100,
                "boundary_source": "symbol-oracle",
                "discovered_by_radare2": True,
            }
            for address in addresses
        ],
        transfers=[
            _direct(0x1000, 0x1010, 0x2000),
            _unresolved(0x2000, 0x2010),
            _unresolved(0x2000, 0x2020),
            _direct(0x2000, 0x2030, 0x3000),
            _unresolved(0x2000, 0x2040),
            _unresolved(0x2000, 0x2050),
            _unresolved(0x2000, 0x2060),
            _unresolved(0x2000, 0x2070),
            _unresolved(0x2000, 0x2080),
            _unresolved(0x2000, 0x2090),
            _unresolved_tail(0x2000, 0x20A0),
        ],
        boundary_mode="symbol-extent",
        boundary_mismatches=[],
    )


def _selection():
    data = {
        "case": "angr-test",
        "build": "O3S",
        "profile": "plain",
        "schema_version": 5,
        "provenance": PROVENANCE.to_dict(),
        "source": "gt_bin/plain/angr-test.O3S.gt.bin",
        "prefix": "angr_test::",
        "addresses": ["0x2000", "0x3000"],
        "function_bounds": [
            {"address": "0x2000", "size": 0x100},
            {"address": "0x3000", "size": 0x100},
        ],
    }
    return parse_candidate_selection(
        data,
        expected_case="angr-test",
        expected_build="O3S",
        expected_profile="plain",
    )


def _check_unresolvable_jump_classification() -> bool:
    class Procedure:
        display_name = "UnresolvableJumpTarget"

    class Functions:
        @staticmethod
        def get(_address):
            return None

    class Loader:
        class MainObject:
            @staticmethod
            def contains_addr(_address):
                return False

        main_object = MainObject()

        @staticmethod
        def find_symbol(_address):
            return None

    class Project:
        loader = Loader()

        @staticmethod
        def is_hooked(_address):
            return True

        @staticmethod
        def hooked_by(_address):
            return Procedure()

    class CFG:
        class KB:
            functions = Functions()

        kb = KB()

    metadata = _target_metadata(
        Project(),
        CFG(),
        mapped_address=0x201050,
        linked_address=0x201050,
        known_functions=set(),
    )
    return (
        metadata.category == "unresolvable"
        and metadata.name == "UnresolvableJumpTarget"
    )


def main() -> int:
    if not _check_unresolvable_jump_classification():
        print("FAIL UnresolvableJumpTarget classification")
        return 1
    raw = _raw_graph()
    augmented = merge_angr_resolutions(
        raw,
        (
            # Singleton known target: promote this unresolved callsite.
            AngrCallResolution(0x2000, 0x2010, (0x4000,)),
            # Multiple targets: preserve uncertainty.
            AngrCallResolution(0x2000, 0x2020, (0x3000, 0x4000)),
            # Existing exact direct edge: never overwrite it.
            AngrCallResolution(0x2000, 0x2030, (0x4000,)),
            # Unknown function start: do not invent an edge.
            AngrCallResolution(0x2000, 0x2040, (0xDEAD,)),
            # Filtering the unknown target first must not create a singleton.
            AngrCallResolution(0x2000, 0x2050, (0x4000, 0xDEAD)),
            # The source function could not be joined unambiguously.
            AngrCallResolution(
                0x2000, 0x2060, (), ambiguous_source=True
            ),
            # 0x2070 is intentionally absent: angr returned no target.
            # Named external target: resolved, but filtered from the graph.
            AngrCallResolution(
                0x2000,
                0x2080,
                (0xF000,),
                target_metadata=(
                    AngrTargetMetadata(0xF000, "import", "malloc"),
                ),
            ),
            # angr's synthetic unresolved target is a real analysis failure.
            AngrCallResolution(
                0x2000,
                0x2090,
                (0xF100,),
                target_metadata=(
                    AngrTargetMetadata(
                        0xF100,
                        "unresolvable",
                        "UnresolvableCallTarget",
                    ),
                ),
            ),
            # An indirect terminal jump is analyzed and remains a tail-call.
            AngrCallResolution(0x2000, 0x20A0, (0x4000,)),
        ),
        angr_version="test",
    )
    validate_raw_graph(augmented)

    by_callsite = {
        int(transfer["callsite"], 16): transfer
        for transfer in augmented["transfers"]
    }
    promoted = by_callsite[0x2010]
    if (
        promoted["status"] != "resolved"
        or promoted["target"] != "0x4000"
        or promoted["resolver"] != ANGR_RESOLVER
        or promoted["confidence"] != "inferred"
    ):
        print(f"FAIL singleton angr resolution: {promoted}")
        return 1
    if by_callsite[0x2020]["status"] != "unresolved":
        print("FAIL multi-target angr result became an exact edge")
        return 1
    if (
        by_callsite[0x2030]["target"] != "0x3000"
        or by_callsite[0x2030]["resolver"] != "direct-immediate"
    ):
        print("FAIL angr overwrote an exact direct edge")
        return 1
    if by_callsite[0x2040]["status"] != "unresolved":
        print("FAIL unknown angr target became an edge")
        return 1
    if by_callsite[0x2050]["status"] != "unresolved":
        print("FAIL mixed known/unknown target set became a singleton edge")
        return 1
    promoted_tail = by_callsite[0x20A0]
    if (
        promoted_tail["kind"] != "tail-call"
        or promoted_tail["status"] != "resolved"
        or promoted_tail["target"] != "0x4000"
        or promoted_tail["resolver"] != ANGR_RESOLVER
    ):
        print(f"FAIL singleton angr tail-call resolution: {promoted_tail}")
        return 1
    expected_statuses = {
        0x2010: "resolved_internal",
        0x2020: "multiple_targets",
        0x2040: "unknown_target",
        0x2050: "multiple_targets",
        0x2060: "ambiguous_source",
        0x2070: "no_angr_result",
        0x2080: "resolved_import",
        0x2090: "unresolvable_target",
    }
    actual_statuses = {
        callsite: by_callsite[callsite]["angr_status"]
        for callsite in expected_statuses
    }
    if actual_statuses != expected_statuses:
        print(f"FAIL angr decision audit: {actual_statuses}")
        return 1
    summary = augmented["indirect_call_summary"]
    if (
        summary["total"] != 9
        or summary["resolved_internal"] != 2
        or summary["resolved_import"] != 1
        or summary["unresolved"] != 6
        or summary["rejected"] != {
            "unresolvable_target": 1,
            "multiple_targets": 2,
            "unknown_target": 1,
            "ambiguous_source": 1,
            "no_angr_result": 1,
        }
    ):
        print(f"FAIL indirect call summary: {summary}")
        return 1
    imported = by_callsite[0x2080]
    if (
        imported["status"] != "filtered"
        or imported["filter_reason"] != "import"
        or imported["angr_target_names"] != {"0xf000": "malloc"}
    ):
        print(f"FAIL resolved import evidence: {imported}")
        return 1
    if augmented["analysis"]["backend"] != ANGR_RAW_GRAPH_BACKEND:
        print("FAIL angr backend provenance")
        return 1
    if augmented["analysis"]["extractor_version"] != "call-evidence-v6+angr-test":
        print("FAIL angr extractor version provenance")
        return 1

    older = _raw_graph()
    older["analysis"]["extractor_version"] = "call-evidence-v5"
    inherited = merge_angr_resolutions(older, (), angr_version="test")
    if inherited["analysis"]["extractor_version"] != "call-evidence-v5+angr-test":
        print("FAIL angr discarded base extractor version")
        return 1

    invalid_backend = _raw_graph()
    invalid_backend["analysis"]["backend"] = ANGR_RAW_GRAPH_BACKEND
    try:
        merge_angr_resolutions(invalid_backend, (), angr_version="test")
    except ValueError:
        pass
    else:
        print("FAIL angr accepted a non-base raw backend")
        return 1

    fixture = project_fixture(
        augmented,
        selection=_selection(),
        track=ANGR_TRACK,
        users_path="users/plain/angr-test.O3S.users.json",
        id_bias=0,
    )
    nodes = {node["id"]: node for node in fixture["nodes"]}
    calls = nodes["FUN_00002000"]["calls"]
    if calls != [
        {"target": "FUN_00003000", "count": 1},
        {"target": "FUN_00004000", "count": 2},
    ]:
        print(f"FAIL angr edge was not projected: {calls}")
        return 1
    if fixture["analysis"]["edge_policy"] != [
        "direct-immediate",
        "direct-tail",
        ELF_RELOCATION_RESOLVER,
        ANGR_RESOLVER,
    ]:
        print("FAIL angr edge policy provenance")
        return 1

    print("angr singleton indirect-call augmentation PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
