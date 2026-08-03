from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from candidate_selection import parse_candidate_selection
from graph_evidence import TransferEvidence, make_raw_graph, raw_graph_sha256
from graph_projector import project_direct_in_fixture, project_direct_v0_fixture
from loader import validate_raw_fixture
from paths import (
    DIRECT_IN_V1_TRACK,
    DIRECT_V0_TRACK,
    fixture_json_for,
    raw_graph_for,
)
from provenance import BuildProvenance


PROVENANCE = BuildProvenance(
    build_id="projector-test",
    source_sha256="1" * 64,
    non_stripped_sha256="2" * 64,
    stripped_sha256="3" * 64,
)


def resolved(source: int, callsite: int, target: int) -> TransferEvidence:
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


def unresolved(source: int, callsite: int) -> TransferEvidence:
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


def filtered_import(source: int, callsite: int, target: int) -> TransferEvidence:
    return TransferEvidence(
        source=source,
        callsite=callsite,
        instruction=f"call 0x{target:x}",
        kind="call",
        operand_kind="immediate",
        status="filtered",
        target=target,
        resolver="direct-immediate",
        confidence="exact",
        filter_reason="import",
    )


def selection(addresses: set[int], bounds: dict[int, int]):
    data = {
        "case": "projector-test",
        "build": "O3S",
        "profile": "plain",
        "schema_version": 5,
        "provenance": PROVENANCE.to_dict(),
        "source": "gt_bin/plain/projector-test.O3S.gt.bin",
        "prefix": "projector-test::",
        "addresses": [f"0x{address:x}" for address in sorted(addresses)],
        "function_bounds": [
            {"address": f"0x{address:x}", "size": size}
            for address, size in sorted(bounds.items())
        ],
    }
    return parse_candidate_selection(
        data,
        expected_case="projector-test",
        expected_build="O3S",
        expected_profile="plain",
    )


def check_track_paths() -> int:
    legacy = fixture_json_for("sample", "O3S", "plain", DIRECT_V0_TRACK)
    if legacy != "fixtures/plain/sample.O3S.fixture.json":
        print(f"FAIL direct-v0 path changed: {legacy}")
        return 1
    tracked = fixture_json_for("sample", "O3S", "plain", DIRECT_IN_V1_TRACK)
    if tracked != "fixtures/direct-in-v1/plain/sample.O3S.fixture.json":
        print(f"FAIL direct-in-v1 fixture path: {tracked}")
        return 1
    raw = raw_graph_for("sample", "O3S", "plain")
    if raw != "extractions/plain/sample.O3S.raw.json":
        print(f"FAIL track-independent raw path: {raw}")
        return 1
    return 0


def check_incoming_projection() -> int:
    # root -> A; A -> outgoing/both; incoming -> A/B; both -> B.
    addresses = (0x1000, 0x2000, 0x2100, 0x3000, 0x4000, 0x5000, 0x6000)
    raw = make_raw_graph(
        case="projector-test",
        build="O3S",
        profile="plain",
        binary_path="bin/plain/projector-test.O3S.fixture.bin",
        provenance=PROVENANCE,
        root_address=0x1000,
        functions=[
            {
                "address": f"0x{address:x}",
                "name": f"function_{address:x}",
                "size": 0x20,
                "boundary_source": (
                    "symbol-oracle" if address in {0x2000, 0x2100} else "radare2"
                ),
            }
            for address in addresses
        ],
        transfers=[
            resolved(0x1000, 0x1004, 0x2000),
            resolved(0x2000, 0x2004, 0x3000),
            resolved(0x2000, 0x2008, 0x5000),
            unresolved(0x2000, 0x200C),
            filtered_import(0x2000, 0x2010, 0xDEAD),
            resolved(0x3000, 0x3004, 0x6000),
            resolved(0x4000, 0x4004, 0x2000),
            resolved(0x4000, 0x4008, 0x2100),
            resolved(0x4000, 0x400C, 0x6000),
            resolved(0x5000, 0x5004, 0x2100),
        ],
        boundary_mode="symbol-extent",
        boundary_mismatches=[],
    )
    fixture = project_direct_in_fixture(
        raw,
        selection=selection(
            {0x2000, 0x2100},
            {0x2000: 0x20, 0x2100: 0x20},
        ),
        users_path="users/plain/projector-test.O3S.users.json",
        id_bias=0,
    )
    validate_raw_fixture(fixture)
    nodes = {node["id"]: node for node in fixture["nodes"]}

    expected = {
        "FUN_00001000",
        "FUN_00002000",
        "FUN_00002100",
        "FUN_00003000",
        "FUN_00004000",
        "FUN_00005000",
    }
    if set(nodes) != expected or "FUN_00006000" in nodes:
        print(f"FAIL projected one-hop node set: {sorted(nodes)}")
        return 1

    expected_kinds = {
        "FUN_00001000": "root",
        "FUN_00003000": "outgoing",
        "FUN_00004000": "incoming",
        "FUN_00005000": "both",
    }
    actual_kinds = {
        node_id: node["anchor_kind"]
        for node_id, node in nodes.items()
        if node["type"] == "anchor"
    }
    if actual_kinds != expected_kinds:
        print(f"FAIL anchor roles: expected {expected_kinds}, got {actual_kinds}")
        return 1

    if nodes["FUN_00004000"]["calls"] != [
        {"target": "FUN_00002000", "count": 1},
        {"target": "FUN_00002100", "count": 1},
    ]:
        print("FAIL shared incoming anchor did not retain both candidate edges")
        return 1
    if nodes["FUN_00003000"]["calls"]:
        print("FAIL outgoing anchor leaked its library-internal edge")
        return 1
    if nodes["FUN_00005000"]["calls"] != [
        {"target": "FUN_00002100", "count": 1}
    ]:
        print("FAIL both anchor did not retain its candidate edge")
        return 1
    if (
        nodes["FUN_00002000"]["observability"]
        ["unresolved_indirect_out_callsites"]
        != 1
    ):
        print("FAIL unresolved register call was not retained as evidence")
        return 1
    if nodes["FUN_00002000"]["calls"] != [
        {"target": "FUN_00003000", "count": 1},
        {"target": "FUN_00005000", "count": 1},
    ]:
        print("FAIL unresolved call was projected as a fake edge")
        return 1

    analysis = fixture["analysis"]
    if (
        analysis["track"] != DIRECT_IN_V1_TRACK
        or analysis["raw_graph_sha256"] != raw_graph_sha256(raw)
        or not analysis["candidate_selection_sha256"]
    ):
        print("FAIL analysis provenance does not bind the raw graph")
        return 1

    v0 = project_direct_v0_fixture(
        raw,
        selection=selection(
            {0x2000, 0x2100},
            {0x2000: 0x20, 0x2100: 0x20},
        ),
        users_path="users/plain/projector-test.O3S.users.json",
        id_bias=0,
    )
    if v0["schema_version"] != 4 or "analysis" in v0:
        print("FAIL frozen direct-v0 projection changed schema")
        return 1
    v0_nodes = {node["id"]: node for node in v0["nodes"]}
    if "FUN_00004000" in v0_nodes:
        print("FAIL direct-v0 projection included an incoming-only caller")
        return 1
    if v0_nodes["FUN_00005000"]["calls"]:
        print("FAIL direct-v0 outgoing anchor retained its incoming edge")
        return 1
    return 0


def check_noncontiguous_radare2_function() -> int:
    # radare2 may assign a basic block below the function's nominal entry.
    # Symbol-oracle extents are linear, while radare2 functions need not be.
    common = {
        "case": "noncontiguous-test",
        "build": "O3S",
        "profile": "plain",
        "binary_path": "bin/plain/noncontiguous-test.O3S.fixture.bin",
        "provenance": PROVENANCE,
        "root_address": 0x5000,
        "transfers": [resolved(0x5000, 0x4000, 0x6000)],
        "boundary_mode": "radare2",
        "boundary_mismatches": [],
    }
    make_raw_graph(
        **common,
        functions=[
            {
                "address": "0x5000", "name": "root", "size": 0x20,
                "boundary_source": "radare2",
            },
            {
                "address": "0x6000", "name": "candidate", "size": 0x20,
                "boundary_source": "symbol-oracle",
            },
        ],
    )

    try:
        make_raw_graph(
            **common,
            functions=[
                {
                    "address": "0x5000",
                    "name": "root",
                    "size": 0x20,
                    "boundary_source": "symbol-oracle",
                },
                {
                    "address": "0x6000",
                    "name": "candidate",
                    "size": 0x20,
                    "boundary_source": "symbol-oracle",
                },
            ],
        )
    except ValueError as exc:
        if "outside its source function extent" not in str(exc):
            print(f"FAIL unexpected symbol extent error: {exc}")
            return 1
    else:
        print("FAIL symbol-oracle extent accepted an out-of-range callsite")
        return 1
    return 0


def main() -> int:
    if check_track_paths() != 0:
        return 1
    if check_incoming_projection() != 0:
        return 1
    if check_noncontiguous_radare2_function() != 0:
        return 1
    print("raw graph and direct incoming projection PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
