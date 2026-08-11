from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from candidate_selection import parse_candidate_selection
from graph_evidence import (
    ELF_RELOCATION_RESOLVER,
    TransferEvidence,
    make_raw_graph,
    raw_graph_sha256,
)
from graph_projector import (
    project_direct_fixture,
    project_context_fixture,
    project_fixture,
)
from loader import validate_raw_fixture
from paths import (
    ANGR_EVIDENCE,
    ANGR_TRACK,
    DIRECT_IN_TRACK,
    DIRECT_TRACK,
    RUST_NONSTD_CANDIDATE_SCOPE,
    ROLE_ANCHOR_POLICY,
    SUBJECT_CANDIDATE_SCOPE,
    fixture_json_for,
    raw_graph_for,
)
from provenance import BuildProvenance
from scores import reports_to_dict, score_case, score_report_to_dict


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


def relocated(source: int, callsite: int, target: int) -> TransferEvidence:
    return TransferEvidence(
        source=source,
        callsite=callsite,
        instruction="call qword ptr [rip + slot]",
        kind="call",
        operand_kind="memory",
        status="resolved",
        target=target,
        resolver=ELF_RELOCATION_RESOLVER,
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


def unmapped(source: int, callsite: int, target: int) -> TransferEvidence:
    return TransferEvidence(
        source=source,
        callsite=callsite,
        instruction=f"call 0x{target:x}",
        kind="call",
        operand_kind="immediate",
        status="unmapped",
        target=target,
        resolver="direct-immediate",
        confidence="exact",
    )


def unmapped_relocation(
    source: int,
    callsite: int,
    target: int,
) -> TransferEvidence:
    return TransferEvidence(
        source=source,
        callsite=callsite,
        instruction="call qword ptr [rip + slot]",
        kind="call",
        operand_kind="memory",
        status="unmapped",
        target=target,
        resolver=ELF_RELOCATION_RESOLVER,
        confidence="exact",
    )


def selection(
    addresses: set[int],
    bounds: dict[int, int],
    *,
    case: str = "projector-test",
):
    data = {
        "case": case,
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
        expected_case=case,
        expected_build="O3S",
        expected_profile="plain",
    )


def broad_selection(
    addresses: set[int],
    bounds: dict[int, int],
    *,
    case: str = "projector-test",
):
    data = {
        "case": case,
        "build": "O3S",
        "profile": "plain",
        "schema_version": 6,
        "provenance": PROVENANCE.to_dict(),
        "source": f"gt_bin/plain/{case}.O3S.gt.bin",
        "scope": "rust-nonstd",
        "root_namespace": "projector_test",
        "namespaces": [],
        "excluded_namespaces": ["core", "alloc", "std", "__rustc"],
        "addresses": [f"0x{address:x}" for address in sorted(addresses)],
        "function_bounds": [
            {"address": f"0x{address:x}", "size": size}
            for address, size in sorted(bounds.items())
        ],
    }
    return parse_candidate_selection(
        data,
        expected_case=case,
        expected_build="O3S",
        expected_profile="plain",
    )


def check_track_paths() -> int:
    legacy = fixture_json_for(
        "sample", "O3S", "plain", DIRECT_TRACK, SUBJECT_CANDIDATE_SCOPE
    )
    if legacy != "fixtures/plain/sample.O3S.fixture.json":
        print(f"FAIL direct path changed: {legacy}")
        return 1
    tracked = fixture_json_for(
        "sample", "O3S", "plain", DIRECT_IN_TRACK, SUBJECT_CANDIDATE_SCOPE
    )
    if tracked != "fixtures/direct-in/plain/sample.O3S.fixture.json":
        print(f"FAIL direct-in fixture path: {tracked}")
        return 1
    raw = raw_graph_for("sample", "O3S", "plain")
    if raw != "extractions/plain/sample.O3S.raw.json":
        print(f"FAIL track-independent raw path: {raw}")
        return 1
    angr_raw = raw_graph_for("sample", "O3S", "plain", ANGR_EVIDENCE)
    if angr_raw != "extractions/angr/plain/sample.O3S.raw.json":
        print(f"FAIL angr raw path: {angr_raw}")
        return 1
    angr_fixture = fixture_json_for(
        "sample", "O3S", "plain", ANGR_TRACK, SUBJECT_CANDIDATE_SCOPE
    )
    if angr_fixture != "fixtures/angr/plain/sample.O3S.fixture.json":
        print(f"FAIL angr fixture path: {angr_fixture}")
        return 1
    broad = fixture_json_for(
        "sample",
        "O3S",
        "plain",
        DIRECT_IN_TRACK,
        RUST_NONSTD_CANDIDATE_SCOPE,
    )
    if broad != "fixtures/direct-in/rust-nonstd/plain/sample.O3S.fixture.json":
        print(f"FAIL scoped fixture path: {broad}")
        return 1
    default_path = fixture_json_for(
        "sample", "O3S", "plain", DIRECT_IN_TRACK
    )
    if default_path != broad:
        print(f"FAIL rust-nonstd is not the default candidate scope: {default_path}")
        return 1
    role = fixture_json_for(
        "sample",
        "O3S",
        "plain",
        DIRECT_IN_TRACK,
        SUBJECT_CANDIDATE_SCOPE,
        ROLE_ANCHOR_POLICY,
    )
    if role != "fixtures/direct-in/role/plain/sample.O3S.fixture.json":
        print(f"FAIL role fixture path: {role}")
        return 1
    return 0


def check_incoming_projection() -> int:
    # root -> A; A -> outgoing/both; incoming -> A/B; both -> B.
    addresses = (
        0x1000, 0x2000, 0x2100, 0x3000,
        0x4000, 0x5000, 0x6000, 0x7000,
    )
    raw = make_raw_graph(
        case="projector-test",
        build="O3S",
        profile="plain",
        binary_path="bin/plain/projector-test.O3S.fixture.bin",
        provenance=PROVENANCE,
        boundary_input_sha256="4" * 64,
        root_address=0x1000,
        functions=[
            {
                "address": f"0x{address:x}",
                "name": f"function_{address:x}",
                "size": 0x20,
                "boundary_source": (
                    "symbol-oracle" if address in {0x2000, 0x2100} else "radare2"
                ),
                # 0x3000 exists only because the common symbol-boundary oracle
                # recovered it. direct-in may use it; frozen direct may
                # not silently gain this new external anchor.
                "discovered_by_radare2": address != 0x3000,
            }
            for address in addresses
        ],
        transfers=[
            resolved(0x1000, 0x1004, 0x2000),
            resolved(0x2000, 0x2004, 0x3000),
            resolved(0x2000, 0x2008, 0x5000),
            relocated(0x2100, 0x2104, 0x3000),
            unresolved(0x2000, 0x200C),
            filtered_import(0x2000, 0x2010, 0xDEAD),
            unmapped(0x2000, 0x2014, 0xBEEF),
            resolved(0x3000, 0x3004, 0x6000),
            resolved(0x4000, 0x4004, 0x2000),
            resolved(0x4000, 0x4008, 0x2100),
            resolved(0x4000, 0x400C, 0x6000),
            resolved(0x5000, 0x5004, 0x2100),
            resolved(0x7000, 0x7004, 0x2000),
        ],
        boundary_mode="symbol-extent",
        boundary_mismatches=[],
    )
    fixture = project_context_fixture(
        raw,
        selection=selection(
            {0x2000, 0x2100},
            {0x2000: 0x20, 0x2100: 0x20},
        ),
        users_path="users/plain/projector-test.O3S.users.json",
        id_bias=0,
    )
    validate_raw_fixture(fixture)
    if "track" in raw["analysis"] or "candidates" in raw:
        print("FAIL raw evidence contains projection/candidate policy")
        return 1
    nodes = {node["id"]: node for node in fixture["nodes"]}

    expected = {
        "FUN_00001000",
        "FUN_00002000",
        "FUN_00002100",
        "FUN_00003000",
        "FUN_00004000",
        "FUN_00005000",
        "FUN_00006000",
        "FUN_00007000",
    }
    if set(nodes) != expected:
        print(f"FAIL projected outgoing-closure node set: {sorted(nodes)}")
        return 1

    expected_kinds = {
        "FUN_00001000": "root",
        "FUN_00003000": "outgoing",
        "FUN_00004000": "incoming",
        "FUN_00005000": "both",
        "FUN_00006000": "context",
        "FUN_00007000": "incoming",
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
        {"target": "FUN_00006000", "count": 1},
    ]:
        print("FAIL shared incoming anchor did not retain both candidate edges")
        return 1
    if nodes["FUN_00007000"]["calls"] != [
        {"target": "FUN_00002000", "count": 1}
    ]:
        print("FAIL second incoming anchor lost its candidate edge")
        return 1
    if nodes["FUN_00003000"]["calls"] != [
        {"target": "FUN_00006000", "count": 1}
    ]:
        print("FAIL outgoing anchor lost its library-internal edge")
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
        analysis["track"] != DIRECT_IN_TRACK
        or analysis["candidate_scope"] != "subject"
        or analysis["raw_graph_sha256"] != raw_graph_sha256(raw)
        or not analysis["candidate_selection_sha256"]
    ):
        print("FAIL analysis provenance does not bind the raw graph")
        return 1

    direct = project_direct_fixture(
        raw,
        selection=selection(
            {0x2000, 0x2100},
            {0x2000: 0x20, 0x2100: 0x20},
        ),
        users_path="users/plain/projector-test.O3S.users.json",
        id_bias=0,
    )
    if direct["schema_version"] != 4 or "analysis" in direct:
        print("FAIL frozen direct projection changed schema")
        return 1
    direct_nodes = {node["id"]: node for node in direct["nodes"]}
    if "FUN_00004000" in direct_nodes:
        print("FAIL direct projection included an incoming-only caller")
        return 1
    if "FUN_00003000" in direct_nodes:
        print("FAIL direct projection gained a symbol-only external anchor")
        return 1
    if direct_nodes["FUN_00005000"]["calls"] != [
        {"target": "FUN_00002100", "count": 1}
    ]:
        print("FAIL direct anchor lost its outgoing edge")
        return 1
    if direct_nodes["FUN_00002100"]["calls"]:
        print("FAIL frozen direct projection gained an ELF relocation edge")
        return 1

    broad_direct = project_fixture(
        raw,
        selection=broad_selection(
            {0x2000, 0x2100},
            {0x2000: 0x20, 0x2100: 0x20},
        ),
        track=DIRECT_TRACK,
        users_path="users/rust-nonstd/plain/projector-test.O3S.users.json",
        id_bias=0,
    )
    validate_raw_fixture(broad_direct)
    if (
        broad_direct["schema_version"] != 6
        or broad_direct["analysis"]["candidate_scope"] != "rust-nonstd"
        or not broad_direct["analysis"]["candidate_selection_sha256"]
    ):
        print("FAIL broad direct projection lost candidate provenance")
        return 1
    broad_direct_nodes = {node["id"]: node for node in broad_direct["nodes"]}
    if "FUN_00004000" in broad_direct_nodes:
        print("FAIL broad direct projection included an incoming-only caller")
        return 1
    if broad_direct_nodes["FUN_00003000"]["calls"] != [
        {"target": "FUN_00006000", "count": 1}
    ]:
        print("FAIL broad direct projection stopped at an anchor")
        return 1
    if broad_direct_nodes["FUN_00002100"]["calls"] != [
        {"target": "FUN_00003000", "count": 1}
    ]:
        print("FAIL schema-v6 direct projection lost an ELF relocation edge")
        return 1

    role_fixture = project_fixture(
        raw,
        selection=selection(
            {0x2000, 0x2100},
            {0x2000: 0x20, 0x2100: 0x20},
        ),
        track=DIRECT_IN_TRACK,
        anchor_policy=ROLE_ANCHOR_POLICY,
        users_path="users/plain/projector-test.O3S.users.json",
        id_bias=0,
    )
    validate_raw_fixture(role_fixture)
    role_nodes = {node["id"]: node for node in role_fixture["nodes"]}
    expected_role_colors = {
        "FUN_00001000": "ROLE:root",
        "FUN_00003000": "ROLE:outgoing",
        "FUN_00004000": "ROLE:incoming",
        "FUN_00005000": "ROLE:both",
        "FUN_00006000": "ROLE:context",
        "FUN_00007000": "ROLE:incoming",
    }
    actual_role_colors = {
        node_id: node["color_class"]
        for node_id, node in role_nodes.items()
        if node["type"] == "anchor"
    }
    if actual_role_colors != expected_role_colors:
        print(
            f"FAIL role anchor colors: expected {expected_role_colors}, "
            f"got {actual_role_colors}"
        )
        return 1
    if role_fixture["analysis"]["anchor_policy"] != ROLE_ANCHOR_POLICY:
        print("FAIL role policy missing from analysis provenance")
        return 1
    return 0


def check_abstention_projection_and_scoring() -> int:
    # root -> active; self_only -> self_only. The latter has no relational
    # evidence with another function and must not receive a CG-WL color.
    raw = make_raw_graph(
        case="abstention-test",
        build="O3S",
        profile="plain",
        binary_path="bin/plain/abstention-test.O3S.fixture.bin",
        provenance=PROVENANCE,
        boundary_input_sha256="4" * 64,
        root_address=0x1000,
        functions=[
            {
                "address": f"0x{address:x}",
                "name": f"function_{address:x}",
                "size": 0x20,
                "boundary_source": "symbol-oracle",
                "discovered_by_radare2": True,
            }
            for address in (0x1000, 0x2000, 0x2100, 0x2200, 0x8000)
        ],
        transfers=[
            resolved(0x1000, 0x1004, 0x2000),
            resolved(0x2100, 0x2104, 0x2100),
            resolved(0x8000, 0x8004, 0x2200),
        ],
        boundary_mode="symbol-extent",
        boundary_mismatches=[],
    )
    fixture = project_fixture(
        raw,
        selection=broad_selection(
            {0x2000, 0x2100, 0x2200},
            {0x2000: 0x20, 0x2100: 0x20, 0x2200: 0x20},
            case="abstention-test",
        ),
        track=DIRECT_TRACK,
        users_path=None,
        id_bias=0,
    )
    validate_raw_fixture(fixture)
    node_ids = {node["id"] for node in fixture["nodes"]}
    expected_abstention = [
        {
            "id": "FUN_00002100",
            "status": "abstain",
            "reason": "no_resolved_nonself_in_or_out_edge",
        },
        {
            "id": "FUN_00002200",
            "status": "abstain",
            "reason": "no_resolved_nonself_in_or_out_edge",
        },
    ]
    if (
        "FUN_00002100" in node_ids
        or "FUN_00002200" in node_ids
        or "FUN_00008000" in node_ids
        or fixture["abstentions"] != expected_abstention
    ):
        print(f"FAIL abstention projection: {fixture['abstentions']}")
        return 1

    direct_in = project_fixture(
        raw,
        selection=broad_selection(
            {0x2000, 0x2100, 0x2200},
            {0x2000: 0x20, 0x2100: 0x20, 0x2200: 0x20},
            case="abstention-test",
        ),
        track=DIRECT_IN_TRACK,
        users_path=None,
        id_bias=0,
    )
    direct_in_nodes = {node["id"]: node for node in direct_in["nodes"]}
    if (
        "FUN_00002200" not in direct_in_nodes
        or direct_in_nodes["FUN_00008000"]["anchor_kind"] != "incoming"
        or direct_in_nodes["FUN_00008000"]["calls"] != [
            {"target": "FUN_00002200", "count": 1}
        ]
        or [item["id"] for item in direct_in["abstentions"]]
        != ["FUN_00002100"]
    ):
        print("FAIL direct/direct-in incoming-only candidate distinction")
        return 1

    ground_truth = {
        "case": "abstention-test",
        "build": "O3S",
        "profile": "plain",
        "schema_version": 5,
        "provenance": PROVENANCE.to_dict(),
        "origins": [{
            "origin": "shared",
            "members": ["FUN_00002000", "FUN_00002100"],
        }, {
            "origin": "external_only",
            "members": ["FUN_00002200"],
        }],
        "symbols": {
            "FUN_00002000": ["abstention_test::shared::<i32>"],
            "FUN_00002100": ["abstention_test::shared::<u64>"],
            "FUN_00002200": ["abstention_test::external_only"],
        },
    }
    with tempfile.TemporaryDirectory() as directory:
        fixture_path = os.path.join(directory, "fixture.json")
        gt_path = os.path.join(directory, "ground_truth.json")
        with open(fixture_path, "w", encoding="utf-8") as handle:
            json.dump(fixture, handle)
        with open(gt_path, "w", encoding="utf-8") as handle:
            json.dump(ground_truth, handle)
        report = score_case(fixture_path, gt_path)

        all_abstain_fixture = project_fixture(
            raw,
            selection=broad_selection(
                {0x2100, 0x2200},
                {0x2100: 0x20, 0x2200: 0x20},
                case="abstention-test",
            ),
            track=DIRECT_TRACK,
            users_path=None,
            id_bias=0,
        )
        all_abstain_gt = {
            "case": "abstention-test",
            "build": "O3S",
            "profile": "plain",
            "schema_version": 5,
            "provenance": PROVENANCE.to_dict(),
            "origins": [{
                "origin": "shared",
                "members": ["FUN_00002100", "FUN_00002200"],
            }],
            "symbols": {
                "FUN_00002100": ["abstention_test::shared::<i32>"],
                "FUN_00002200": ["abstention_test::shared::<u64>"],
            },
        }
        all_abstain_fixture_path = os.path.join(
            directory, "all-abstain-fixture.json"
        )
        all_abstain_gt_path = os.path.join(
            directory, "all-abstain-ground-truth.json"
        )
        with open(all_abstain_fixture_path, "w", encoding="utf-8") as handle:
            json.dump(all_abstain_fixture, handle)
        with open(all_abstain_gt_path, "w", encoding="utf-8") as handle:
            json.dump(all_abstain_gt, handle)
        all_abstain_report = score_case(
            all_abstain_fixture_path,
            all_abstain_gt_path,
        )

        no_abstain_fixture = project_fixture(
            raw,
            selection=broad_selection(
                {0x2000},
                {0x2000: 0x20},
                case="abstention-test",
            ),
            track=DIRECT_TRACK,
            users_path=None,
            id_bias=0,
        )
        no_abstain_gt = {
            "case": "abstention-test",
            "build": "O3S",
            "profile": "plain",
            "schema_version": 5,
            "provenance": PROVENANCE.to_dict(),
            "origins": [{
                "origin": "active",
                "members": ["FUN_00002000"],
            }],
            "symbols": {
                "FUN_00002000": ["abstention_test::active"],
            },
        }
        no_abstain_fixture_path = os.path.join(
            directory, "no-abstain-fixture.json"
        )
        no_abstain_gt_path = os.path.join(
            directory, "no-abstain-ground-truth.json"
        )
        with open(no_abstain_fixture_path, "w", encoding="utf-8") as handle:
            json.dump(no_abstain_fixture, handle)
        with open(no_abstain_gt_path, "w", encoding="utf-8") as handle:
            json.dump(no_abstain_gt, handle)
        no_abstain_report = score_case(
            no_abstain_fixture_path,
            no_abstain_gt_path,
        )

    if (
        report.target_count != 3
        or report.candidate_count != 1
        or report.pair_count != 0
        or report.scored_same_family_pair_count != 0
        or report.pairwise.f1 is not None
        or report.pairwise.ari is not None
        or len(report.abstentions) != 2
        or report.abstentions[0].origin != "shared"
        or report.origins[0].scored_instance_count != 1
        or report.origins[0].abstained_instance_count != 1
    ):
        print(f"FAIL abstention scoring: {report}")
        return 1
    if (
        all_abstain_report.grouped_candidate_count != 0
        or all_abstain_report.target_count != 2
        or all_abstain_report.pairwise.f1 is not None
        or all_abstain_report.pairwise.ari is not None
        or all_abstain_report.effective_family_pair_recall != 0.0
    ):
        print(f"FAIL all-abstain scoring: {all_abstain_report}")
        return 1
    no_abstain_rendered = score_report_to_dict(no_abstain_report)
    no_abstain_document = reports_to_dict((no_abstain_report,))
    if (
        no_abstain_document.get("schema_version") != 6
        or no_abstain_rendered.get("schema_version") != 6
        or no_abstain_rendered.get("target_count") != 1
        or no_abstain_rendered.get("grouped_candidate_count") != 1
        or no_abstain_rendered.get("abstained_candidate_count") != 0
        or no_abstain_rendered.get("abstentions") != []
        or no_abstain_rendered.get("coverage", {}).get("target_coverage") != 1.0
    ):
        print(f"FAIL schema-v6 zero-abstention output: {no_abstain_rendered}")
        return 1
    rendered = score_report_to_dict(report)
    if rendered.get("coverage", {}).get("effective_family_pair_recall") != 0.0:
        print(f"FAIL effective recall: {rendered.get('coverage')}")
        return 1
    if [item["id"] for item in rendered.get("abstentions", [])] != [
        "FUN_00002100",
        "FUN_00002200",
    ]:
        print(f"FAIL abstention result JSON: {rendered.get('abstentions')}")
        return 1
    return 0


def check_opaque_relocation_anchor() -> int:
    raw = make_raw_graph(
        case="opaque-anchor-test",
        build="O3S",
        profile="plain",
        binary_path="bin/plain/opaque-anchor-test.O3S.fixture.bin",
        provenance=PROVENANCE,
        boundary_input_sha256="4" * 64,
        root_address=0x1000,
        functions=[
            {
                "address": f"0x{address:x}",
                "name": f"function_{address:x}",
                "size": 0x20,
                "boundary_source": "symbol-oracle",
                "discovered_by_radare2": True,
            }
            for address in (0x1000, 0x2000)
        ],
        transfers=[
            resolved(0x1000, 0x1004, 0x2000),
            unmapped_relocation(0x2000, 0x2004, 0x9000),
            unmapped_relocation(0x2000, 0x2008, 0x9000),
            unmapped(0x2000, 0x200C, 0xA000),
        ],
        boundary_mode="symbol-extent",
        boundary_mismatches=[],
    )
    candidate_selection = broad_selection(
        {0x2000},
        {0x2000: 0x20},
        case="opaque-anchor-test",
    )
    fixture = project_fixture(
        raw,
        selection=candidate_selection,
        track=DIRECT_TRACK,
        anchor_policy=ROLE_ANCHOR_POLICY,
        users_path=None,
        id_bias=0,
    )
    validate_raw_fixture(fixture)
    nodes = {node["id"]: node for node in fixture["nodes"]}
    if set(nodes) != {
        "FUN_00001000", "FUN_00002000", "FUN_00009000"
    }:
        print(f"FAIL opaque relocation node set: {sorted(nodes)}")
        return 1
    if nodes["FUN_00002000"]["calls"] != [
        {"target": "FUN_00009000", "count": 2}
    ]:
        print("FAIL exact relocation calls were not projected to opaque anchor")
        return 1
    opaque = nodes["FUN_00009000"]
    if (
        opaque["type"] != "anchor"
        or opaque["scored"]
        or opaque["anchor_kind"] != "outgoing"
        or opaque["color_class"] != "ROLE:outgoing"
        or opaque["calls"]
    ):
        print(f"FAIL opaque relocation anchor metadata: {opaque}")
        return 1
    if "FUN_0000a000" in nodes:
        print("FAIL ordinary unmapped direct target became an opaque anchor")
        return 1
    if fixture["abstentions"]:
        print("FAIL exact opaque relation did not keep candidate active")
        return 1

    frozen = project_direct_fixture(
        raw,
        selection=selection(
            {0x2000},
            {0x2000: 0x20},
            case="opaque-anchor-test",
        ),
        users_path=None,
        id_bias=0,
    )
    frozen_nodes = {node["id"]: node for node in frozen["nodes"]}
    if "FUN_00009000" in frozen_nodes or frozen_nodes["FUN_00002000"]["calls"]:
        print("FAIL frozen schema-v4 fixture gained an opaque relocation anchor")
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
        "boundary_input_sha256": "4" * 64,
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
                "discovered_by_radare2": True,
            },
            {
                "address": "0x6000", "name": "candidate", "size": 0x20,
                "boundary_source": "symbol-oracle",
                "discovered_by_radare2": True,
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
                    "discovered_by_radare2": True,
                },
                {
                    "address": "0x6000",
                    "name": "candidate",
                    "size": 0x20,
                    "boundary_source": "symbol-oracle",
                    "discovered_by_radare2": True,
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
    if check_abstention_projection_and_scoring() != 0:
        return 1
    if check_opaque_relocation_anchor() != 0:
        return 1
    print("raw graph and direct incoming projection PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
