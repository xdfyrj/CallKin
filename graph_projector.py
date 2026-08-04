from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from analysis_provenance import AnalysisProvenance
from candidate_selection import CandidateSelection, load_candidate_selection
from graph_evidence import (
    ANGR_RAW_GRAPH_BACKEND,
    ANGR_RESOLVER,
    RAW_GRAPH_BACKEND,
    load_raw_graph,
    raw_graph_sha256,
    validate_raw_graph,
)
from paths import (
    ANALYSIS_TRACKS,
    ANGR_TRACK,
    DEFAULT_ANALYSIS_TRACK,
    DIRECT_IN_TRACK,
    DIRECT_TRACK,
    SUBJECT_CANDIDATE_SCOPE,
    fixture_json_for,
    normalize_track,
)
from provenance import parse_provenance


FIXTURE_SCHEMA_V5 = 5
ANCHOR_POLICIES = ("address", "role")


@dataclass(frozen=True)
class ProjectionConfig:
    track: str
    include_incoming_anchors: bool
    anchor_policy: str
    edge_policy: tuple[str, ...]
    oracle_level: str = "candidate-and-boundary"

    def to_dict(self) -> dict[str, object]:
        return {
            "track": self.track,
            "include_incoming_anchors": self.include_incoming_anchors,
            "anchor_policy": self.anchor_policy,
            "edge_policy": list(self.edge_policy),
            "oracle_level": self.oracle_level,
        }


def projection_config_for(track: str) -> ProjectionConfig:
    track = normalize_track(track)
    if track == DIRECT_TRACK:
        return ProjectionConfig(
            track=track,
            include_incoming_anchors=False,
            anchor_policy="address",
            edge_policy=("direct-immediate", "direct-tail"),
        )
    if track == DIRECT_IN_TRACK:
        return ProjectionConfig(
            track=track,
            include_incoming_anchors=True,
            anchor_policy="address",
            edge_policy=("direct-immediate", "direct-tail"),
        )
    if track == ANGR_TRACK:
        return ProjectionConfig(
            track=track,
            include_incoming_anchors=True,
            anchor_policy="address",
            edge_policy=("direct-immediate", "direct-tail", ANGR_RESOLVER),
        )
    raise ValueError(f"unsupported projection track: {track}")


def projection_config_sha256(config: ProjectionConfig) -> str:
    encoded = json.dumps(
        config.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def resolved_graph(
    raw: dict[str, Any],
    config: ProjectionConfig,
) -> dict[int, Counter[int]]:
    validate_raw_graph(raw)
    functions = {
        _address(item["address"])
        for item in raw["functions"]
    }
    graph = {address: Counter() for address in functions}
    allowed_resolvers = set(config.edge_policy)
    for transfer in raw["transfers"]:
        if (
            transfer["status"] == "resolved"
            and transfer["resolver"] in allowed_resolvers
        ):
            graph[_address(transfer["source"])][_address(transfer["target"])] += 1
    return graph


def project_context_fixture(
    raw: dict[str, Any],
    *,
    selection: CandidateSelection,
    users_path: str | None,
    id_bias: int,
    score_root: bool = False,
    config: ProjectionConfig | None = None,
) -> dict[str, Any]:
    validate_raw_graph(raw)
    config = config or projection_config_for(DIRECT_IN_TRACK)
    if config.track not in {DIRECT_TRACK, DIRECT_IN_TRACK, ANGR_TRACK}:
        raise ValueError(f"unsupported schema v5 projection track: {config.track}")
    if config.anchor_policy not in ANCHOR_POLICIES:
        raise ValueError(f"unsupported anchor policy: {config.anchor_policy}")
    _validate_selection_join(raw, selection)

    graph = resolved_graph(raw, config)
    root = _address(raw["root"])
    candidates = set(selection.addresses)
    unknown_candidates = candidates - set(graph)
    if unknown_candidates:
        rendered = ", ".join(f"0x{value:x}" for value in sorted(unknown_candidates))
        raise ValueError(f"candidate selection is absent from raw graph: {rendered}")
    scored_users = set(candidates)
    if score_root:
        scored_users.add(root)

    outgoing_anchors = {
        target
        for source in scored_users
        for target in graph[source]
        if target not in scored_users
    }
    incoming_anchors = set()
    if config.include_incoming_anchors:
        incoming_anchors = {
            source
            for source, targets in graph.items()
            if source not in scored_users
            and source != root
            and any(target in candidates for target in targets)
        }

    selected = (
        scored_users
        | outgoing_anchors
        | incoming_anchors
        | {root}
    )
    raw_digest = raw_graph_sha256(raw)
    analysis = AnalysisProvenance(
        track=config.track,
        candidate_scope=selection.scope,
        backend=raw["analysis"]["backend"],
        extractor_version=raw["analysis"]["extractor_version"],
        raw_graph_sha256=raw_digest,
        candidate_selection_sha256=selection.sha256,
        projection_config_sha256=projection_config_sha256(config),
        anchor_policy=config.anchor_policy,
        edge_policy=config.edge_policy,
        oracle_level=config.oracle_level,
    )

    unresolved_by_source = Counter()
    for transfer in raw["transfers"]:
        if (
            transfer["status"] == "unresolved"
            and transfer["operand_kind"] in {"memory", "register"}
        ):
            unresolved_by_source[_address(transfer["source"])] += 1

    incoming_callers = {address: set() for address in graph}
    for source, targets in graph.items():
        for target in targets:
            incoming_callers[target].add(source)

    nodes = []
    for address in sorted(selected):
        node_id = function_id(address, id_bias=id_bias)
        is_root = address == root
        is_user = address in scored_users

        if is_user:
            anchor_kind = None
            color_class = None
            allowed_targets = selected
        else:
            anchor_kind = _anchor_kind(
                address,
                is_root=is_root,
                incoming_anchors=incoming_anchors,
                outgoing_anchors=outgoing_anchors,
            )
            color_class = _anchor_color_class(
                node_id,
                anchor_kind,
                config.anchor_policy,
            )
            if is_root or anchor_kind in {"incoming", "both"}:
                allowed_targets = candidates
            else:
                allowed_targets = set()

        calls = [
            {
                "target": function_id(target, id_bias=id_bias),
                "count": count,
            }
            for target, count in sorted(graph[address].items())
            if target in allowed_targets and count > 0
        ]
        nodes.append({
            "id": node_id,
            "type": "user" if is_user else "anchor",
            "scored": is_user,
            "anchor_kind": anchor_kind,
            "color_class": color_class,
            "observability": {
                "resolved_out_calls": sum(graph[address].values()),
                "unresolved_indirect_out_callsites": unresolved_by_source[address],
                "address_taken_references": None,
                "resolved_in_callers": len(incoming_callers[address]),
            },
            "calls": calls,
        })

    provenance = parse_provenance(raw["provenance"], where="raw graph.provenance")
    context_description = "candidates plus their resolved callees"
    if config.include_incoming_anchors:
        context_description += " and resolved external callers"
    return {
        "case": raw["case"],
        "build": raw["build"],
        "profile": raw["profile"],
        "schema_version": FIXTURE_SCHEMA_V5,
        "provenance": provenance.to_dict(),
        "analysis": analysis.to_dict(),
        "extraction": _projected_extraction(raw, selection),
        "note": (
            f"projected by graph_projector.py from {raw['binary']['path']}; "
            f"track={config.track}; candidate_scope={selection.scope}; "
            f"root={function_id(root, id_bias=id_bias)}; "
            f"users={users_path or 'none'}; {context_description} are emitted; "
            "anchors expose only edges "
            "into candidates; unresolved transfers remain analysis evidence and "
            "are not projected as call edges"
        ),
        "nodes": nodes,
    }


def project_direct_fixture(
    raw: dict[str, Any],
    *,
    selection: CandidateSelection,
    users_path: str | None,
    id_bias: int,
    score_root: bool = False,
) -> dict[str, Any]:
    """Project the frozen schema-v4 direct compatibility fixture."""
    validate_raw_graph(raw)
    _validate_selection_join(raw, selection)
    config = projection_config_for(DIRECT_TRACK)
    graph = resolved_graph(raw, config)
    root = _address(raw["root"])
    candidates = set(selection.addresses)
    unknown_candidates = candidates - set(graph)
    if unknown_candidates:
        rendered = ", ".join(f"0x{value:x}" for value in sorted(unknown_candidates))
        raise ValueError(f"candidate selection is absent from raw graph: {rendered}")

    # The shared raw graph contains symbol-oracle function starts unavailable to
    # the original direct extraction. Keep the frozen projection compatible:
    # candidate starts are always valid, while context anchors must still have
    # been discovered independently by radare2.
    r2_discovered = {
        _address(function["address"])
        for function in raw["functions"]
        if function["discovered_by_radare2"]
    }
    allowed_context_targets = candidates | r2_discovered
    graph = {
        source: Counter({
            target: count
            for target, count in targets.items()
            if target in allowed_context_targets
        })
        for source, targets in graph.items()
    }

    selected = {root} | candidates
    context_sources = set(candidates)
    if score_root:
        context_sources.add(root)
    for source in context_sources:
        selected.update(graph[source])
    selected &= set(graph)

    nodes = []
    for address in sorted(selected):
        is_root = address == root
        node_type = (
            "user"
            if address in candidates or (score_root and is_root)
            else "anchor"
        )
        if node_type == "user":
            allowed_targets = selected
        elif is_root:
            allowed_targets = candidates
        else:
            allowed_targets = set()
        calls = [
            {
                "target": function_id(target, id_bias=id_bias),
                "count": count,
            }
            for target, count in sorted(graph[address].items())
            if target in allowed_targets and count > 0
        ]
        nodes.append({
            "id": function_id(address, id_bias=id_bias),
            "type": node_type,
            "scored": node_type == "user",
            "calls": calls,
        })

    names = {
        _address(function["address"]): function["name"]
        for function in raw["functions"]
    }
    root_id = function_id(root, id_bias=id_bias)
    note = (
        f"generated by binary_extractor.py from {raw['binary']['path']}; "
        f"root={root_id}/{names[root]}; "
        f"users={users_path or 'none'}; "
        "listed user nodes are user/scored=true; "
        "user mode emits root plus listed users plus direct callees "
        "of listed users only; "
        "root anchor retains edges to listed users; "
        "non-root anchors are terminal/scored=false; "
        "std/runtime classification is out of this extractor's research scope; "
        "edges to non-emitted targets are omitted"
    )
    provenance = parse_provenance(raw["provenance"], where="raw graph.provenance")
    return {
        "case": raw["case"],
        "build": raw["build"],
        "profile": raw["profile"],
        "schema_version": 4,
        "provenance": provenance.to_dict(),
        "extraction": _projected_extraction(raw, selection),
        "note": note,
        "nodes": nodes,
    }


def project_fixture(
    raw: dict[str, Any],
    *,
    selection: CandidateSelection,
    track: str,
    users_path: str | None,
    id_bias: int,
    score_root: bool = False,
) -> dict[str, Any]:
    track = normalize_track(track)
    backend = raw["analysis"]["backend"]
    if track == ANGR_TRACK and backend != ANGR_RAW_GRAPH_BACKEND:
        raise ValueError(
            "the angr projection requires raw evidence augmented by angr"
        )
    if track != ANGR_TRACK and backend != RAW_GRAPH_BACKEND:
        raise ValueError(
            f"the {track} projection requires direct raw evidence"
        )
    if track == DIRECT_TRACK and selection.scope == SUBJECT_CANDIDATE_SCOPE:
        return project_direct_fixture(
            raw,
            selection=selection,
            users_path=users_path,
            id_bias=id_bias,
            score_root=score_root,
        )
    return project_context_fixture(
        raw,
        selection=selection,
        users_path=users_path,
        id_bias=id_bias,
        score_root=score_root,
        config=projection_config_for(track),
    )


def _validate_selection_join(
    raw: dict[str, Any],
    selection: CandidateSelection,
) -> None:
    identity = (raw["case"], raw["build"], raw["profile"])
    selected_identity = (
        selection.data["case"],
        selection.data["build"],
        selection.data["profile"],
    )
    if identity != selected_identity:
        raise ValueError(
            "raw graph/candidate selection identity mismatch: "
            f"raw={identity}, selection={selected_identity}"
        )
    provenance = parse_provenance(raw["provenance"], where="raw graph.provenance")
    if selection.provenance != provenance:
        raise ValueError("raw graph/candidate selection build provenance mismatch")


def _projected_extraction(
    raw: dict[str, Any],
    selection: CandidateSelection,
) -> dict[str, Any]:
    relevant_addresses = set(selection.function_bounds)
    return {
        "boundary_mode": raw["extraction"]["boundary_mode"],
        "boundary_mismatches": [
            mismatch
            for mismatch in raw["extraction"]["boundary_mismatches"]
            if _address(mismatch["address"]) in relevant_addresses
        ],
    }


def function_id(address: int, *, id_bias: int) -> str:
    return f"FUN_{address + id_bias:08x}"


def _anchor_kind(
    address: int,
    *,
    is_root: bool,
    incoming_anchors: set[int],
    outgoing_anchors: set[int],
) -> str:
    if is_root:
        return "root"
    incoming = address in incoming_anchors
    outgoing = address in outgoing_anchors
    if incoming and outgoing:
        return "both"
    if incoming:
        return "incoming"
    if outgoing:
        return "outgoing"
    raise ValueError(f"selected anchor 0x{address:x} has no role")


def _anchor_color_class(node_id: str, anchor_kind: str, policy: str) -> str:
    if policy == "address":
        return f"ADDR:{node_id}"
    if policy == "role":
        return f"ROLE:{anchor_kind}"
    raise ValueError(f"unsupported anchor policy: {policy}")


def _address(value: str) -> int:
    return int(value, 16)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Project a raw extraction graph into a CallKin fixture."
    )
    parser.add_argument("raw_graph", help="*.raw.json produced by binary_extractor.py")
    parser.add_argument("selection", help="candidate selection JSON, usually users/*.json")
    parser.add_argument("output", nargs="?", help="projected fixture JSON path")
    parser.add_argument(
        "--track",
        choices=ANALYSIS_TRACKS,
        default=DEFAULT_ANALYSIS_TRACK,
        help=f"projection track. Default: {DEFAULT_ANALYSIS_TRACK}",
    )
    parser.add_argument(
        "--id-bias",
        type=lambda value: int(value, 0),
        default=0x100000,
        help="value added when formatting FUN_ ids. Default: 0x100000",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        raw = load_raw_graph(args.raw_graph)
        track = normalize_track(args.track)
        selection = load_candidate_selection(
            args.selection,
            expected_case=raw["case"],
            expected_build=raw["build"],
            expected_profile=raw["profile"],
        )
        fixture = project_fixture(
            raw,
            selection=selection,
            track=track,
            users_path=args.selection,
            id_bias=args.id_bias,
        )
        output = args.output or fixture_json_for(
            raw["case"],
            raw["build"],
            raw["profile"],
            track,
            selection.scope,
        )
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {output}")
    print(f"nodes={len(fixture['nodes'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
