from __future__ import annotations

import importlib.metadata
import platform
import struct
import subprocess
from collections import Counter, deque
from pathlib import Path
from statistics import median
from typing import Any, Iterable

from candidate_selection import CandidateSelection
from graph_evidence import (
    ANGR_RESOLVER,
    ELF_RELOCATION_RESOLVER,
    indirect_call_summary,
    make_indirect_call_summary,
    validate_raw_graph,
)

try:
    import resource
except ImportError:  # pragma: no cover - Windows fallback
    resource = None


def build_run_summary(
    *,
    raw: dict[str, Any],
    fixture: dict[str, Any],
    ground_truth: dict[str, Any],
    selection: CandidateSelection,
    reports: Iterable[Any],
    execution: dict[str, Any],
    binary_path: str,
    id_bias: int,
) -> dict[str, Any]:
    validate_raw_graph(raw)
    reports = tuple(reports)
    gt_summary = ground_truth_summary(ground_truth)
    scored_same_family_pairs = _scored_same_family_pair_count(
        ground_truth,
        fixture,
    )
    for report in reports:
        if report.pairwise.tp + report.pairwise.fn != scored_same_family_pairs:
            raise ValueError(
                "ground-truth pair count does not match score TP+FN: "
                f"{scored_same_family_pairs} != "
                f"{report.pairwise.tp + report.pairwise.fn}"
            )
    all_indirect = indirect_call_summary(raw)
    exact_static_all = exact_static_indirect_summary(raw)
    abstained_count = len(fixture.get("abstentions", []))
    target_count = gt_summary["target_count"]
    gt_summary.update({
        "grouped_candidate_count": target_count - abstained_count,
        "abstained_candidate_count": abstained_count,
        "scored_same_family_pair_count": scored_same_family_pairs,
        "same_family_pair_coverage": (
            scored_same_family_pairs / gt_summary["same_family_pair_count"]
            if gt_summary["same_family_pair_count"] else None
        ),
    })

    return {
        "ground_truth": gt_summary,
        "extraction": {
            "exact_static_indirect_summary": {
                "all_sources": exact_static_all,
                "candidate_sources": exact_static_indirect_summary(
                    raw,
                    source_addresses=set(selection.addresses),
                ),
            },
            "indirect_call_summary": {
                "all_sources": all_indirect,
                "candidate_sources": make_indirect_call_summary(
                    raw["transfers"],
                    analysis_status=all_indirect["analysis_status"],
                    source_addresses=set(selection.addresses),
                ),
            },
        },
        "candidate_impact": candidate_impact(raw, selection),
        "candidate_observability": candidate_observability(
            raw,
            fixture,
            selection,
            id_bias=id_bias,
        ),
        "execution": execution,
        "artifact_summary": artifact_summary(
            raw,
            fixture,
            selection,
            binary_path=binary_path,
        ),
        "tool_versions": tool_versions(),
    }


def exact_static_indirect_summary(
    raw: dict[str, Any],
    *,
    source_addresses: set[int] | None = None,
) -> dict[str, Any]:
    """Summarize indirect transfers proven without angr inference."""
    resolvers = (ELF_RELOCATION_RESOLVER,)
    selected = [
        transfer
        for transfer in raw["transfers"]
        if transfer.get("resolver") in resolvers
        and transfer.get("operand_kind") in {"memory", "register"}
        and (
            source_addresses is None
            or _address(transfer["source"]) in source_addresses
        )
    ]
    return {
        "total": len(selected),
        "resolved_internal": sum(
            transfer["status"] == "resolved" for transfer in selected
        ),
        "filtered_import": sum(
            transfer["status"] == "filtered" for transfer in selected
        ),
        "unmapped": sum(
            transfer["status"] == "unmapped" for transfer in selected
        ),
        "by_resolver": {
            resolver: sum(
                transfer["resolver"] == resolver for transfer in selected
            )
            for resolver in resolvers
        },
    }


def candidate_impact(
    raw: dict[str, Any],
    selection: CandidateSelection,
) -> dict[str, int]:
    candidates = set(selection.addresses)
    accepted = [
        transfer
        for transfer in raw["transfers"]
        if transfer.get("angr_status") in {"accepted", "resolved_internal"}
        and transfer.get("resolver") == ANGR_RESOLVER
    ]
    accepted_edges = {
        (_address(transfer["source"]), _address(transfer["target"]))
        for transfer in accepted
    }
    outgoing_edges = {
        edge for edge in accepted_edges
        if edge[0] in candidates
    }
    incoming_edges = {
        edge for edge in accepted_edges
        if edge[1] in candidates
    }
    outgoing_candidates = {source for source, _target in outgoing_edges}
    incoming_candidates = {target for _source, target in incoming_edges}
    changed = outgoing_candidates | incoming_candidates
    outgoing_callsites = sum(
        _address(transfer["source"]) in candidates
        for transfer in accepted
    )
    incoming_callsites = sum(
        _address(transfer["target"]) in candidates
        for transfer in accepted
    )
    return {
        "resolved_internal_callsites_total": len(accepted),
        "resolved_internal_unique_edges_total": len(accepted_edges),
        "candidate_outgoing_edges_added": outgoing_callsites,
        "candidate_incoming_edges_added": incoming_callsites,
        "candidate_outgoing_unique_edges_added": len(outgoing_edges),
        "candidate_incoming_unique_edges_added": len(incoming_edges),
        "candidates_with_new_outgoing_evidence": len(outgoing_candidates),
        "candidates_with_new_incoming_evidence": len(incoming_candidates),
        "candidates_unchanged": len(candidates - changed),
    }


def candidate_observability(
    raw: dict[str, Any],
    fixture: dict[str, Any],
    selection: CandidateSelection,
    *,
    id_bias: int,
) -> dict[str, Any]:
    nodes = {node["id"]: node for node in fixture["nodes"]}
    candidate_ids = {
        _function_id(address, id_bias)
        for address in selection.addresses
    }
    abstained_ids = {
        item["id"]
        for item in fixture.get("abstentions", [])
    }
    missing = candidate_ids - set(nodes) - abstained_ids
    if missing:
        raise ValueError(f"candidate(s) absent from fixture: {sorted(missing)}")

    incoming = {node_id: set() for node_id in nodes}
    for source, node in nodes.items():
        for call in node["calls"]:
            incoming[call["target"]].add(source)

    root_id = _function_id(_address(raw["root"]), id_bias)
    reachable = _reachable_fixture_nodes(nodes, root_id)
    unresolved_sources = {
        _address(transfer["source"])
        for transfer in raw["transfers"]
        if transfer["status"] == "unresolved"
        and transfer["kind"] in {"call", "tail-call"}
        and transfer["operand_kind"] in {"memory", "register"}
    }
    zero_outgoing = {
        node_id for node_id in candidate_ids
        if node_id in abstained_ids
        or not nodes[node_id]["calls"]
    }
    zero_incoming = {
        node_id for node_id in candidate_ids
        if node_id in abstained_ids
        or not incoming[node_id]
    }
    excluded = selection.data.get("excluded_namespaces", [])
    analysis = fixture.get("analysis") or {}
    return {
        "target_count": len(candidate_ids),
        "grouped_candidate_count": len(candidate_ids - abstained_ids),
        "abstained_candidate_count": len(abstained_ids),
        "reachable_from_root": len(candidate_ids & reachable),
        "unreachable_from_root": len(candidate_ids - reachable),
        "zero_outgoing": len(zero_outgoing),
        "zero_incoming": len(zero_incoming),
        "fully_isolated": len(zero_outgoing & zero_incoming),
        "with_unresolved_indirect_calls": len(
            set(selection.addresses) & unresolved_sources
        ),
        "reachability_policy": {
            "edge_policy": list(analysis.get(
                "edge_policy",
                ["direct-immediate", "direct-tail"],
            )),
            "stop_namespaces": [],
            "candidate_excluded_namespaces": list(excluded),
            "anchor_traversal": "complete resolved outgoing closure",
        },
    }


def _scored_same_family_pair_count(
    ground_truth: dict[str, Any],
    fixture: dict[str, Any],
) -> int:
    abstained = {item["id"] for item in fixture.get("abstentions", [])}
    pair_count = 0
    for origin in ground_truth["origins"]:
        scored_count = sum(
            member not in abstained
            for member in origin["members"]
        )
        pair_count += scored_count * (scored_count - 1) // 2
    return pair_count


def ground_truth_summary(ground_truth: dict[str, Any]) -> dict[str, Any]:
    sizes = [len(origin["members"]) for origin in ground_truth["origins"]]
    family_sizes = [size for size in sizes if size >= 2]
    candidate_count = sum(sizes)
    true_pairs = sum(size * (size - 1) // 2 for size in sizes)
    return {
        "target_count": candidate_count,
        "origin_count": len(sizes),
        "generic_family_count": len(family_sizes),
        "singleton_origin_count": sum(size == 1 for size in sizes),
        "family_member_count": sum(family_sizes),
        "same_family_pair_count": true_pairs,
        "family_size": {
            "min": min(family_sizes) if family_sizes else None,
            "median": median(family_sizes) if family_sizes else None,
            "max": max(family_sizes) if family_sizes else None,
        },
        "cross_origin_alias_address_count": len(
            ground_truth.get("cross_origin_aliases", [])
        ),
    }


def compare_ground_truth_profiles(
    plain: dict[str, Any],
    minimum: dict[str, Any],
) -> dict[str, Any]:
    plain_origins = _origin_names(plain)
    min_origins = _origin_names(minimum)
    plain_families = _generic_origin_names(plain)
    min_families = _generic_origin_names(minimum)
    plain_instances = _instance_symbol_multiset(plain)
    min_instances = _instance_symbol_multiset(minimum)
    return {
        "candidate_origins": _set_comparison(plain_origins, min_origins),
        "generic_families": _set_comparison(plain_families, min_families),
        "monomorphized_instances": _multiset_comparison(
            plain_instances,
            min_instances,
        ),
    }


def artifact_summary(
    raw: dict[str, Any],
    fixture: dict[str, Any],
    selection: CandidateSelection,
    *,
    binary_path: str,
) -> dict[str, Any]:
    supplied = [
        function
        for function in raw["functions"]
        if function["boundary_source"] == "symbol-oracle"
    ]
    supplied_discovered = [
        function
        for function in supplied
        if function["discovered_by_radare2"]
    ]
    return {
        "binary_size_bytes": Path(binary_path).stat().st_size,
        "text_size_bytes": elf_text_size(binary_path),
        "known_function_count": len(raw["functions"]),
        "candidate_function_count": len(selection.addresses),
        "fixture_node_count": len(fixture["nodes"]),
        "abstention_count": len(fixture.get("abstentions", [])),
        "boundary_oracle": {
            "supplied_function_count": len(supplied),
            "radare2_discovered_count": len(supplied_discovered),
            "radare2_missing_count": sum(
                not function["discovered_by_radare2"]
                for function in supplied
            ),
            "size_mismatch_count": sum(
                mismatch["radare2_size"] > 0
                and mismatch["radare2_size"] != mismatch["symbol_size"]
                for mismatch in raw["extraction"]["boundary_mismatches"]
            ),
        },
    }


def execution_summary(
    *,
    duration_seconds: dict[str, float],
    warnings: list[dict[str, object]],
) -> dict[str, Any]:
    return {
        "status": "completed_with_warnings" if warnings else "completed",
        "duration_seconds": {
            key: round(value, 6)
            for key, value in duration_seconds.items()
        },
        "peak_rss_mb": peak_rss_mb(),
        "warnings": warnings,
    }


def peak_rss_mb() -> float | None:
    if resource is None:
        return None
    try:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (AttributeError, OSError):
        return None
    divisor = 1024 * 1024 if platform.system() == "Darwin" else 1024
    return round(value / divisor, 3)


def tool_versions() -> dict[str, str | None]:
    return {
        "python": platform.python_version(),
        "radare2": _command_version(("radare2", "-v")),
        "r2pipe": _package_version("r2pipe"),
        "capstone": _package_version("capstone"),
        "pyelftools": _package_version("pyelftools"),
        "angr": _package_version("angr"),
        "cle": _package_version("cle"),
        "pyvex": _package_version("pyvex"),
    }


def elf_text_size(path: str) -> int | None:
    data = Path(path).read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    elf_class = data[4]
    byte_order = "<" if data[5] == 1 else ">" if data[5] == 2 else None
    if byte_order is None:
        return None
    if elf_class == 2:
        shoff = struct.unpack_from(byte_order + "Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(byte_order + "HHH", data, 0x3A)
        offset_field, size_field, word = 0x18, 0x20, "Q"
    elif elf_class == 1:
        shoff = struct.unpack_from(byte_order + "I", data, 0x20)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(byte_order + "HHH", data, 0x2E)
        offset_field, size_field, word = 0x10, 0x14, "I"
    else:
        return None
    if not shoff or not shnum or shstrndx >= shnum:
        return None

    def section(index: int) -> tuple[int, int, int]:
        base = shoff + index * shentsize
        name_offset = struct.unpack_from(byte_order + "I", data, base)[0]
        offset = struct.unpack_from(byte_order + word, data, base + offset_field)[0]
        size = struct.unpack_from(byte_order + word, data, base + size_field)[0]
        return name_offset, offset, size

    _name, strings_offset, strings_size = section(shstrndx)
    strings = data[strings_offset:strings_offset + strings_size]
    for index in range(shnum):
        name_offset, _offset, size = section(index)
        end = strings.find(b"\0", name_offset)
        if end >= 0 and strings[name_offset:end] == b".text":
            return size
    return None


def _reachable_fixture_nodes(nodes: dict[str, dict], root_id: str) -> set[str]:
    if root_id not in nodes:
        return set()
    reached = {root_id}
    queue = deque([root_id])
    while queue:
        source = queue.popleft()
        for call in nodes[source]["calls"]:
            target = call["target"]
            if target not in reached:
                reached.add(target)
                queue.append(target)
    return reached


def _package_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def _command_version(command: tuple[str, ...]) -> str | None:
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    line = result.stdout.strip().splitlines()
    return line[0] if line else None


def _function_id(address: int, id_bias: int) -> str:
    return f"FUN_{address + id_bias:08x}"


def _address(value: str) -> int:
    return int(value, 16)


def _origin_names(gt: dict[str, Any]) -> set[str]:
    return {origin["origin"] for origin in gt["origins"]}


def _generic_origin_names(gt: dict[str, Any]) -> set[str]:
    return {
        origin["origin"]
        for origin in gt["origins"]
        if len(origin["members"]) >= 2
    }


def _instance_symbol_multiset(
    gt: dict[str, Any],
) -> Counter[tuple[str, tuple[str, ...]]]:
    origin_of = {
        member: origin["origin"]
        for origin in gt["origins"]
        for member in origin["members"]
    }
    return Counter(
        (origin_of[member], tuple(sorted(symbols)))
        for member, symbols in gt["symbols"].items()
    )


def _multiset_comparison(
    plain: Counter[tuple[str, tuple[str, ...]]],
    minimum: Counter[tuple[str, tuple[str, ...]]],
) -> dict[str, int]:
    common = plain & minimum
    return {
        "common_symbols": common.total(),
        "plain_only": (plain - minimum).total(),
        "min_only": (minimum - plain).total(),
    }


def _set_comparison(
    plain: set[str],
    minimum: set[str],
    *,
    common_key: str = "common",
) -> dict[str, int]:
    return {
        common_key: len(plain & minimum),
        "plain_only": len(plain - minimum),
        "min_only": len(minimum - plain),
    }
