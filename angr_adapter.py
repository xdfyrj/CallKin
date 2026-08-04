from __future__ import annotations

import copy
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from graph_evidence import (
    ANGR_RAW_GRAPH_BACKEND,
    ANGR_RESOLVER,
    RAW_GRAPH_EXTRACTOR_VERSION,
    validate_raw_graph,
)


@dataclass(frozen=True)
class AngrCallResolution:
    source: int
    callsite: int
    targets: tuple[int, ...]


def augment_raw_graph_with_angr(
    raw: dict[str, Any],
    *,
    binary_path: str,
) -> dict[str, Any]:
    """Resolve singleton indirect calls with angr and return a new raw graph."""
    resolutions, angr_version = analyze_indirect_calls(binary_path, raw)
    return merge_angr_resolutions(
        raw,
        resolutions,
        angr_version=angr_version,
    )


def analyze_indirect_calls(
    binary_path: str,
    raw: dict[str, Any],
) -> tuple[tuple[AngrCallResolution, ...], str]:
    validate_raw_graph(raw)
    try:
        import angr
    except ImportError as exc:
        raise RuntimeError(
            "the angr track requires the angr package. Install dependencies "
            "with `python3 -m pip install -r requirements.txt`."
        ) from exc

    project = angr.Project(binary_path, auto_load_libs=False)
    main_object = project.loader.main_object
    load_bias = main_object.mapped_base - main_object.linked_base
    known_functions = {
        _address(function["address"])
        for function in raw["functions"]
    }
    function_starts = [
        address + load_bias
        for address in sorted(known_functions)
        if main_object.min_addr <= address + load_bias <= main_object.max_addr
    ]

    cfg = project.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        function_starts=function_starts,
        force_complete_scan=False,
    )

    source_by_callsite: dict[int, set[int]] = defaultdict(set)
    for transfer in raw["transfers"]:
        source_by_callsite[_address(transfer["callsite"])].add(
            _address(transfer["source"])
        )

    targets_by_site: dict[tuple[int, int], set[int]] = defaultdict(set)

    # A resolver-success call may disappear from cfg.indirect_jumps and remain
    # only as a normal Ijk_Call edge in the recovered CFG. Join those edges by
    # the original machine-instruction address recorded in the raw graph.
    for source_node, target_node, edge in cfg.graph.edges(data=True):
        if edge.get("jumpkind") != "Ijk_Call":
            continue
        ins_addr = edge.get("ins_addr")
        target_addr = getattr(target_node, "addr", None)
        if not isinstance(ins_addr, int) or not isinstance(target_addr, int):
            continue
        callsite = ins_addr - load_bias
        sources = source_by_callsite.get(callsite, set())
        if len(sources) != 1:
            continue
        source = next(iter(sources))
        targets_by_site[(source, callsite)].add(target_addr - load_bias)

    for jump in cfg.indirect_jumps.values():
        if jump.jumpkind != "Ijk_Call" or not isinstance(jump.ins_addr, int):
            continue
        callsite = jump.ins_addr - load_bias
        sources = source_by_callsite.get(callsite, set())
        if len(sources) == 1:
            source = next(iter(sources))
        else:
            if not isinstance(jump.func_addr, int):
                continue
            source = jump.func_addr - load_bias
            if source not in known_functions:
                continue

        # Preserve the complete angr target set here. Filtering to known
        # function starts before checking cardinality would turn
        # {known_target, unknown_target} into a false singleton.
        targets = {
            target - load_bias
            for target in (jump.resolved_targets or ())
            if isinstance(target, int)
        }
        targets_by_site[(source, callsite)].update(targets)

    resolutions = tuple(
        AngrCallResolution(
            source=source,
            callsite=callsite,
            targets=tuple(sorted(targets)),
        )
        for (source, callsite), targets in sorted(targets_by_site.items())
        if targets
    )
    return resolutions, str(getattr(angr, "__version__", "unknown"))


def merge_angr_resolutions(
    raw: dict[str, Any],
    resolutions: Iterable[AngrCallResolution],
    *,
    angr_version: str,
) -> dict[str, Any]:
    """Replace only unresolved callsites with singleton angr targets."""
    validate_raw_graph(raw)
    merged = copy.deepcopy(raw)
    known_functions = {
        _address(function["address"])
        for function in merged["functions"]
    }
    transfer_index = {
        (_address(transfer["source"]), _address(transfer["callsite"])): index
        for index, transfer in enumerate(merged["transfers"])
    }

    targets_by_site: dict[tuple[int, int], set[int]] = defaultdict(set)
    for resolution in resolutions:
        targets_by_site[(resolution.source, resolution.callsite)].update(
            resolution.targets
        )

    for key, targets in targets_by_site.items():
        if len(targets) != 1 or key not in transfer_index:
            continue
        target = next(iter(targets))
        if target not in known_functions:
            continue
        transfer = merged["transfers"][transfer_index[key]]
        if transfer["status"] != "unresolved" or transfer["kind"] != "call":
            continue
        transfer["status"] = "resolved"
        transfer["target"] = f"0x{target:x}"
        transfer["resolver"] = ANGR_RESOLVER
        transfer["confidence"] = "inferred"
        transfer["filter_reason"] = None

    merged["analysis"]["backend"] = ANGR_RAW_GRAPH_BACKEND
    merged["analysis"]["extractor_version"] = (
        f"{RAW_GRAPH_EXTRACTOR_VERSION}+angr-{angr_version}"
    )
    validate_raw_graph(merged)
    return merged


def _address(value: str) -> int:
    return int(value, 16)
