from __future__ import annotations

import copy
import logging
import re
import time
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from graph_evidence import (
    ANGR_RAW_GRAPH_BACKEND,
    ANGR_RESOLVER,
    RAW_GRAPH_BACKEND,
    make_indirect_call_summary,
    validate_raw_graph,
)


@dataclass(frozen=True)
class AngrTargetMetadata:
    address: int
    category: str
    name: str | None = None


@dataclass(frozen=True)
class AngrCallResolution:
    source: int
    callsite: int
    targets: tuple[int, ...]
    ambiguous_source: bool = False
    target_metadata: tuple[AngrTargetMetadata, ...] = ()


@dataclass(frozen=True)
class AngrAnalysisResult:
    resolutions: tuple[AngrCallResolution, ...]
    angr_version: str
    duration_seconds: float
    warnings: tuple[dict[str, object], ...]


def augment_raw_graph_with_angr(
    raw: dict[str, Any],
    *,
    binary_path: str,
    runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve singleton indirect calls/tail-calls and return a new raw graph."""
    result = analyze_indirect_calls_detailed(binary_path, raw)
    if runtime is not None:
        runtime["duration_seconds"] = result.duration_seconds
        runtime["warnings"] = list(result.warnings)
        runtime["angr_version"] = result.angr_version
    return merge_angr_resolutions(
        raw,
        result.resolutions,
        angr_version=result.angr_version,
    )


def analyze_indirect_calls(
    binary_path: str,
    raw: dict[str, Any],
) -> tuple[tuple[AngrCallResolution, ...], str]:
    """Compatibility wrapper returning the recovered target sets and version."""
    result = analyze_indirect_calls_detailed(binary_path, raw)
    return result.resolutions, result.angr_version


def analyze_indirect_calls_detailed(
    binary_path: str,
    raw: dict[str, Any],
) -> AngrAnalysisResult:
    validate_raw_graph(raw)
    try:
        import angr
    except ImportError as exc:
        raise RuntimeError(
            "the angr track requires the angr package. Install dependencies "
            "with `python3 -m pip install -r requirements.txt`."
        ) from exc

    started = time.perf_counter()
    warning_counts: Counter[tuple[str, str]] = Counter()
    handler = _WarningHandler(warning_counts)
    root_logger = logging.getLogger()
    original_showwarning = warnings.showwarning

    def capture_warning(message, category, filename, lineno, file=None, line=None):
        component = f"python.{category.__name__}"
        warning_counts[(component, _normalize_warning(str(message)))] += 1
        original_showwarning(message, category, filename, lineno, file=file, line=line)

    root_logger.addHandler(handler)
    warnings.showwarning = capture_warning
    try:
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
        transfer_kind: dict[tuple[int, int], str] = {}
        unresolved_sites = []
        for transfer in raw["transfers"]:
            if not (
                transfer["status"] == "unresolved"
                and transfer["kind"] in {"call", "tail-call"}
                and transfer["operand_kind"] in {"memory", "register"}
            ):
                continue
            source = _address(transfer["source"])
            callsite = _address(transfer["callsite"])
            source_by_callsite[callsite].add(source)
            transfer_kind[(source, callsite)] = transfer["kind"]
            unresolved_sites.append((source, callsite))

        targets_by_site: dict[tuple[int, int], set[int]] = defaultdict(set)
        metadata_by_site: dict[
            tuple[int, int], dict[int, AngrTargetMetadata]
        ] = defaultdict(dict)
        ambiguous_callsites: set[int] = set()

        # A resolved transfer may disappear from cfg.indirect_jumps and remain
        # only as a normal CFG edge. Join it by the original instruction address.
        for _source_node, target_node, edge in cfg.graph.edges(data=True):
            ins_addr = edge.get("ins_addr")
            target_addr = getattr(target_node, "addr", None)
            if not isinstance(ins_addr, int) or not isinstance(target_addr, int):
                continue
            callsite = ins_addr - load_bias
            sources = source_by_callsite.get(callsite, set())
            if not sources:
                continue
            if len(sources) != 1:
                ambiguous_callsites.add(callsite)
                continue
            source = next(iter(sources))
            expected_jumpkind = (
                "Ijk_Call"
                if transfer_kind[(source, callsite)] == "call"
                else "Ijk_Boring"
            )
            if edge.get("jumpkind") != expected_jumpkind:
                continue
            target = target_addr - load_bias
            targets_by_site[(source, callsite)].add(target)
            metadata_by_site[(source, callsite)][target] = _target_metadata(
                project,
                cfg,
                mapped_address=target_addr,
                linked_address=target,
                known_functions=known_functions,
            )

        for jump in cfg.indirect_jumps.values():
            if not isinstance(jump.ins_addr, int):
                continue
            callsite = jump.ins_addr - load_bias
            sources = source_by_callsite.get(callsite, set())
            if not sources:
                continue
            if len(sources) != 1:
                ambiguous_callsites.add(callsite)
                continue
            source = next(iter(sources))
            expected_jumpkind = (
                "Ijk_Call"
                if transfer_kind[(source, callsite)] == "call"
                else "Ijk_Boring"
            )
            if jump.jumpkind != expected_jumpkind:
                continue

            # Preserve the complete angr target set here. Filtering to known
            # function starts before checking cardinality would turn
            # {known_target, unknown_target} into a false singleton.
            for mapped_target in jump.resolved_targets or ():
                if not isinstance(mapped_target, int):
                    continue
                target = mapped_target - load_bias
                targets_by_site[(source, callsite)].add(target)
                metadata_by_site[(source, callsite)][target] = _target_metadata(
                    project,
                    cfg,
                    mapped_address=mapped_target,
                    linked_address=target,
                    known_functions=known_functions,
                )

        resolutions = tuple(
            AngrCallResolution(
                source=source,
                callsite=callsite,
                targets=tuple(sorted(targets_by_site.get((source, callsite), set()))),
                ambiguous_source=callsite in ambiguous_callsites,
                target_metadata=tuple(
                    metadata_by_site.get((source, callsite), {}).get(
                        target,
                        AngrTargetMetadata(target, "unknown"),
                    )
                    for target in sorted(
                        targets_by_site.get((source, callsite), set())
                    )
                ),
            )
            for source, callsite in sorted(unresolved_sites)
        )
    finally:
        warnings.showwarning = original_showwarning
        root_logger.removeHandler(handler)

    return AngrAnalysisResult(
        resolutions=resolutions,
        angr_version=str(getattr(angr, "__version__", "unknown")),
        duration_seconds=time.perf_counter() - started,
        warnings=tuple(
            {
                "component": component,
                "message": message,
                "count": count,
            }
            for (component, message), count in sorted(warning_counts.items())
        ),
    )


def merge_angr_resolutions(
    raw: dict[str, Any],
    resolutions: Iterable[AngrCallResolution],
    *,
    angr_version: str,
) -> dict[str, Any]:
    """Replace only unresolved transfer sites with singleton angr targets."""
    validate_raw_graph(raw)
    if raw["schema_version"] < 5:
        raise ValueError("angr diagnostics require raw graph schema v5")
    if raw["analysis"]["backend"] != RAW_GRAPH_BACKEND:
        raise ValueError(
            "angr augmentation requires a radare2-capstone base raw graph"
        )
    base_version = raw["analysis"]["extractor_version"]
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
    metadata_by_site: dict[
        tuple[int, int], dict[int, AngrTargetMetadata]
    ] = defaultdict(dict)
    ambiguous_sites: set[tuple[int, int]] = set()
    for resolution in resolutions:
        key = (resolution.source, resolution.callsite)
        targets_by_site[key].update(
            resolution.targets
        )
        for metadata in resolution.target_metadata:
            if metadata.address not in resolution.targets:
                raise ValueError(
                    "angr target metadata address is absent from target set"
                )
            metadata_by_site[key][metadata.address] = metadata
        if resolution.ambiguous_source:
            ambiguous_sites.add(key)

    for key, index in transfer_index.items():
        transfer = merged["transfers"][index]
        if transfer.get("angr_status") != "not_run":
            continue
        targets = targets_by_site.get(key, set())
        transfer["angr_targets"] = [f"0x{target:x}" for target in sorted(targets)]
        transfer["angr_target_names"] = {
            f"0x{target:x}": metadata.name
            for target, metadata in sorted(metadata_by_site.get(key, {}).items())
            if metadata.name
        }
        if key in ambiguous_sites:
            transfer["angr_status"] = "ambiguous_source"
            transfer["angr_targets"] = []
            transfer["angr_target_names"] = {}
            continue
        if not targets:
            transfer["angr_status"] = "no_angr_result"
            continue
        if len(targets) > 1:
            transfer["angr_status"] = "multiple_targets"
            continue
        target = next(iter(targets))
        metadata = metadata_by_site.get(key, {}).get(
            target,
            AngrTargetMetadata(target, "unknown"),
        )
        if target in known_functions:
            transfer["angr_status"] = "resolved_internal"
            transfer["status"] = "resolved"
            transfer["target"] = f"0x{target:x}"
            transfer["resolver"] = ANGR_RESOLVER
            transfer["confidence"] = "inferred"
            transfer["filter_reason"] = None
            continue
        if metadata.category == "import" and metadata.name:
            transfer["angr_status"] = "resolved_import"
            transfer["status"] = "filtered"
            transfer["target"] = f"0x{target:x}"
            transfer["resolver"] = ANGR_RESOLVER
            transfer["confidence"] = "inferred"
            transfer["filter_reason"] = "import"
            continue
        if metadata.category == "unresolvable":
            transfer["angr_status"] = "unresolvable_target"
            continue
        transfer["angr_status"] = "unknown_target"

    merged["analysis"]["backend"] = ANGR_RAW_GRAPH_BACKEND
    merged["analysis"]["extractor_version"] = (
        f"{base_version}+angr-{angr_version}"
    )
    merged["indirect_call_summary"] = make_indirect_call_summary(
        merged["transfers"],
        analysis_status="completed",
    )
    validate_raw_graph(merged)
    return merged


def _target_metadata(
    project: Any,
    cfg: Any,
    *,
    mapped_address: int,
    linked_address: int,
    known_functions: set[int],
) -> AngrTargetMetadata:
    if linked_address in known_functions:
        return AngrTargetMetadata(linked_address, "internal")

    names = []
    is_hooked = bool(project.is_hooked(mapped_address))
    if is_hooked:
        procedure = project.hooked_by(mapped_address)
        names.extend((
            getattr(procedure, "display_name", None),
            procedure.__class__.__name__,
        ))

    function = cfg.kb.functions.get(mapped_address)
    if function is not None:
        names.append(getattr(function, "name", None))

    symbol = project.loader.find_symbol(mapped_address)
    if symbol is not None:
        names.append(getattr(symbol, "name", None))

    name = next(
        (
            str(candidate)
            for candidate in names
            if candidate and str(candidate) not in {"SimProcedure", "None"}
        ),
        None,
    )
    if name and any(
        marker in name
        for marker in ("UnresolvableCallTarget", "UnresolvableJumpTarget")
    ):
        return AngrTargetMetadata(linked_address, "unresolvable", name)

    main_object = project.loader.main_object
    outside_main_object = not main_object.contains_addr(mapped_address)
    if name and (is_hooked or outside_main_object):
        return AngrTargetMetadata(linked_address, "import", name)

    return AngrTargetMetadata(linked_address, "unknown", name)


class _WarningHandler(logging.Handler):
    def __init__(self, counts: Counter[tuple[str, str]]) -> None:
        super().__init__(level=logging.WARNING)
        self.counts = counts

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno < logging.WARNING:
            return
        self.counts[(record.name, _normalize_warning(record.getMessage()))] += 1


def _normalize_warning(message: str) -> str:
    message = re.sub(r"0x[0-9a-fA-F]+", "0x<addr>", message)
    return " ".join(message.split())


def _address(value: str) -> int:
    return int(value, 16)
