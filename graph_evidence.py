from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from paths import normalize_profile
from provenance import BuildProvenance, parse_provenance


RAW_GRAPH_SCHEMA_VERSION = 5
SUPPORTED_RAW_GRAPH_SCHEMAS = {3, 5}
RAW_GRAPH_BACKEND = "radare2-capstone"
ANGR_RAW_GRAPH_BACKEND = "radare2-capstone+angr"
RAW_GRAPH_EXTRACTOR_VERSION = "call-evidence-v6"
ANGR_RESOLVER = "angr-cfg"
ELF_RELOCATION_RESOLVER = "elf-relocation"

TRANSFER_KINDS = {"call", "tail-call"}
TRANSFER_STATUSES = {"resolved", "unresolved", "unmapped", "filtered"}
TRANSFER_RESOLVERS = {
    "direct-immediate",
    "direct-tail",
    ELF_RELOCATION_RESOLVER,
    ANGR_RESOLVER,
}
TRANSFER_FILTER_REASONS = {"import"}
OPERAND_KINDS = {"immediate", "memory", "register", "unknown"}
BOUNDARY_SOURCES = {"radare2", "symbol-oracle"}
ANGR_STATUSES = {
    "not_applicable",
    "not_run",
    "accepted",
    "resolved_internal",
    "resolved_import",
    "unresolvable_target",
    "multiple_targets",
    "unknown_target",
    "ambiguous_source",
    "no_angr_result",
}
ANGR_REJECTION_REASONS = (
    "unresolvable_target",
    "multiple_targets",
    "unknown_target",
    "ambiguous_source",
    "no_angr_result",
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class TransferEvidence:
    source: int
    callsite: int
    instruction: str
    kind: str
    operand_kind: str
    status: str
    target: int | None
    resolver: str | None
    confidence: str
    filter_reason: str | None = None
    angr_status: str | None = None
    angr_targets: tuple[int, ...] = ()
    angr_target_names: tuple[tuple[int, str], ...] = ()

    def to_dict(self) -> dict[str, object]:
        angr_status = self.angr_status
        if angr_status is None:
            angr_status = (
                "not_run"
                if (
                    self.kind in TRANSFER_KINDS
                    and self.status == "unresolved"
                    and self.operand_kind in {"memory", "register"}
                )
                else "not_applicable"
            )
        return {
            "source": _hex(self.source),
            "callsite": _hex(self.callsite),
            "instruction": self.instruction,
            "kind": self.kind,
            "operand_kind": self.operand_kind,
            "status": self.status,
            "target": _hex(self.target) if self.target is not None else None,
            "resolver": self.resolver,
            "confidence": self.confidence,
            "filter_reason": self.filter_reason,
            "angr_status": angr_status,
            "angr_targets": [_hex(target) for target in self.angr_targets],
            "angr_target_names": {
                _hex(target): name
                for target, name in self.angr_target_names
            },
        }


def make_raw_graph(
    *,
    case: str,
    build: str,
    profile: str,
    binary_path: str,
    provenance: BuildProvenance,
    boundary_input_sha256: str,
    root_address: int,
    functions: list[dict[str, object]],
    transfers: list[TransferEvidence],
    boundary_mode: str,
    boundary_mismatches: list[dict[str, int | str]],
    backend: str = RAW_GRAPH_BACKEND,
    extractor_version: str = RAW_GRAPH_EXTRACTOR_VERSION,
) -> dict[str, Any]:
    transfer_dicts = [
        item.to_dict()
        for item in sorted(
            transfers,
            key=lambda item: (
                item.source,
                item.callsite,
                item.target if item.target is not None else -1,
            ),
        )
    ]
    raw = {
        "schema_version": RAW_GRAPH_SCHEMA_VERSION,
        "case": case,
        "build": build,
        "profile": profile,
        "provenance": provenance.to_dict(),
        "analysis": {
            "backend": backend,
            "extractor_version": extractor_version,
            "oracle_level": "symbol-boundary",
            "boundary_input_sha256": boundary_input_sha256,
        },
        "binary": {
            "path": binary_path,
            "stripped_sha256": provenance.stripped_sha256,
        },
        "root": _hex(root_address),
        "extraction": {
            "boundary_mode": boundary_mode,
            "boundary_mismatches": boundary_mismatches,
        },
        "indirect_call_summary": make_indirect_call_summary(
            transfer_dicts,
            analysis_status="not_run",
        ),
        "functions": functions,
        "transfers": transfer_dicts,
    }
    validate_raw_graph(raw)
    return raw


def raw_graph_bytes(raw: dict[str, Any]) -> bytes:
    validate_raw_graph(raw)
    return (json.dumps(raw, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def raw_graph_sha256(raw: dict[str, Any]) -> str:
    return hashlib.sha256(raw_graph_bytes(raw)).hexdigest()


def write_raw_graph(raw: dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw_graph_bytes(raw))


def load_raw_graph(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as file:
        raw = json.load(file)
    validate_raw_graph(raw)
    return raw


def validate_raw_graph(raw: Any) -> None:
    if not isinstance(raw, dict):
        raise ValueError("raw graph root must be an object")
    schema_version = raw.get("schema_version")
    if schema_version not in SUPPORTED_RAW_GRAPH_SCHEMAS:
        raise ValueError(f"unsupported raw graph schema: {schema_version!r}")
    required = {
        "schema_version", "case", "build", "profile", "provenance",
        "analysis", "binary", "root", "extraction",
        "functions", "transfers",
    }
    if schema_version >= 4:
        required.add("indirect_call_summary")
    if set(raw) != required:
        raise ValueError(f"raw graph must contain exactly {sorted(required)}")
    for key in ("case", "build"):
        _require_string(raw[key], f"raw graph.{key}")
    normalize_profile(raw["profile"])
    provenance = parse_provenance(raw["provenance"], where="raw graph.provenance")

    analysis = raw["analysis"]
    analysis_keys = {
        "backend", "extractor_version", "oracle_level", "boundary_input_sha256"
    }
    if not isinstance(analysis, dict) or set(analysis) != analysis_keys:
        raise ValueError(
            f"raw graph.analysis must contain exactly {sorted(analysis_keys)}"
        )
    for key in analysis_keys - {"boundary_input_sha256"}:
        _require_string(analysis[key], f"raw graph.analysis.{key}")
    if (
        not isinstance(analysis["boundary_input_sha256"], str)
        or not _SHA256_RE.fullmatch(analysis["boundary_input_sha256"])
    ):
        raise ValueError("raw graph.analysis.boundary_input_sha256 must be SHA-256")

    binary = raw["binary"]
    if not isinstance(binary, dict) or set(binary) != {"path", "stripped_sha256"}:
        raise ValueError("raw graph.binary must contain exactly path/stripped_sha256")
    _require_string(binary["path"], "raw graph.binary.path")
    if binary["stripped_sha256"] != provenance.stripped_sha256:
        raise ValueError("raw graph binary hash does not match build provenance")

    root = _parse_hex(raw["root"], "raw graph.root")
    _validate_extraction(raw["extraction"])

    functions = raw["functions"]
    if not isinstance(functions, list) or not functions:
        raise ValueError("raw graph.functions must be a non-empty list")
    function_addresses = set()
    function_sizes = {}
    function_sources = {}
    for index, function in enumerate(functions):
        where = f"raw graph.functions[{index}]"
        if not isinstance(function, dict) or set(function) != {
            "address", "name", "size", "boundary_source", "discovered_by_radare2",
        }:
            raise ValueError(
                f"{where} has an invalid field set"
            )
        address = _parse_hex(function["address"], f"{where}.address")
        if address in function_addresses:
            raise ValueError(f"duplicate raw graph function address: {_hex(address)}")
        function_addresses.add(address)
        _require_string(function["name"], f"{where}.name")
        size = function["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"{where}.size must be a non-negative integer")
        function_sizes[address] = size
        if function["boundary_source"] not in BOUNDARY_SOURCES:
            raise ValueError(f"invalid {where}.boundary_source")
        function_sources[address] = function["boundary_source"]
        if not isinstance(function["discovered_by_radare2"], bool):
            raise ValueError(f"{where}.discovered_by_radare2 must be boolean")

    if root not in function_addresses:
        raise ValueError("raw graph root is not a known function")
    _validate_transfers(
        raw["transfers"],
        function_addresses,
        function_sizes,
        function_sources,
        schema_version=schema_version,
    )
    if schema_version >= 4:
        _validate_indirect_call_summary(
            raw["indirect_call_summary"],
            raw["transfers"],
        )


def _validate_extraction(extraction: Any) -> None:
    if not isinstance(extraction, dict) or set(extraction) != {
        "boundary_mode", "boundary_mismatches",
    }:
        raise ValueError(
            "raw graph.extraction must contain boundary_mode/boundary_mismatches"
        )
    if extraction["boundary_mode"] not in {"radare2", "symbol-extent"}:
        raise ValueError("invalid raw graph extraction boundary_mode")
    mismatches = extraction["boundary_mismatches"]
    if not isinstance(mismatches, list):
        raise ValueError("raw graph boundary_mismatches must be a list")
    required = {"id", "address", "symbol_size", "radare2_size"}
    for index, mismatch in enumerate(mismatches):
        where = f"raw graph boundary_mismatches[{index}]"
        if not isinstance(mismatch, dict) or set(mismatch) != required:
            raise ValueError(f"{where} must contain exactly {sorted(required)}")
        _require_string(mismatch["id"], f"{where}.id")
        _parse_hex(mismatch["address"], f"{where}.address")
        for key in ("symbol_size", "radare2_size"):
            value = mismatch[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{where}.{key} must be a non-negative integer")


def _validate_transfers(
    transfers: Any,
    function_addresses: set[int],
    function_sizes: dict[int, int],
    function_sources: dict[int, str],
    *,
    schema_version: int,
) -> None:
    if not isinstance(transfers, list):
        raise ValueError("raw graph.transfers must be a list")
    required = {
        "source", "callsite", "instruction", "kind", "operand_kind",
        "status", "target", "resolver", "confidence", "filter_reason",
    }
    if schema_version >= 4:
        required |= {"angr_status", "angr_targets"}
    if schema_version >= 5:
        required.add("angr_target_names")
    seen_callsites = set()
    for index, transfer in enumerate(transfers):
        where = f"raw graph.transfers[{index}]"
        if not isinstance(transfer, dict) or set(transfer) != required:
            raise ValueError(f"{where} has an invalid field set")
        source = _parse_hex(transfer["source"], f"{where}.source")
        callsite = _parse_hex(transfer["callsite"], f"{where}.callsite")
        if source not in function_addresses:
            raise ValueError(f"{where}.source is not a known function")
        source_size = function_sizes[source]
        if (
            function_sources[source] == "symbol-oracle"
            and source_size > 0
            and not source <= callsite < source + source_size
        ):
            raise ValueError(
                f"{where}.callsite is outside its source function extent"
            )
        site_key = (source, callsite)
        if site_key in seen_callsites:
            raise ValueError(f"duplicate transfer callsite: {_hex(callsite)}")
        seen_callsites.add(site_key)
        _require_string(transfer["instruction"], f"{where}.instruction")
        if transfer["kind"] not in TRANSFER_KINDS:
            raise ValueError(f"invalid {where}.kind")
        if transfer["operand_kind"] not in OPERAND_KINDS:
            raise ValueError(f"invalid {where}.operand_kind")
        status = transfer["status"]
        if status not in TRANSFER_STATUSES:
            raise ValueError(f"invalid {where}.status")
        if status == "resolved":
            target = _parse_hex(transfer["target"], f"{where}.target")
            if target not in function_addresses:
                raise ValueError(f"{where}.target is not a known function")
            if transfer["resolver"] not in TRANSFER_RESOLVERS:
                raise ValueError(f"invalid {where}.resolver")
            expected_confidence = (
                "inferred"
                if transfer["resolver"] == ANGR_RESOLVER
                else "exact"
            )
            if transfer["confidence"] != expected_confidence:
                raise ValueError(
                    f"{where}.confidence must be {expected_confidence}"
                )
            if transfer["filter_reason"] is not None:
                raise ValueError(f"{where} resolved transfer cannot be filtered")
        elif status == "filtered":
            _parse_hex(transfer["target"], f"{where}.target")
            if transfer["resolver"] not in TRANSFER_RESOLVERS:
                raise ValueError(f"invalid {where}.resolver")
            expected_confidence = (
                "inferred"
                if transfer["resolver"] == ANGR_RESOLVER
                else "exact"
            )
            if transfer["confidence"] != expected_confidence:
                raise ValueError(
                    f"{where}.confidence must be {expected_confidence}"
                )
            if transfer["filter_reason"] not in TRANSFER_FILTER_REASONS:
                raise ValueError(f"invalid {where}.filter_reason")
        elif status == "unmapped":
            _parse_hex(transfer["target"], f"{where}.target")
            if transfer["resolver"] not in TRANSFER_RESOLVERS:
                raise ValueError(f"invalid {where}.resolver")
            if transfer["confidence"] != "exact":
                raise ValueError(f"{where}.confidence must be exact")
            if transfer["filter_reason"] is not None:
                raise ValueError(f"{where} unmapped transfer cannot be filtered")
        elif transfer["target"] is not None or transfer["resolver"] is not None:
            raise ValueError(f"{where} unresolved transfer cannot have target/resolver")
        elif transfer["filter_reason"] is not None:
            raise ValueError(f"{where} unresolved transfer cannot have filter_reason")
        elif transfer["confidence"] != "unknown":
            raise ValueError(f"{where}.confidence must be unknown")

        if schema_version >= 4:
            _validate_angr_evidence(transfer, where)


def make_indirect_call_summary(
    transfers: list[dict[str, Any]],
    *,
    analysis_status: str,
    source_addresses: set[int] | None = None,
) -> dict[str, Any]:
    if analysis_status not in {"not_run", "completed"}:
        raise ValueError(f"invalid indirect analysis status: {analysis_status!r}")
    indirect = [
        transfer
        for transfer in transfers
        if (
            transfer["kind"] in TRANSFER_KINDS
            and transfer["operand_kind"] in {"memory", "register"}
            and transfer.get("angr_status") != "not_applicable"
            and (
                source_addresses is None
                or _parse_hex(transfer["source"], "transfer.source")
                in source_addresses
            )
        )
    ]
    resolved_internal = sum(
        transfer.get("angr_status") in {"accepted", "resolved_internal"}
        for transfer in indirect
    )
    resolved_import = sum(
        transfer.get("angr_status") == "resolved_import"
        for transfer in indirect
    )
    by_operand = {}
    for operand in ("memory", "register"):
        selected = [
            transfer for transfer in indirect
            if transfer["operand_kind"] == operand
        ]
        by_operand[operand] = _indirect_counts(selected)
    rejected = {
        reason: sum(
            transfer.get("angr_status") == reason
            for transfer in indirect
        )
        for reason in ANGR_REJECTION_REASONS
    }
    total = len(indirect)
    unresolved = total - resolved_internal - resolved_import
    internal_denominator = total - resolved_import
    return {
        "analysis_status": analysis_status,
        "total": total,
        "resolved_internal": resolved_internal,
        "resolved_import": resolved_import,
        "unresolved": unresolved,
        "target_resolution_rate": (
            (resolved_internal + resolved_import) / total if total else 0.0
        ),
        "internal_resolution_rate": (
            resolved_internal / internal_denominator
            if internal_denominator else 0.0
        ),
        "by_operand": by_operand,
        "rejected": rejected,
    }


def _indirect_counts(transfers: list[dict[str, Any]]) -> dict[str, int]:
    resolved_internal = sum(
        transfer.get("angr_status") in {"accepted", "resolved_internal"}
        for transfer in transfers
    )
    resolved_import = sum(
        transfer.get("angr_status") == "resolved_import"
        for transfer in transfers
    )
    return {
        "total": len(transfers),
        "resolved_internal": resolved_internal,
        "resolved_import": resolved_import,
        "unresolved": len(transfers) - resolved_internal - resolved_import,
    }


def indirect_call_summary(raw: dict[str, Any]) -> dict[str, Any]:
    """Return stored diagnostics, or derive a not-run summary for schema v3."""
    validate_raw_graph(raw)
    if raw["schema_version"] >= 4:
        return raw["indirect_call_summary"]
    return make_indirect_call_summary(
        raw["transfers"],
        analysis_status="not_run",
    )


def _validate_angr_evidence(transfer: dict[str, Any], where: str) -> None:
    angr_status = transfer["angr_status"]
    if angr_status not in ANGR_STATUSES:
        raise ValueError(f"invalid {where}.angr_status")
    targets = _parse_unique_hex_list(
        transfer["angr_targets"],
        f"{where}.angr_targets",
    )
    target_names = _parse_target_names(
        transfer.get("angr_target_names", {}),
        f"{where}.angr_target_names",
    )
    if set(target_names) - targets:
        raise ValueError(f"{where}.angr_target_names contains an unknown target")
    if angr_status in {"accepted", "resolved_internal"}:
        if (
            transfer["status"] != "resolved"
            or transfer["resolver"] != ANGR_RESOLVER
            or len(targets) != 1
            or _parse_hex(transfer["target"], f"{where}.target") not in targets
        ):
            raise ValueError(f"{where} has inconsistent accepted angr evidence")
    elif angr_status == "resolved_import":
        if (
            transfer["status"] != "filtered"
            or transfer["resolver"] != ANGR_RESOLVER
            or transfer["filter_reason"] != "import"
            or transfer["confidence"] != "inferred"
            or len(targets) != 1
            or _parse_hex(transfer["target"], f"{where}.target") not in targets
            or set(target_names) != targets
        ):
            raise ValueError(f"{where} has inconsistent resolved import evidence")
    elif angr_status == "multiple_targets":
        if transfer["status"] != "unresolved" or len(targets) < 2:
            raise ValueError(f"{where} multiple_targets requires two or more targets")
    elif angr_status in {"unknown_target", "unresolvable_target"}:
        if transfer["status"] != "unresolved" or len(targets) != 1:
            raise ValueError(f"{where} {angr_status} requires one target")
    elif angr_status in {"ambiguous_source", "no_angr_result", "not_run"}:
        if transfer["status"] != "unresolved" or targets:
            raise ValueError(f"{where} {angr_status} cannot contain targets")
    elif targets:
        raise ValueError(f"{where} not_applicable cannot contain targets")


def _validate_indirect_call_summary(
    summary: Any,
    transfers: list[dict[str, Any]],
) -> None:
    if not isinstance(summary, dict):
        raise ValueError("raw graph.indirect_call_summary must be an object")
    status = summary.get("analysis_status")
    expected = make_indirect_call_summary(transfers, analysis_status=status)
    if summary != expected:
        raise ValueError("raw graph.indirect_call_summary does not match transfers")
    indirect_statuses = {
        transfer["angr_status"]
        for transfer in transfers
        if (
            transfer["kind"] in TRANSFER_KINDS
            and transfer["operand_kind"] in {"memory", "register"}
            and transfer["angr_status"] != "not_applicable"
        )
    }
    if status == "not_run" and indirect_statuses - {"not_run"}:
        raise ValueError("not-run indirect summary contains angr decisions")
    if status == "completed" and "not_run" in indirect_statuses:
        raise ValueError("completed indirect summary contains unanalyzed callsites")


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _parse_hex(value: Any, where: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(
            f"{where} must be a hexadecimal address string, got {value!r}"
        )
    try:
        return int(value, 16)
    except ValueError as exc:
        raise ValueError(
            f"{where} must be a hexadecimal address string, got {value!r}"
        ) from exc


def _parse_unique_hex_list(value: Any, where: str) -> set[int]:
    if not isinstance(value, list):
        raise ValueError(f"{where} must be a list")
    parsed = {_parse_hex(item, f"{where}[]") for item in value}
    if len(parsed) != len(value):
        raise ValueError(f"{where} contains duplicate addresses")
    return parsed


def _parse_target_names(value: Any, where: str) -> dict[int, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    parsed = {}
    for address, name in value.items():
        target = _parse_hex(address, f"{where}.key")
        _require_string(name, f"{where}[{address!r}]")
        parsed[target] = name
    return parsed


def _require_string(value: Any, where: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where} must be a non-empty string")
