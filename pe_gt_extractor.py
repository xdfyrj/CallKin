"""Build evaluator-only ground truth artifacts from a stripped PE and its PDB.

This is intentionally separate from ``run_case.py``.  It does not extract a
call graph and it never gives PDB names to the anonymous GT artifact.  The
PDB-derived ``functions.json`` is the evaluator catalog; ``gt_groups.json``
contains only RVA-based function IDs and anonymous group IDs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gt_extractor import normalize_all_rust_origin, origin_from_symbol
from paths import (
    CANDIDATE_SCOPES,
    DEFAULT_CANDIDATE_SCOPE,
    RUST_NONSTD_CANDIDATE_SCOPE,
    SUBJECT_CANDIDATE_SCOPE,
    normalize_candidate_scope,
)


PE32_PLUS = 0x20B
AMD64 = 0x8664
EXECUTE_CHARACTERISTIC = 0x20000000

_PROC_HEADER = re.compile(
    r"^\s*\d+\s+\|\s+S_[GL]PROC32(?:_(?:ID|ST|DPC|DPC_ID))?"
    r"\s+\[size\s*=\s*\d+\]\s+`(?P<name>.*)`\s*$"
)
_PROC_ADDRESS = re.compile(
    r"addr\s*=\s*(?P<section>[0-9]+):(?P<offset>[0-9]+)"
    r"\s*,\s*code size\s*=\s*(?P<size>\d+)"
)
_PDB_AGE = re.compile(r"^\s*Age:\s*(?P<age>\d+)\s*$", re.IGNORECASE)
_PDB_GUID = re.compile(
    r"^\s*GUID:\s*\{(?P<guid>[0-9A-Fa-f-]+)\}\s*$", re.IGNORECASE
)


@dataclass(frozen=True)
class PdbProcedure:
    name: str
    section: int
    offset: int
    size: int


@dataclass
class FunctionRecord:
    rva: int
    size: int
    names: set[str]
    origin: str | None
    selected: bool
    is_root: bool = False

    @property
    def member_id(self) -> str:
        return f"FUN_{self.rva:08x}"

    @property
    def role(self) -> str:
        if self.is_root:
            return "root"
        return "target" if self.selected else "context"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_llvm_pdb_symbols(
    text: str,
    section_rvas: dict[int, int],
) -> list[PdbProcedure]:
    """Parse procedure records emitted by ``llvm-pdbutil dump -symbols``."""
    procedures: list[PdbProcedure] = []
    pending_name: str | None = None

    for line in text.splitlines():
        header = _PROC_HEADER.match(line)
        if header:
            pending_name = header.group("name")
            continue

        if pending_name is None:
            continue
        address = _PROC_ADDRESS.search(line)
        if address is None:
            continue

        # llvm-pdbutil prints CodeView segment and offset fields in decimal.
        section = int(address.group("section"), 10)
        offset = int(address.group("offset"), 10)
        size = int(address.group("size"), 10)
        if section in section_rvas:
            procedures.append(
                PdbProcedure(
                    name=pending_name,
                    section=section,
                    offset=offset,
                    size=size,
                )
            )
        pending_name = None

    return procedures


def _read_codeview_records(binary: Path, pe: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with binary.open("rb") as stream:
        for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            if int(entry.struct.Type) != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                continue
            offset = int(entry.struct.PointerToRawData)
            size = int(entry.struct.SizeOfData)
            stream.seek(offset)
            data = stream.read(size)
            if len(data) < 24 or data[:4] != b"RSDS":
                continue
            guid = str(uuid.UUID(bytes_le=data[4:20])).lower()
            age = struct.unpack_from("<I", data, 20)[0]
            pdb_path = data[24:].split(b"\0", 1)[0].decode(
                "utf-8", errors="replace"
            )
            records.append({"guid": guid, "age": age, "pdb_path": pdb_path})
    return records


def load_pe_layout(binary: Path) -> tuple[dict[int, int], list[tuple[int, int]], dict[str, Any]]:
    try:
        import pefile
    except ImportError as exc:
        raise RuntimeError("PE GT extraction requires the 'pefile' package") from exc

    pe = pefile.PE(str(binary), fast_load=False)
    try:
        if pe.FILE_HEADER.Machine != AMD64:
            raise ValueError("expected PE32+ x86-64 (IMAGE_FILE_MACHINE_AMD64)")
        if pe.OPTIONAL_HEADER.Magic != PE32_PLUS:
            raise ValueError("expected PE32+ optional header")

        section_rvas: dict[int, int] = {}
        executable_ranges: list[tuple[int, int]] = []
        section_layout: list[dict[str, Any]] = []
        text_sha256 = None
        for index, section in enumerate(pe.sections, start=1):
            start = int(section.VirtualAddress)
            length = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            end = start + length
            section_rvas[index] = start
            name = section.Name.rstrip(b"\0").decode("ascii", errors="replace")
            section_layout.append({
                "name": name,
                "rva": start,
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
            })
            if name == ".text":
                text_sha256 = hashlib.sha256(section.get_data()).hexdigest()
            if section.Characteristics & EXECUTE_CHARACTERISTIC:
                executable_ranges.append((start, end))

        debug = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            debug.append({
                "type": int(entry.struct.Type),
                "timestamp": int(entry.struct.TimeDateStamp),
                "size": int(entry.struct.SizeOfData),
            })

        metadata = {
            "format": "PE32+",
            "machine": "x86-64",
            "image_base": f"0x{int(pe.OPTIONAL_HEADER.ImageBase):x}",
            "entrypoint_rva": f"0x{int(pe.OPTIONAL_HEADER.AddressOfEntryPoint):x}",
            "sections": len(pe.sections),
            "section_layout": section_layout,
            "text_sha256": text_sha256,
            "codeview": _read_codeview_records(binary, pe),
            "debug_directories": debug,
        }
        return section_rvas, executable_ranges, metadata
    finally:
        pe.close()


def verify_pe_pair(linked_meta: dict[str, Any], stripped_meta: dict[str, Any]) -> None:
    """Ensure the PDB-side linked PE and analyst-side stripped PE align."""
    for key in ("format", "machine", "text_sha256"):
        if linked_meta.get(key) != stripped_meta.get(key):
            raise ValueError(
                f"linked/stripped PE mismatch for {key}: "
                f"{linked_meta.get(key)!r} != {stripped_meta.get(key)!r}"
            )
    linked_sections = [
        (item["name"], item["rva"], item["virtual_size"])
        for item in linked_meta.get("section_layout", [])
    ]
    stripped_sections = [
        (item["name"], item["rva"], item["virtual_size"])
        for item in stripped_meta.get("section_layout", [])
    ]
    if linked_sections != stripped_sections:
        raise ValueError(
            "linked/stripped PE mismatch for section names, RVAs, or virtual sizes"
        )


def parse_pdb_summary(text: str) -> dict[str, Any]:
    age = None
    guid = None
    for line in text.splitlines():
        age_match = _PDB_AGE.match(line)
        if age_match:
            age = int(age_match.group("age"))
        guid_match = _PDB_GUID.match(line)
        if guid_match:
            guid = str(uuid.UUID(guid_match.group("guid"))).lower()
    if age is None or guid is None:
        raise ValueError("llvm-pdbutil summary did not contain PDB GUID and Age")
    return {"guid": guid, "age": age}


def verify_codeview_identity(
    linked_meta: dict[str, Any],
    pdb_identity: dict[str, Any],
) -> dict[str, Any]:
    matches = [
        record
        for record in linked_meta.get("codeview", [])
        if record.get("guid") == pdb_identity.get("guid")
        and record.get("age") == pdb_identity.get("age")
    ]
    if not matches:
        raise ValueError(
            "linked PE CodeView GUID/Age does not match the supplied PDB: "
            f"PE={linked_meta.get('codeview')!r}, PDB={pdb_identity!r}"
        )
    return matches[0]


def run_pdbutil(pdb: Path, tool: str) -> tuple[str, str]:
    executable = shutil.which(tool) or tool
    result = subprocess.run(
        [executable, "dump", "-symbols", str(pdb)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{executable} dump -symbols failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result.stdout, executable


def run_pdb_summary(pdb: Path, executable: str) -> dict[str, Any]:
    result = subprocess.run(
        [executable, "dump", "--summary", str(pdb)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{executable} dump --summary failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return parse_pdb_summary(result.stdout)


def in_executable_range(rva: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= rva < end for start, end in ranges)


def pdb_name_statistics(procedures: list[PdbProcedure]) -> dict[str, Any]:
    rust_like = [
        procedure.name
        for procedure in procedures
        if "::" in procedure.name or procedure.name.startswith("<")
    ]
    mangled_like = [
        procedure.name
        for procedure in procedures
        if procedure.name.startswith(("_R", "_ZN", "?"))
    ]
    if mangled_like and not rust_like:
        name_format = "mangled-or-decorated"
    elif rust_like:
        name_format = "demangled-or-qualified"
    else:
        name_format = "unknown"
    return {
        "name_format": name_format,
        "rust_like_name_count": len(rust_like),
        "mangled_like_name_count": len(mangled_like),
    }


def collect_functions(
    procedures: list[PdbProcedure],
    section_rvas: dict[int, int],
    executable_ranges: list[tuple[int, int]],
    *,
    candidate_scope: str,
    namespaces: tuple[str, ...] = (),
    root_namespace: str | None = None,
) -> list[FunctionRecord]:
    """Convert PDB procedures to RVA records and select GT targets."""
    scope = normalize_candidate_scope(candidate_scope)
    if scope == RUST_NONSTD_CANDIDATE_SCOPE and not root_namespace:
        raise ValueError("rust-nonstd requires --root-namespace")
    if scope == SUBJECT_CANDIDATE_SCOPE and not namespaces:
        raise ValueError("subject requires at least one --namespace")

    by_rva: dict[int, FunctionRecord] = {}
    for procedure in procedures:
        section_rva = section_rvas.get(procedure.section)
        if section_rva is None:
            continue
        rva = section_rva + procedure.offset
        if not in_executable_range(rva, executable_ranges):
            continue

        is_root = (
            root_namespace is not None
            and procedure.name == f"{root_namespace}::main"
        )
        origin = (
            procedure.name
            if is_root
            else origin_from_symbol(
                procedure.name,
                namespaces,
                candidate_scope=scope,
                root_namespace=root_namespace,
            )
        )
        if origin is not None and not is_root:
            # PDB names use `foo<T>` while ELF demangling usually uses
            # `foo::<T>`. Normalize both spellings to one source origin.
            origin = normalize_all_rust_origin(origin)
        record = by_rva.get(rva)
        if record is None:
            record = FunctionRecord(
                rva=rva,
                size=procedure.size,
                names=set(),
                origin=origin,
                selected=origin is not None and not is_root,
                is_root=is_root,
            )
            by_rva[rva] = record
        record.names.add(procedure.name)
        record.size = max(record.size, procedure.size)
        record.is_root = record.is_root or is_root
        if origin is not None:
            if record.origin is None:
                record.origin = origin
            elif record.origin != origin:
                record.origin = f"shared-address@{record.member_id}"
            record.selected = record.selected or (not record.is_root and not is_root)
        if record.is_root:
            record.selected = False

    return [by_rva[rva] for rva in sorted(by_rva)]


def evaluator_catalog_json(
    *,
    case: str,
    linked_binary: Path,
    stripped_binary: Path,
    pdb: Path,
    linked_meta: dict[str, Any],
    stripped_meta: dict[str, Any],
    pdb_identity: dict[str, Any],
    matched_codeview: dict[str, Any],
    pdb_tool: str,
    procedure_count: int,
    name_statistics: dict[str, Any],
    records: list[FunctionRecord],
    candidate_scope: str,
    namespaces: tuple[str, ...],
    root_namespace: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "tool": "callkin-pe-gt",
        "case": case,
        "address_space": "RVA",
        "linked_binary": {
            **linked_meta,
            "path": str(linked_binary),
            "sha256": sha256_file(linked_binary),
        },
        "stripped_binary": {
            "format": stripped_meta["format"],
            "machine": stripped_meta["machine"],
            "path": str(stripped_binary),
            "sha256": sha256_file(stripped_binary),
        },
        "pdb": {
            "path": str(pdb),
            "sha256": sha256_file(pdb),
            "identity": pdb_identity,
            "matched_codeview": matched_codeview,
        },
        "selection": {
            "candidate_scope": candidate_scope,
            "namespaces": list(namespaces),
            "root_namespace": root_namespace,
        },
        "parser": {
            "backend": "llvm-pdbutil-dump-symbols",
            "pdb_tool": pdb_tool,
            "procedure_record_count": procedure_count,
            "function_record_count": len(records),
            **name_statistics,
        },
        "functions": [
            {
                "id": record.member_id,
                "rva": f"0x{record.rva:x}",
                "size": record.size,
                "symbol_names": sorted(record.names),
                "selected": record.selected,
                "role": record.role,
                "origin": record.origin,
            }
            for record in records
        ],
    }


def anonymous_functions_json(
    *,
    stripped_binary_sha256: str,
    records: list[FunctionRecord],
) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "tool": "callkin-pe-gt",
        "address_space": "RVA",
        "binary_sha256": stripped_binary_sha256,
        "functions": [
            {
                "id": record.member_id,
                "rva": f"0x{record.rva:x}",
                "size": record.size,
                "role": record.role,
            }
            for record in records
        ],
    }


def anonymous_groups_json(
    *,
    binary_sha256: str,
    records: list[FunctionRecord],
) -> dict[str, Any]:
    groups: dict[str, list[FunctionRecord]] = {}
    for record in records:
        if record.selected and record.origin is not None:
            groups.setdefault(record.origin, []).append(record)

    ordered = sorted(
        (
            sorted(record.member_id for record in family)
            for family in groups.values()
            if len(family) >= 2
            and len({name for record in family for name in record.names}) >= 2
        ),
        key=lambda members: (members[0], len(members), members),
    )
    return {
        "schema_version": 2,
        "tool": "callkin-pe-gt",
        "address_space": "RVA",
        "binary_sha256": binary_sha256,
        "groups": [
            {"group": f"G{index:04d}", "members": members}
            for index, members in enumerate(ordered, start=1)
        ],
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create evaluator-only anonymous GT from a stripped PE and PDB."
    )
    parser.add_argument("binary", type=Path, help="stripped PE32+ x86-64 binary")
    parser.add_argument(
        "--linked-binary",
        required=True,
        type=Path,
        help="matching non-stripped PE used with the PDB",
    )
    parser.add_argument("--pdb", required=True, type=Path)
    parser.add_argument("--case", required=True)
    parser.add_argument(
        "--candidate-scope",
        choices=CANDIDATE_SCOPES,
        default=DEFAULT_CANDIDATE_SCOPE,
    )
    parser.add_argument(
        "--namespace",
        action="append",
        default=[],
        help="subject namespace; repeat for multiple namespaces",
    )
    parser.add_argument("--root-namespace")
    parser.add_argument("--pdb-tool", default="llvm-pdbutil")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--catalog-output", type=Path)
    parser.add_argument("--functions-output", type=Path)
    parser.add_argument("--groups-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    stripped_binary = args.binary.resolve()
    linked_binary = args.linked_binary.resolve()
    pdb = args.pdb.resolve()
    if not stripped_binary.is_file():
        raise SystemExit(f"stripped PE binary not found: {stripped_binary}")
    if not linked_binary.is_file():
        raise SystemExit(f"linked PE binary not found: {linked_binary}")
    if not pdb.is_file():
        raise SystemExit(f"PDB not found: {pdb}")

    scope = normalize_candidate_scope(args.candidate_scope)
    if scope == SUBJECT_CANDIDATE_SCOPE and not args.namespace:
        raise SystemExit("--candidate-scope subject requires --namespace")
    if scope == RUST_NONSTD_CANDIDATE_SCOPE and not args.root_namespace:
        raise SystemExit("--candidate-scope rust-nonstd requires --root-namespace")
    root_namespace = args.root_namespace
    if root_namespace is None and scope == SUBJECT_CANDIDATE_SCOPE:
        if len(args.namespace) == 1:
            root_namespace = args.namespace[0]

    default_dir = args.output_dir or Path("evaluation", "pe", args.case)
    catalog_path = args.catalog_output or default_dir / "evaluator_catalog.json"
    functions_path = args.functions_output or default_dir / "functions.json"
    groups_path = args.groups_output or default_dir / "gt_groups.json"

    linked_sections, executable_ranges, linked_meta = load_pe_layout(linked_binary)
    _stripped_sections, _stripped_ranges, stripped_meta = load_pe_layout(stripped_binary)
    verify_pe_pair(linked_meta, stripped_meta)
    symbol_text, pdb_tool = run_pdbutil(pdb, args.pdb_tool)
    pdb_identity = run_pdb_summary(pdb, pdb_tool)
    matched_codeview = verify_codeview_identity(linked_meta, pdb_identity)
    procedures = parse_llvm_pdb_symbols(symbol_text, linked_sections)
    if not procedures:
        raise SystemExit(
            "no PDB procedure records parsed; check llvm-pdbutil output and PDB compatibility"
        )
    name_statistics = pdb_name_statistics(procedures)
    if name_statistics["name_format"] == "mangled-or-decorated":
        raise SystemExit(
            "PDB procedure names appear mangled/decorated; this step requires "
            "demangled Rust names from the PDB"
        )
    records = collect_functions(
        procedures,
        linked_sections,
        executable_ranges,
        candidate_scope=scope,
        namespaces=tuple(args.namespace),
        root_namespace=root_namespace,
    )
    if not any(record.selected for record in records):
        raise SystemExit(
            "no selected functions; check PDB name format, namespace, and candidate scope"
        )
    catalog = evaluator_catalog_json(
        case=args.case,
        linked_binary=linked_binary,
        stripped_binary=stripped_binary,
        pdb=pdb,
        linked_meta=linked_meta,
        stripped_meta=stripped_meta,
        pdb_identity=pdb_identity,
        matched_codeview=matched_codeview,
        pdb_tool=pdb_tool,
        procedure_count=len(procedures),
        name_statistics=name_statistics,
        records=records,
        candidate_scope=scope,
        namespaces=tuple(args.namespace),
        root_namespace=root_namespace,
    )
    stripped_sha256 = sha256_file(stripped_binary)
    functions = anonymous_functions_json(
        stripped_binary_sha256=stripped_sha256,
        records=records,
    )
    groups = anonymous_groups_json(
        binary_sha256=stripped_sha256,
        records=records,
    )
    write_json(catalog_path, catalog)
    write_json(functions_path, functions)
    write_json(groups_path, groups)
    print(f"evaluator catalog: {catalog_path}")
    print(f"anonymous functions: {functions_path}")
    print(f"anonymous groups: {groups_path}")
    print(
        f"PDB procedures={len(procedures)} functions={len(records)} "
        f"selected={sum(record.selected for record in records)} "
        f"groups={len(groups['groups'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
