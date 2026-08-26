from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from typing import Any

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from binary_extractor import DEFAULT_ID_BIAS, function_id
from body_evidence import (
    DecodedInstruction,
    build_cfg,
    normalize_instruction,
    write_body_evidence,
)
from build_manifest import sha256_file
from candidate_selection import CandidateSelection, load_candidate_selection
from graph_evidence import load_raw_graph, raw_graph_sha256
from paths import (
    CANDIDATE_SCOPES,
    DEFAULT_BUILD,
    DEFAULT_CANDIDATE_SCOPE,
    DEFAULT_PROFILE,
    body_evidence_for,
    fixture_binary_for,
    normalize_build,
    normalize_candidate_scope,
    normalize_profile,
    raw_graph_for,
    users_json_for,
)


_OPERAND_KINDS = {
    X86_OP_REG: "register",
    X86_OP_MEM: "memory",
    X86_OP_IMM: "immediate",
}


def read_elf_extent(binary_path: str, address: int, size: int) -> bytes:
    if (
        not isinstance(address, int)
        or isinstance(address, bool)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
    ):
        raise ValueError("ELF extent requires an integer address and positive size")

    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError("Python package pyelftools is required") from exc

    path = Path(binary_path)
    try:
        with path.open("rb") as stream:
            try:
                elf = ELFFile(stream)
            except Exception as exc:
                raise ValueError(f"invalid ELF binary: {binary_path}") from exc
            if elf.elfclass != 64 or elf["e_machine"] != "EM_X86_64":
                raise ValueError("body extraction supports ELF x86-64 only")

            stream.seek(0, 2)
            actual_file_size = stream.tell()
            requested_end = address + size
            for segment in elf.iter_segments():
                if segment["p_type"] != "PT_LOAD":
                    continue
                virtual_start = int(segment["p_vaddr"])
                file_size = int(segment["p_filesz"])
                file_offset = int(segment["p_offset"])
                if file_offset + file_size > actual_file_size:
                    raise ValueError("ELF PT_LOAD segment is truncated")
                if not (
                    virtual_start <= address
                    and requested_end <= virtual_start + file_size
                ):
                    continue
                stream.seek(file_offset + address - virtual_start)
                code = stream.read(size)
                if len(code) != size:
                    raise ValueError("ELF extent is truncated")
                return code
    except OSError as exc:
        raise ValueError(f"cannot read ELF binary: {binary_path}") from exc

    raise ValueError(
        f"extent 0x{address:x}+0x{size:x} is not file-backed by one PT_LOAD segment"
    )


def decode_x86_64(code: bytes, address: int) -> tuple[DecodedInstruction, ...]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = False
    return tuple(
        DecodedInstruction(
            offset=instruction.address - address,
            size=instruction.size,
            mnemonic=instruction.mnemonic,
            operand_text=instruction.op_str,
            operand_kinds=tuple(
                _OPERAND_KINDS.get(operand.type, "unknown")
                for operand in instruction.operands
            ),
            groups=tuple(
                instruction.group_name(group_id)
                for group_id in instruction.groups
            ),
        )
        for instruction in decoder.disasm(code, address)
    )


def build_function_evidence(
    code: bytes,
    address: int,
    size: int,
) -> dict[str, object]:
    if len(code) != size:
        raise ValueError("function bytes do not match the declared extent")
    instructions = decode_x86_64(code, address)
    normalized = tuple(
        normalize_instruction(
            item,
            function_address=address,
            function_size=size,
        )
        for item in instructions
    )
    cfg = build_cfg(normalized, size)
    decoded_byte_count = sum(item.size for item in instructions)
    callsite_count = sum(item.control_flow == "call" for item in normalized)
    unresolved_callsite_count = sum(
        item.control_flow == "call"
        and any(slot.kind == "call" and slot.status == "unresolved" for slot in item.slots)
        for item in normalized
    )
    branch_count = sum(
        item.control_flow
        in {"conditional_branch", "local_jump", "external_jump", "indirect_jump"}
        for item in normalized
    )
    load_count = 0
    store_count = 0
    for item in normalized:
        if item.mnemonic_class == "LEA":
            continue
        if item.operands and item.operands[0].startswith(("stack", "ip_data_slot", "general_pointer")):
            store_count += 1
        if len(item.operands) > 1 and item.operands[1].startswith(("stack", "ip_data_slot", "general_pointer")):
            load_count += 1
    return {
        "id": function_id(address, id_bias=DEFAULT_ID_BIAS),
        "address": f"0x{address:x}",
        "size": size,
        "byte_sha256": hashlib.sha256(code).hexdigest(),
        "instructions": [item.to_dict() for item in instructions],
        "normalized_instructions": [item.to_dict() for item in normalized],
        "blocks": [block.to_dict() for block in cfg.blocks],
        "cfg_edges": [edge.to_dict() for edge in cfg.edges],
        "summary": {
            "byte_size": size,
            "instruction_count": len(instructions),
            "decoded_byte_count": decoded_byte_count,
            "block_count": len(cfg.blocks),
            "cfg_edge_count": len(cfg.edges),
            "branch_count": branch_count,
            "callsite_count": callsite_count,
            "unresolved_callsite_count": unresolved_callsite_count,
            "load_count": load_count,
            "store_count": store_count,
        },
        "quality": {
            "complete_decode": _is_complete_decode(instructions, size),
            "opaque_indirect_jumps": cfg.opaque_indirect_jumps,
        },
    }


def build_body_evidence(
    *,
    binary_path: str,
    selection: CandidateSelection,
    raw_graph: dict[str, Any],
) -> dict[str, Any]:
    actual_binary_sha256 = sha256_file(binary_path)
    if actual_binary_sha256 != selection.provenance.stripped_sha256:
        raise ValueError("stripped binary SHA-256 does not match candidate selection")
    if raw_graph["provenance"] != selection.provenance.to_dict():
        raise ValueError("raw graph/candidate selection build provenance mismatch")
    if raw_graph["binary"]["stripped_sha256"] != actual_binary_sha256:
        raise ValueError("raw graph does not describe the supplied stripped binary")

    functions = []
    for address in sorted(selection.addresses):
        size = selection.function_bounds[address]
        code = read_elf_extent(binary_path, address, size)
        functions.append(build_function_evidence(
            code,
            address,
            size,
        ))
    if sha256_file(binary_path) != actual_binary_sha256:
        raise ValueError("stripped binary changed during body extraction")

    return {
        "schema_version": 2,
        "case": raw_graph["case"],
        "build": raw_graph["build"],
        "profile": raw_graph["profile"],
        "scope": selection.scope,
        "provenance": {
            "stripped_sha256": actual_binary_sha256,
            "candidate_selection_sha256": selection.sha256,
            "raw_graph_sha256": raw_graph_sha256(raw_graph),
        },
        "functions": functions,
    }


def extract_body_evidence(
    *,
    binary_path: str,
    selection_path: str,
    raw_graph_path: str,
    expected_case: str,
    expected_build: str,
    expected_profile: str,
) -> dict[str, Any]:
    raw_graph = load_raw_graph(raw_graph_path)
    for key, expected in (
        ("case", expected_case),
        ("build", expected_build),
        ("profile", expected_profile),
    ):
        if raw_graph[key] != expected:
            raise ValueError(
                f"raw graph {key} mismatch: expected {expected!r}, "
                f"got {raw_graph[key]!r}"
            )
    selection = load_candidate_selection(
        selection_path,
        expected_case=expected_case,
        expected_build=expected_build,
        expected_profile=expected_profile,
    )
    return build_body_evidence(
        binary_path=binary_path,
        selection=selection,
        raw_graph=raw_graph,
    )


def _is_complete_decode(
    instructions: tuple[DecodedInstruction, ...],
    size: int,
) -> bool:
    next_offset = 0
    for instruction in instructions:
        if instruction.offset != next_offset:
            return False
        next_offset += instruction.size
    return next_offset == size


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decode exact x86-64 ELF function extents into body evidence."
    )
    parser.add_argument("case", help="canonical CallKin case name")
    parser.add_argument("--build", default=DEFAULT_BUILD)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument(
        "--candidate-scope",
        default=DEFAULT_CANDIDATE_SCOPE,
        choices=CANDIDATE_SCOPES,
    )
    parser.add_argument("--binary", help="override stripped ELF path")
    parser.add_argument("--users", help="override candidate selection path")
    parser.add_argument("--raw-graph", help="override raw call graph path")
    parser.add_argument("--output", help="override body evidence output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    build = normalize_build(args.build)
    profile = normalize_profile(args.profile)
    scope = normalize_candidate_scope(args.candidate_scope)
    binary_path = args.binary or fixture_binary_for(args.case, build, profile)
    selection_path = args.users or users_json_for(
        args.case, build, profile, scope
    )
    raw_graph_path = args.raw_graph or raw_graph_for(
        args.case, build, profile
    )
    output_path = args.output or body_evidence_for(
        args.case, build, profile, scope
    )
    try:
        artifact = extract_body_evidence(
            binary_path=binary_path,
            selection_path=selection_path,
            raw_graph_path=raw_graph_path,
            expected_case=args.case,
            expected_build=build,
            expected_profile=profile,
        )
        write_body_evidence(artifact, output_path)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {output_path}")
    print(f"functions={len(artifact['functions'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
