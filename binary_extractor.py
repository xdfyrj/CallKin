from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from build_manifest import BUILD_TARGET, load_and_verify_manifest
from candidate_selection import load_candidate_selection
from graph_evidence import (
    ELF_RELOCATION_RESOLVER,
    TransferEvidence,
    make_raw_graph,
    raw_graph_sha256,
    write_raw_graph,
)
from graph_projector import project_fixture
from function_boundaries import load_function_boundaries
from paths import (
    ANALYSIS_TRACKS,
    ANCHOR_POLICIES,
    ANGR_TRACK,
    BUILD_PROFILES,
    CANDIDATE_SCOPES,
    DEFAULT_ANALYSIS_TRACK,
    DEFAULT_ANCHOR_POLICY,
    DEFAULT_BUILD,
    DEFAULT_CANDIDATE_SCOPE,
    DEFAULT_PROFILE,
    boundaries_json_for,
    build_manifest_for,
    fixture_json_for,
    evidence_backend_for_track,
    normalize_profile,
    normalize_anchor_policy,
    normalize_candidate_scope,
    normalize_track,
    raw_graph_for,
    resolve_fixture_binary,
    resolve_users_json,
    split_case_build,
)
from provenance import BuildProvenance


SCHEMA_VERSION = 4
DEFAULT_ID_BIAS = 0x100000
DEFAULT_CASE = "unknown"
R2_EXECUTABLE = "radare2"
_X86_64_RELOCATION_TYPES = {
    "absolute": 1,       # R_X86_64_64
    "glob_dat": 6,       # R_X86_64_GLOB_DAT
    "jump_slot": 7,      # R_X86_64_JUMP_SLOT
    "relative": 8,       # R_X86_64_RELATIVE
}


@dataclass(frozen=True)
class R2Function:
    addr: int
    name: str
    size: int
    kind: str


@dataclass(frozen=True)
class ExtractionArtifacts:
    raw_graph: dict[str, Any]
    fixture: dict[str, Any]
    raw_graph_sha256: str
    execution: dict[str, Any]


def ensure_radare2_available() -> None:
    if shutil.which(R2_EXECUTABLE):
        return

    raise RuntimeError(
        f"{R2_EXECUTABLE} executable was not found. Install radare2 before running "
        "binary_extractor.py."
    )


def open_r2(binary_path: str) -> Any:
    ensure_radare2_available()

    try:
        import r2pipe
    except ImportError as exc:
        raise RuntimeError(
            "Python package r2pipe is not installed. Install Python "
            "dependencies with `python3 -m pip install -r requirements.txt`."
        ) from exc

    try:
        return r2pipe.open(binary_path, flags=["-2"])
    except Exception as exc:
        raise RuntimeError(
            f"failed to open {binary_path!r} with radare2/r2pipe: {exc}"
        ) from exc


def function_id(addr: int, *, id_bias: int = 0) -> str:
    return f"FUN_{addr + id_bias:08x}"


def parse_int(value: str) -> int:
    return int(value, 0)


def is_probably_import(func: R2Function) -> bool:
    return func.name.startswith("sym.imp.") or func.kind == "sym"


def load_elf_relocation_targets(binary_path: str) -> dict[int, int]:
    """Return exact x86-64 relocation slot -> linked target mappings."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection
    except ImportError as exc:
        raise RuntimeError(
            "Python package pyelftools is required for ELF relocation analysis. "
            "Install dependencies with `python3 -m pip install -r requirements.txt`."
        ) from exc

    targets: dict[int, int] = {}
    with open(binary_path, "rb") as handle:
        elf = ELFFile(handle)
        if elf.header["e_machine"] != "EM_X86_64":
            raise ValueError("ELF relocation analysis currently supports x86-64 only")

        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symbol_table = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                entry = relocation.entry
                relocation_type = entry["r_info_type"]
                addend = int(entry.get("r_addend", 0))
                target = None
                if relocation_type == _X86_64_RELOCATION_TYPES["relative"]:
                    target = addend
                elif relocation_type in {
                    _X86_64_RELOCATION_TYPES["absolute"],
                    _X86_64_RELOCATION_TYPES["glob_dat"],
                    _X86_64_RELOCATION_TYPES["jump_slot"],
                } and symbol_table is not None:
                    symbol = symbol_table.get_symbol(entry["r_info_sym"])
                    if symbol["st_shndx"] != "SHN_UNDEF":
                        target = int(symbol["st_value"]) + addend
                if target is None:
                    continue
                slot = int(entry["r_offset"])
                target &= (1 << 64) - 1
                previous = targets.get(slot)
                if previous is not None and previous != target:
                    raise ValueError(
                        f"conflicting ELF relocations at 0x{slot:x}: "
                        f"0x{previous:x} != 0x{target:x}"
                    )
                targets[slot] = target
    return targets


class BinaryExtractor:
    def __init__(
        self,
        binary_path: str,
        *,
        include_imports: bool = False,
        id_bias: int = DEFAULT_ID_BIAS,
    ) -> None:
        self.binary_path = binary_path
        self.include_imports = include_imports
        self.id_bias = id_bias
        self.r2 = open_r2(binary_path)
        self.functions: list[R2Function] = []
        self.by_addr: dict[int, R2Function] = {}
        self.all_functions: list[R2Function] = []
        self.all_by_addr: dict[int, R2Function] = {}
        self._call_cache: dict[tuple[int, int | None], Counter[int]] = {}
        self._transfer_cache: dict[
            tuple[int, int | None], tuple[TransferEvidence, ...]
        ] = {}
        self.relocation_targets = load_elf_relocation_targets(binary_path)

    def close(self) -> None:
        try:
            self.r2.quit()
        except Exception:
            pass

    def analyze(self) -> None:
        self.r2.cmd("aaa")
        self._refresh_functions()

    def _refresh_functions(self) -> None:
        raw_functions = self.r2.cmdj("aflj") or []

        all_functions: list[R2Function] = []
        for raw in raw_functions:
            addr = raw.get("offset")
            if not isinstance(addr, int):
                continue

            func = R2Function(
                addr=addr,
                name=str(raw.get("name") or self._function_id(addr)),
                size=int(raw.get("size") or 0),
                kind=str(raw.get("type") or ""),
            )
            all_functions.append(func)

        all_functions.sort(key=lambda f: f.addr)
        functions = [
            func
            for func in all_functions
            if self.include_imports or not is_probably_import(func)
        ]
        self.all_functions = all_functions
        self.all_by_addr = {func.addr: func for func in all_functions}
        self.functions = functions
        self.by_addr = {f.addr: f for f in functions}
        self._call_cache.clear()
        self._transfer_cache.clear()

    def list_functions(self) -> None:
        for func in self.functions:
            print(f"{self._function_id(func.addr)}  raw={func.addr:#x}  {func.name}  size={func.size}")

    def resolve_root(
        self,
        root: str | None,
        *,
        function_bounds: dict[int, int] | None = None,
    ) -> R2Function:
        if root:
            resolved = self._resolve_function_spec(root)
            if resolved is None:
                raise ValueError(f"cannot resolve root function: {root}")
            return resolved

        entry_root = self._root_from_libc_start_main(function_bounds or {})
        if entry_root is not None:
            return entry_root

        for wanted in ("main", "sym.main"):
            resolved = self._resolve_function_spec(wanted)
            if resolved is not None:
                return resolved

        resolved = self._resolve_function_spec("entry0")
        if resolved is not None:
            return resolved

        raise ValueError(
            "cannot auto-detect main/root. Re-run with --list-functions, then pass --root."
        )

    def _resolve_function_spec(self, spec: str) -> R2Function | None:
        try:
            addr = parse_int(spec)
        except ValueError:
            addr = None

        if addr is not None:
            biased_addr = addr - self.id_bias
            return self.function_containing(addr) or self.function_containing(biased_addr)

        for func in self.functions:
            if spec in {self._function_id(func.addr), function_id(func.addr), func.name}:
                return func

        for func in self.functions:
            if func.name.endswith(spec):
                return func

        return None

    def _function_id(self, addr: int) -> str:
        return function_id(addr, id_bias=self.id_bias)

    def _root_from_libc_start_main(
        self,
        function_bounds: dict[int, int] | None = None,
    ) -> R2Function | None:
        entry = self._resolve_function_spec("entry0")
        if entry is None:
            return None

        wrapper_addr = self._libc_start_main_wrapper_addr(entry)
        if wrapper_addr is None:
            return None

        self._ensure_function_at(wrapper_addr)
        wrapper_size = (function_bounds or {}).get(wrapper_addr)
        rust_main_addr = self._rust_main_from_start_wrapper(
            wrapper_addr,
            symbol_size=wrapper_size,
        )
        if rust_main_addr is not None:
            return self._ensure_function_at(rust_main_addr)

        return self.function_containing(wrapper_addr)

    def _libc_start_main_wrapper_addr(self, entry: R2Function) -> int | None:
        pdf = self.r2.cmdj(f"pdfj @ {entry.addr}") or {}
        last_rdi_ptr: int | None = None

        for op in pdf.get("ops") or []:
            opcode = str(op.get("opcode") or "")
            if opcode.startswith("lea rdi,") and isinstance(op.get("ptr"), int):
                last_rdi_ptr = op["ptr"]
                continue

            if "__libc_start_main" in self._op_text(op) and last_rdi_ptr is not None:
                return last_rdi_ptr

        return None

    def _rust_main_from_start_wrapper(
        self,
        wrapper_addr: int,
        *,
        symbol_size: int | None = None,
    ) -> int | None:
        scan_full_extent = symbol_size is not None
        if symbol_size is not None:
            ops = self._startup_ops_from_symbol_extent(wrapper_addr, symbol_size)
        else:
            pdf = self.r2.cmdj(f"pdfj @ {wrapper_addr}") or {}
            ops = (pdf.get("ops") or []) if isinstance(pdf, dict) else []
            if not ops:
                ops = self.r2.cmdj(f"pdj 64 @ {wrapper_addr}") or []
            if isinstance(ops, dict):
                ops = ops.get("ops") or []

        pending_main_addr: int | None = None
        pending_register: str | None = None
        saw_main_pointer_store = False

        for op in ops:
            opcode = str(op.get("opcode") or "")
            op_type = str(op.get("type") or "")

            if opcode.startswith(("lea rax,", "lea rdi,")) and isinstance(
                op.get("ptr"), int
            ):
                pending_main_addr = op["ptr"]
                pending_register = "rax" if opcode.startswith("lea rax,") else "rdi"
                saw_main_pointer_store = False
                continue

            if pending_main_addr is not None and self._stores_rax_as_lang_start_arg(op):
                saw_main_pointer_store = True
                continue

            if pending_main_addr is not None and self._is_call_or_tail_transfer(op):
                text = self._op_text(op)
                if (
                    "lang_start_internal" in text
                    or saw_main_pointer_store
                    or (
                        pending_register == "rdi"
                        and (
                            self._is_tail_call_jump_op(op)
                            or self._call_target_invokes_rdi(op)
                        )
                    )
                ):
                    return pending_main_addr
                pending_main_addr = None
                pending_register = None
                saw_main_pointer_store = False

            if op_type in {"ret", "trap"} or opcode.startswith(("ret", "hlt", "int3")):
                if not scan_full_extent:
                    break
                pending_main_addr = None
                pending_register = None
                saw_main_pointer_store = False

        return None

    def _startup_ops_from_symbol_extent(
        self,
        address: int,
        size: int,
    ) -> list[dict[str, Any]]:
        """Decode a complete startup wrapper extent without trusting r2 pdfj."""
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
            from capstone.x86_const import (
                X86_OP_IMM,
                X86_OP_MEM,
                X86_OP_REG,
                X86_REG_RAX,
                X86_REG_RIP,
                X86_REG_RSP,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Python package capstone is required for full startup root "
                "detection. Install dependencies with `python3 -m pip install "
                "-r requirements.txt`."
            ) from exc

        raw_bytes = self.r2.cmdj(f"p8j {size} @ {address}") or []
        if not isinstance(raw_bytes, list) or len(raw_bytes) != size or not all(
            isinstance(value, int) and 0 <= value <= 0xFF for value in raw_bytes
        ):
            raise ValueError(
                f"radare2 could not read startup symbol extent "
                f"0x{address:x}+0x{size:x}"
            )

        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        instructions = list(decoder.disasm(bytes(raw_bytes), address))
        expected = address
        end = address + size
        ops: list[dict[str, Any]] = []

        for instruction in instructions:
            if instruction.address != expected:
                raise ValueError(
                    f"incomplete startup symbol-extent decode at 0x{expected:x}; "
                    f"next instruction starts at 0x{instruction.address:x}"
                )
            expected = instruction.address + instruction.size
            opcode = f"{instruction.mnemonic} {instruction.op_str}".strip()
            op: dict[str, Any] = {
                "offset": instruction.address,
                "opcode": opcode,
                "type": instruction.mnemonic,
            }

            operands = instruction.operands
            if (
                instruction.mnemonic == "lea"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and instruction.reg_name(operands[0].reg) in {"rax", "rdi"}
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.base == X86_REG_RIP
            ):
                op["ptr"] = (
                    instruction.address
                    + instruction.size
                    + operands[1].mem.disp
                ) & ((1 << 64) - 1)

            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_MEM
                and operands[0].mem.base == X86_REG_RSP
                and operands[0].mem.index == 0
                and operands[0].mem.disp == 0
                and operands[1].type == X86_OP_REG
                and operands[1].reg == X86_REG_RAX
            ):
                op["stores_rax_to_rsp"] = True

            if (
                instruction.mnemonic in {"call", "jmp"}
                and len(operands) == 1
                and operands[0].type == X86_OP_IMM
            ):
                op["jump"] = int(operands[0].imm) & ((1 << 64) - 1)

            ops.append(op)

        if expected != end:
            raise ValueError(
                f"incomplete startup symbol-extent decode for 0x{address:x}: "
                f"expected end 0x{end:x}, got 0x{expected:x}"
            )
        return ops

    def _call_target_invokes_rdi(self, op: dict[str, Any]) -> bool:
        target = self._direct_code_target(op)
        if target is None:
            return False
        target_ops = self.r2.cmdj(f"pdj 8 @ {target}") or []
        if isinstance(target_ops, dict):
            target_ops = target_ops.get("ops") or []
        return any(
            str(target_op.get("opcode") or "").strip() == "call rdi"
            for target_op in target_ops
        )

    @staticmethod
    def _stores_rax_as_lang_start_arg(op: dict[str, Any]) -> bool:
        if op.get("stores_rax_to_rsp") is True:
            return True
        opcode = str(op.get("opcode") or "")
        return opcode in {
            "mov qword [rsp], rax",
            "mov [rsp], rax",
        }

    @staticmethod
    def _op_text(op: dict[str, Any]) -> str:
        return f"{op.get('opcode') or ''} {op.get('disasm') or ''}"

    def _ensure_function_at(self, addr: int) -> R2Function | None:
        existing = self.by_addr.get(addr)
        if existing is not None:
            return existing

        self.r2.cmd(f"af @ {addr}")
        self._refresh_functions()

        return self.by_addr.get(addr) or self.function_containing(addr)

    def function_containing(self, addr: int) -> R2Function | None:
        if addr in self.by_addr:
            return self.by_addr[addr]

        for func in self.functions:
            if func.size <= 0:
                continue
            if func.addr <= addr < func.addr + func.size:
                return func

        return None

    def add_symbol_bound_functions(
        self,
        function_bounds: dict[int, int],
    ) -> list[int]:
        """Add symbol-known user starts that radare2 did not recover."""
        if not hasattr(self, "all_functions"):
            self.all_functions = list(self.functions)
        if not hasattr(self, "all_by_addr"):
            self.all_by_addr = dict(self.by_addr)
        added = []
        for addr, size in sorted(function_bounds.items()):
            if addr in self.by_addr:
                continue
            func = R2Function(
                addr=addr,
                name=f"symbol.bound.0x{addr:x}",
                size=size,
                kind="symbol",
            )
            self.functions.append(func)
            self.by_addr[addr] = func
            self.all_functions.append(func)
            self.all_by_addr[addr] = func
            added.append(addr)
        self.functions.sort(key=lambda func: func.addr)
        self.all_functions.sort(key=lambda func: func.addr)
        return added

    def direct_calls(
        self,
        func: R2Function,
        *,
        symbol_size: int | None = None,
    ) -> Counter[int]:
        cache_key = (func.addr, symbol_size)
        if cache_key in self._call_cache:
            return self._call_cache[cache_key].copy()

        counts: Counter[int] = Counter()
        for transfer in self.transfer_evidence(func, symbol_size=symbol_size):
            if transfer.status == "resolved" and transfer.target is not None:
                counts[transfer.target] += 1

        self._call_cache[cache_key] = counts.copy()
        return counts

    def transfer_evidence(
        self,
        func: R2Function,
        *,
        symbol_size: int | None = None,
    ) -> tuple[TransferEvidence, ...]:
        cache_key = (func.addr, symbol_size)
        transfer_cache = getattr(self, "_transfer_cache", None)
        if transfer_cache is None:
            transfer_cache = {}
            self._transfer_cache = transfer_cache
        if cache_key in transfer_cache:
            return transfer_cache[cache_key]

        if symbol_size is None:
            transfers = self._r2_transfer_evidence(func)
        else:
            transfers = self._symbol_extent_transfer_evidence(func, symbol_size)
        transfer_cache[cache_key] = tuple(transfers)
        return transfer_cache[cache_key]

    def _r2_transfer_evidence(
        self,
        func: R2Function,
    ) -> list[TransferEvidence]:
        pdf = self.r2.cmdj(f"pdfj @ {func.addr}") or {}
        ops = pdf.get("ops") or []
        transfers = []
        for index, op in enumerate(ops):
            callsite = op.get("offset")
            if not isinstance(callsite, int):
                callsite = func.addr + index
            instruction = str(op.get("opcode") or op.get("disasm") or op.get("type") or "unknown")
            is_call = self._is_call_op(op)
            is_tail_jump = self._is_tail_call_jump_op(op)
            if not is_call and not is_tail_jump:
                continue
            direct_target = self._direct_code_target(op)
            target_func = self._direct_call_target(
                func,
                op,
                include_filtered=True,
            )
            operand_kind = self._r2_operand_kind(op)
            relocation_target = self._r2_relocation_target(op)
            relocation_func = (
                getattr(self, "all_by_addr", self.by_addr).get(relocation_target)
                if relocation_target is not None
                else None
            )

            if (
                target_func is not None
                and not self.include_imports
                and is_probably_import(target_func)
            ):
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=callsite,
                    instruction=instruction,
                    kind="call" if is_call else "tail-call",
                    operand_kind="immediate",
                    status="filtered",
                    target=target_func.addr,
                    resolver="direct-immediate" if is_call else "direct-tail",
                    confidence="exact",
                    filter_reason="import",
                ))
            elif target_func is not None:
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=callsite,
                    instruction=instruction,
                    kind="call" if is_call else "tail-call",
                    operand_kind="immediate",
                    status="resolved",
                    target=target_func.addr,
                    resolver="direct-immediate" if is_call else "direct-tail",
                    confidence="exact",
                ))
            elif (
                relocation_func is not None
                and not self.include_imports
                and is_probably_import(relocation_func)
            ):
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=callsite,
                    instruction=instruction,
                    kind="call" if is_call else "tail-call",
                    operand_kind="memory",
                    status="filtered",
                    target=relocation_func.addr,
                    resolver=ELF_RELOCATION_RESOLVER,
                    confidence="exact",
                    filter_reason="import",
                ))
            elif relocation_func is not None:
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=callsite,
                    instruction=instruction,
                    kind="call" if is_call else "tail-call",
                    operand_kind="memory",
                    status="resolved",
                    target=relocation_func.addr,
                    resolver=ELF_RELOCATION_RESOLVER,
                    confidence="exact",
                ))
            elif relocation_target is not None:
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=callsite,
                    instruction=instruction,
                    kind="call" if is_call else "tail-call",
                    operand_kind="memory",
                    status="unmapped",
                    target=relocation_target,
                    resolver=ELF_RELOCATION_RESOLVER,
                    confidence="exact",
                ))
            elif (
                is_call
                and direct_target is not None
                and operand_kind == "immediate"
            ):
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=callsite,
                    instruction=instruction,
                    kind="call",
                    operand_kind="immediate",
                    status="unmapped",
                    target=direct_target,
                    resolver="direct-immediate",
                    confidence="exact",
                ))
            elif is_call:
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=callsite,
                    instruction=instruction,
                    kind="call",
                    operand_kind=operand_kind,
                    status="unresolved",
                    target=None,
                    resolver=None,
                    confidence="unknown",
                ))
            elif (
                is_tail_jump
                and operand_kind in {"memory", "register"}
                and self._is_terminal_r2_jump(ops, index)
            ):
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=callsite,
                    instruction=instruction,
                    kind="tail-call",
                    operand_kind=operand_kind,
                    status="unresolved",
                    target=None,
                    resolver=None,
                    confidence="unknown",
                ))
        return self._deduplicate_transfer_sites(transfers)

    def _symbol_extent_transfer_evidence(
        self,
        func: R2Function,
        size: int,
    ) -> list[TransferEvidence]:
        try:
            from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_MODE_64, Cs
            from capstone.x86_const import (
                X86_OP_IMM,
                X86_OP_MEM,
                X86_OP_REG,
                X86_REG_RIP,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Python package capstone is required for symbol-extent call "
                "extraction. Install dependencies with `python3 -m pip install "
                "-r requirements.txt`."
            ) from exc

        raw_bytes = self.r2.cmdj(f"p8j {size} @ {func.addr}") or []
        if not isinstance(raw_bytes, list) or len(raw_bytes) != size or not all(
            isinstance(value, int) and 0 <= value <= 0xFF for value in raw_bytes
        ):
            raise ValueError(
                f"radare2 could not read symbol extent 0x{func.addr:x}+0x{size:x}"
            )

        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        instructions = list(decoder.disasm(bytes(raw_bytes), func.addr))
        expected = func.addr
        end = func.addr + size
        transfers = []

        for instruction in instructions:
            if instruction.address != expected:
                raise ValueError(
                    f"incomplete symbol-extent decode at 0x{expected:x}; "
                    f"next instruction starts at 0x{instruction.address:x}"
                )
            expected = instruction.address + instruction.size

            is_call = instruction.group(CS_GRP_CALL)
            is_tail_jump = instruction.mnemonic == "jmp"
            if not is_call and not is_tail_jump:
                continue
            instruction_text = (
                f"{instruction.mnemonic} {instruction.op_str}".strip()
            )
            operand = (
                instruction.operands[0]
                if len(instruction.operands) == 1
                else None
            )
            if operand is not None and operand.type == X86_OP_MEM:
                operand_kind = "memory"
            elif operand is not None and operand.type == X86_OP_REG:
                operand_kind = "register"
            elif operand is not None and operand.type == X86_OP_IMM:
                operand_kind = "immediate"
            else:
                operand_kind = "unknown"

            target_func = None
            direct_target = None
            resolver = None
            if operand is not None and operand.type == X86_OP_IMM:
                direct_target = int(operand.imm) & ((1 << 64) - 1)
                resolver = "direct-immediate" if is_call else "direct-tail"
            elif (
                operand is not None
                and operand.type == X86_OP_MEM
                and operand.mem.base == X86_REG_RIP
            ):
                slot = instruction.address + instruction.size + operand.mem.disp
                direct_target = getattr(self, "relocation_targets", {}).get(slot)
                if direct_target is not None:
                    resolver = ELF_RELOCATION_RESOLVER
            if direct_target is not None:
                if resolver == ELF_RELOCATION_RESOLVER:
                    target_func = getattr(
                        self, "all_by_addr", self.by_addr
                    ).get(direct_target)
                else:
                    target_func = self._resolve_direct_target(
                        func,
                        direct_target,
                        is_call=is_call,
                        is_tail_jump=is_tail_jump,
                        include_filtered=True,
                    )

            if (
                target_func is not None
                and not self.include_imports
                and is_probably_import(target_func)
            ):
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=instruction.address,
                    instruction=instruction_text,
                    kind="call" if is_call else "tail-call",
                    operand_kind=operand_kind,
                    status="filtered",
                    target=target_func.addr,
                    resolver=resolver,
                    confidence="exact",
                    filter_reason="import",
                ))
            elif target_func is not None:
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=instruction.address,
                    instruction=instruction_text,
                    kind="call" if is_call else "tail-call",
                    operand_kind=operand_kind,
                    status="resolved",
                    target=target_func.addr,
                    resolver=resolver,
                    confidence="exact",
                ))
            elif direct_target is not None and (
                is_call or resolver != "direct-tail"
            ):
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=instruction.address,
                    instruction=instruction_text,
                    kind="call" if is_call else "tail-call",
                    operand_kind=operand_kind,
                    status="unmapped",
                    target=direct_target,
                    resolver=resolver,
                    confidence="exact",
                ))
            elif is_call or (
                is_tail_jump
                and operand_kind in {"memory", "register"}
                and instruction.address + instruction.size == end
            ):
                transfers.append(TransferEvidence(
                    source=func.addr,
                    callsite=instruction.address,
                    instruction=instruction_text,
                    kind="call" if is_call else "tail-call",
                    operand_kind=operand_kind,
                    status="unresolved",
                    target=None,
                    resolver=None,
                    confidence="unknown",
                ))

        if expected != end:
            raise ValueError(
                f"incomplete symbol-extent decode for 0x{func.addr:x}: "
                f"expected end 0x{end:x}, got 0x{expected:x}"
            )
        return self._deduplicate_transfer_sites(transfers)

    @staticmethod
    def _r2_operand_kind(op: dict[str, Any]) -> str:
        opcode = str(op.get("opcode") or "")
        operand = opcode.split(None, 1)[1] if " " in opcode else ""
        if "[" in operand:
            return "memory"
        if operand and not operand.startswith("0x"):
            return "register"
        if isinstance(op.get("jump"), int):
            return "immediate"
        return "unknown"

    def _r2_relocation_target(self, op: dict[str, Any]) -> int | None:
        if self._r2_operand_kind(op) != "memory":
            return None
        slot = op.get("ptr")
        if not isinstance(slot, int):
            return None
        return getattr(self, "relocation_targets", {}).get(slot)

    @staticmethod
    def _is_terminal_r2_jump(ops: list[dict[str, Any]], index: int) -> bool:
        for later in ops[index + 1:]:
            opcode = str(later.get("opcode") or "").strip()
            op_type = str(later.get("type") or "")
            if opcode.startswith(("nop", "int3")) or op_type in {"nop", "trap"}:
                continue
            return False
        return True

    @staticmethod
    def _deduplicate_transfer_sites(
        transfers: list[TransferEvidence],
    ) -> list[TransferEvidence]:
        by_callsite: dict[int, TransferEvidence] = {}
        for transfer in transfers:
            previous = by_callsite.get(transfer.callsite)
            if previous is None:
                by_callsite[transfer.callsite] = transfer
            elif previous != transfer:
                raise ValueError(
                    "conflicting transfer evidence at "
                    f"0x{transfer.callsite:x}: {previous} != {transfer}"
                )
        return [by_callsite[address] for address in sorted(by_callsite)]

    @staticmethod
    def _is_call_op(op: dict[str, Any]) -> bool:
        op_type = str(op.get("type") or "")
        opcode = str(op.get("opcode") or "")
        return "call" in op_type or opcode.startswith("call ")

    @classmethod
    def _is_call_or_tail_transfer(cls, op: dict[str, Any]) -> bool:
        return cls._is_call_op(op) or cls._is_tail_call_jump_op(op)

    def _direct_call_target(
        self,
        current_func: R2Function,
        op: dict[str, Any],
        *,
        include_filtered: bool = False,
    ) -> R2Function | None:
        target = self._direct_code_target(op)
        if target is None:
            return None

        return self._resolve_direct_target(
            current_func,
            target,
            is_call=self._is_call_op(op),
            is_tail_jump=self._is_tail_call_jump_op(op),
            include_filtered=include_filtered,
        )

    def _resolve_direct_target(
        self,
        current_func: R2Function,
        target: int,
        *,
        is_call: bool,
        is_tail_jump: bool,
        include_filtered: bool = False,
    ) -> R2Function | None:
        if is_call:
            if include_filtered:
                return self._function_containing_all(target)
            return self.function_containing(target)

        if is_tail_jump:
            # O3 often lowers `call f; ret` to `jmp f`.
            # Count it only when the jump target is exactly another function's
            # start address. This avoids ordinary in-function branches and most
            # switch/case labels that radare2 may expose as pseudo-functions.
            target_func = (
                getattr(self, "all_by_addr", self.by_addr).get(target)
                if include_filtered
                else self.by_addr.get(target)
            )
            if target_func is not None and target_func.addr != current_func.addr:
                return target_func

        return None

    def _function_containing_all(self, address: int) -> R2Function | None:
        all_by_addr = getattr(self, "all_by_addr", self.by_addr)
        if address in all_by_addr:
            return all_by_addr[address]
        for func in getattr(self, "all_functions", self.functions):
            if func.size > 0 and func.addr <= address < func.addr + func.size:
                return func
        return None

    @staticmethod
    def _is_tail_call_jump_op(op: dict[str, Any]) -> bool:
        op_type = str(op.get("type") or "")
        opcode = str(op.get("opcode") or "")
        return op_type in {"jmp", "ujmp"} or opcode.startswith("jmp ")

    @staticmethod
    def _direct_code_target(op: dict[str, Any]) -> int | None:
        value = op.get("jump")
        if isinstance(value, int):
            return value & ((1 << 64) - 1)
        return None

    def build_call_graph(
        self,
        *,
        function_bounds: dict[int, int] | None = None,
    ) -> dict[int, Counter[int]]:
        bounds = function_bounds or {}
        return {
            func.addr: self.direct_calls(func, symbol_size=bounds.get(func.addr))
            for func in self.functions
        }

    def build_raw_graph(
        self,
        *,
        case: str,
        build: str,
        profile: str,
        provenance: BuildProvenance,
        boundary_input_sha256: str,
        root_address: int,
        function_bounds: dict[int, int],
        symbol_only_addresses: set[int],
        boundary_mode: str,
        boundary_mismatches: list[dict[str, int | str]],
    ) -> dict[str, Any]:
        transfers = []
        for func in self.functions:
            transfers.extend(
                self.transfer_evidence(
                    func,
                    symbol_size=function_bounds.get(func.addr),
                )
            )
        functions = [
            {
                "address": f"0x{func.addr:x}",
                "name": func.name,
                "size": function_bounds.get(func.addr, func.size),
                "boundary_source": (
                    "symbol-oracle"
                    if func.addr in function_bounds
                    else "radare2"
                ),
                "discovered_by_radare2": func.addr not in symbol_only_addresses,
            }
            for func in self.functions
        ]
        return make_raw_graph(
            case=case,
            build=build,
            profile=profile,
            binary_path=self.binary_path,
            provenance=provenance,
            boundary_input_sha256=boundary_input_sha256,
            root_address=root_address,
            functions=functions,
            transfers=transfers,
            boundary_mode=boundary_mode,
            boundary_mismatches=boundary_mismatches,
        )

    def boundary_mismatches(
        self,
        function_bounds: dict[int, int],
    ) -> list[dict[str, int | str]]:
        mismatches = []
        for addr, symbol_size in sorted(function_bounds.items()):
            func = self.by_addr.get(addr)
            if func is None or func.size == symbol_size:
                continue
            mismatches.append(
                {
                    "id": self._function_id(addr),
                    "address": f"0x{addr:x}",
                    "symbol_size": symbol_size,
                    "radare2_size": func.size,
                }
            )
        return mismatches


def select_reachable(
    graph: dict[int, Counter[int]],
    root_addr: int,
) -> set[int]:
    selected: set[int] = {root_addr}
    queue: deque[int] = deque([root_addr])

    while queue:
        addr = queue.popleft()

        for target in graph.get(addr, {}):
            if target in selected:
                continue
            selected.add(target)
            queue.append(target)

    return selected


def select_user_context(
    graph: dict[int, Counter[int]],
    root_addr: int,
    user_addrs: set[int],
    *,
    allowed_addrs: set[int],
    score_root: bool,
) -> set[int]:
    """
    Select the fixture subgraph for user-address mode.

    Emit the complete resolved outgoing closure of root and listed users.

    Listed users remain authoritative even when root reachability is incomplete.
    Non-user functions in the closure are emitted as unscored anchors.
    """
    selected = ({root_addr} | set(user_addrs)) & allowed_addrs
    queue = deque(sorted(selected))
    while queue:
        source = queue.popleft()
        for target in graph.get(source, {}):
            if target not in allowed_addrs or target in selected:
                continue
            selected.add(target)
            queue.append(target)
    return selected


def make_fixture_json(
    *,
    case: str,
    build: str,
    profile: str,
    binary_path: str,
    root: R2Function,
    functions: dict[int, R2Function],
    graph: dict[int, Counter[int]],
    selected: set[int],
    score_root: bool,
    user_addrs: set[int] | None,
    users_path: str | None,
    id_bias: int,
    provenance: BuildProvenance,
    boundary_mode: str = "radare2",
    boundary_mismatches: list[dict[str, int | str]] | None = None,
) -> dict[str, Any]:
    nodes = []

    for addr in sorted(selected):
        func = functions[addr]
        is_root = addr == root.addr
        if user_addrs is None:
            node_type = "user" if score_root or not is_root else "anchor"
        else:
            node_type = "user" if addr in user_addrs or (score_root and is_root) else "anchor"

        calls = [
            {"target": function_id(target, id_bias=id_bias), "count": count}
            for target, count in sorted(graph.get(addr, {}).items())
            if target in selected and count > 0
        ]
        scored = node_type == "user"

        nodes.append(
            {
                "id": function_id(func.addr, id_bias=id_bias),
                "type": node_type,
                "scored": scored,
                "calls": calls,
            }
        )

    note = (
        f"generated by binary_extractor.py from {binary_path}; "
        f"root={function_id(root.addr, id_bias=id_bias)}/{root.name}; "
        f"users={users_path or 'none'}; "
        "listed user nodes are user/scored=true; "
        "user mode emits the complete resolved outgoing closure of root and "
        "listed users; all selected anchors retain resolved outgoing edges; "
        "anchors remain scored=false; "
        "std/runtime classification is out of this extractor's research scope; "
        "edges to non-emitted targets are omitted"
    )

    return {
        "case": case,
        "build": build,
        "profile": profile,
        "schema_version": SCHEMA_VERSION,
        "provenance": provenance.to_dict(),
        "extraction": {
            "boundary_mode": boundary_mode,
            "boundary_mismatches": boundary_mismatches or [],
        },
        "note": note,
        "nodes": nodes,
    }


def extract_artifacts(args: argparse.Namespace) -> ExtractionArtifacts:
    extraction_started = time.perf_counter()
    extractor = BinaryExtractor(
        args.binary,
        include_imports=args.include_imports,
        id_bias=args.id_bias,
    )
    try:
        extractor.analyze()

        if args.list_functions:
            extractor.list_functions()
            return ExtractionArtifacts({}, {}, "", {})

        selection = (
            load_candidate_selection(
                args.users,
                expected_case=args.case,
                expected_build=args.build,
                expected_profile=args.profile,
            )
            if args.users
            else None
        )
        if selection is None:
            raise ValueError(
                "fixture projection requires a candidate selection JSON; pass --users"
            )
        if not getattr(args, "boundaries", None):
            raise ValueError(
                "raw extraction requires a scope-independent function boundary "
                "JSON; run gt_extractor.py first or pass --boundaries"
            )
        boundary_input = load_function_boundaries(
            args.boundaries,
            expected_case=args.case,
            expected_build=args.build,
            expected_profile=args.profile,
        )
        function_bounds = boundary_input.bounds
        boundary_input_sha256 = boundary_input.sha256
        provenance = getattr(args, "provenance", None)
        if provenance is None:
            raise ValueError("verified build provenance is required for fixture extraction")
        if selection.provenance != provenance:
            raise ValueError("candidate selection/fixture build provenance mismatch")
        if boundary_input.provenance != provenance:
            raise ValueError("function boundaries/fixture build provenance mismatch")
        root = extractor.resolve_root(
            args.root,
            function_bounds=function_bounds,
        )
        user_addrs = set(selection.addresses)
        boundary_mismatches = extractor.boundary_mismatches(function_bounds)
        added_symbol_starts = extractor.add_symbol_bound_functions(function_bounds)
        for addr in added_symbol_starts:
            boundary_mismatches.append(
                {
                    "id": extractor._function_id(addr),
                    "address": f"0x{addr:x}",
                    "symbol_size": function_bounds[addr],
                    "radare2_size": 0,
                }
            )
        missing_starts = user_addrs - set(extractor.by_addr)
        if missing_starts:
            missing = ", ".join(f"0x{addr:x}" for addr in sorted(missing_starts))
            raise ValueError(
                "candidate address(es) are not available as function starts "
                f"in stripped binary: {missing}"
            )

        track = normalize_track(getattr(args, "track", DEFAULT_ANALYSIS_TRACK))
        anchor_policy = normalize_anchor_policy(
            getattr(args, "anchor_policy", DEFAULT_ANCHOR_POLICY)
        )
        boundary_mode = "symbol-extent"
        raw_graph = extractor.build_raw_graph(
            case=args.case,
            build=args.build,
            profile=args.profile,
            provenance=provenance,
            boundary_input_sha256=boundary_input_sha256,
            root_address=root.addr,
            function_bounds=function_bounds,
            symbol_only_addresses=set(added_symbol_starts),
            boundary_mode=boundary_mode,
            boundary_mismatches=boundary_mismatches,
        )
        direct_duration = time.perf_counter() - extraction_started
        angr_runtime: dict[str, Any] = {
            "duration_seconds": 0.0,
            "warnings": [],
            "angr_version": None,
        }
        if track == ANGR_TRACK:
            from angr_adapter import augment_raw_graph_with_angr

            raw_graph = augment_raw_graph_with_angr(
                raw_graph,
                binary_path=args.binary,
                runtime=angr_runtime,
            )
        projection_started = time.perf_counter()
        fixture = project_fixture(
            raw_graph,
            selection=selection,
            track=track,
            anchor_policy=anchor_policy,
            users_path=args.users,
            id_bias=args.id_bias,
            score_root=args.score_root,
        )
        projection_duration = time.perf_counter() - projection_started

        return ExtractionArtifacts(
            raw_graph=raw_graph,
            fixture=fixture,
            raw_graph_sha256=raw_graph_sha256(raw_graph),
            execution={
                "duration_seconds": {
                    "direct_extraction": direct_duration,
                    "angr_cfg": angr_runtime["duration_seconds"],
                    "projection": projection_duration,
                },
                "warnings": angr_runtime["warnings"],
                "angr_version": angr_runtime["angr_version"],
            },
        )
    finally:
        extractor.close()


def extract_fixture(args: argparse.Namespace) -> dict[str, Any]:
    return extract_artifacts(args).fixture


def write_fixture(fixture: dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2)
        f.write("\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract a radare2-discovered call graph into this project's "
            "*.fixture.json format."
        )
    )
    parser.add_argument("binary", help="ELF/Rust binary path, or an example stem")
    parser.add_argument(
        "output",
        nargs="?",
        help=(
            "output path. If omitted, direct writes the compatibility path; "
            "other tracks write fixtures/<track>/<profile>/."
        ),
    )
    parser.add_argument(
        "--case",
        default=DEFAULT_CASE,
        help=f"fixture case name. Default: {DEFAULT_CASE}",
    )
    parser.add_argument(
        "--build",
        help=f"build label. Default: {DEFAULT_BUILD}",
    )
    parser.add_argument(
        "--profile",
        choices=BUILD_PROFILES,
        default=DEFAULT_PROFILE,
        help=f"compiler profile. Default: {DEFAULT_PROFILE}",
    )
    parser.add_argument(
        "--track",
        choices=ANALYSIS_TRACKS,
        default=DEFAULT_ANALYSIS_TRACK,
        help=f"analysis track. Default: {DEFAULT_ANALYSIS_TRACK}",
    )
    parser.add_argument(
        "--anchor-policy",
        choices=ANCHOR_POLICIES,
        default=DEFAULT_ANCHOR_POLICY,
        help=f"anchor color policy. Default: {DEFAULT_ANCHOR_POLICY}",
    )
    parser.add_argument(
        "--candidate-scope",
        choices=CANDIDATE_SCOPES,
        default=DEFAULT_CANDIDATE_SCOPE,
        help=f"candidate selection scope. Default: {DEFAULT_CANDIDATE_SCOPE}",
    )
    parser.add_argument(
        "--raw-output",
        help="raw extraction graph output path",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_option",
        help="output path. Positional output is preferred.",
    )
    parser.add_argument(
        "--root",
        help=(
            "root function name/id/address. Use --list-functions to inspect "
            "radare2 function ids. If omitted, tries main/sym.main, Rust "
            "startup wrapper detection, then entry0."
        ),
    )
    parser.add_argument("--users", help="JSON file containing raw user addresses")
    parser.add_argument(
        "--boundaries",
        help="scope-independent function boundary JSON",
    )
    parser.add_argument("--manifest", help="override and verify build manifest path")
    parser.add_argument(
        "--score-root",
        action="store_true",
        help="emit the root as user/scored=true instead of anchor/scored=false",
    )
    parser.add_argument(
        "--include-imports",
        action="store_true",
        help="include radare2 import stubs when direct calls resolve to them",
    )
    parser.add_argument(
        "--id-bias",
        type=parse_int,
        default=DEFAULT_ID_BIAS,
        help=(
            "value added to radare2 raw addresses when formatting FUN_ ids. "
            "Default 0x100000 matches the current Ghidra-style fixture ids; "
            "use 0 for raw radare2 ids."
        ),
    )
    parser.add_argument(
        "--list-functions",
        action="store_true",
        help="print radare2 functions and exit without writing output",
    )
    return parser


def apply_cli_defaults(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.output and args.output_option and args.output != args.output_option:
        parser.error("use either positional output or --output, not both")

    args.output = args.output_option or args.output
    case, build = split_case_build(args.binary, args.build)
    args.profile = normalize_profile(args.profile)
    args.track = normalize_track(args.track)
    args.anchor_policy = normalize_anchor_policy(args.anchor_policy)
    args.candidate_scope = normalize_candidate_scope(args.candidate_scope)

    if not Path(args.binary).exists():
        args.binary = resolve_fixture_binary(case, build, args.profile)

    if not Path(args.binary).exists():
        parser.error(f"binary not found: {args.binary}")

    if args.case == DEFAULT_CASE:
        args.case = case
    args.build = build

    if args.output is None:
        args.output = fixture_json_for(
            args.case,
            build,
            args.profile,
            args.track,
            args.candidate_scope,
            args.anchor_policy,
        )
    if args.raw_output is None:
        args.raw_output = raw_graph_for(
            args.case,
            build,
            args.profile,
            evidence_backend_for_track(args.track),
        )

    default_users = resolve_users_json(
        args.case,
        build,
        args.profile,
        args.candidate_scope,
    )
    if args.users is None and Path(default_users).exists():
        args.users = default_users
    default_boundaries = boundaries_json_for(args.case, build, args.profile)
    if args.boundaries is None and Path(default_boundaries).exists():
        args.boundaries = default_boundaries
    args.manifest = args.manifest or build_manifest_for(args.case, build, args.profile)

    if args.list_functions:
        return


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    apply_cli_defaults(args, parser)

    try:
        if not args.list_functions:
            verified = load_and_verify_manifest(
                args.manifest,
                expected_case=args.case,
                expected_build=args.build,
                expected_profile=args.profile,
                expected_target=BUILD_TARGET,
            )
            if Path(args.binary).resolve() != Path(verified.stripped_binary).resolve():
                raise ValueError(
                    f"binary does not match build manifest: {args.binary!r} != "
                    f"{verified.stripped_binary!r}"
                )
            args.provenance = verified.provenance
        artifacts = extract_artifacts(args)
        if args.list_functions:
            return 0
        write_raw_graph(artifacts.raw_graph, args.raw_output)
        write_fixture(artifacts.fixture, args.output)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {args.output}")
    print(f"raw graph: {args.raw_output}")
    print(f"raw graph SHA-256: {artifacts.raw_graph_sha256}")
    print(f"nodes={len(artifacts.fixture.get('nodes', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
