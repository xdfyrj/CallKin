from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from build_manifest import BUILD_TARGET, load_and_verify_manifest
from paths import (
    BUILD_PROFILES,
    DEFAULT_BUILD,
    DEFAULT_PROFILE,
    build_manifest_for,
    fixture_json_for,
    normalize_profile,
    resolve_fixture_binary,
    resolve_users_json,
    split_case_build,
)
from provenance import BuildProvenance, parse_provenance


SCHEMA_VERSION = 4
USERS_SCHEMA_VERSION = 4
DEFAULT_ID_BIAS = 0x100000
DEFAULT_CASE = "unknown"
R2_EXECUTABLE = "radare2"


@dataclass(frozen=True)
class R2Function:
    addr: int
    name: str
    size: int
    kind: str


@dataclass(frozen=True)
class UserSelection:
    addresses: set[int]
    function_bounds: dict[int, int]
    provenance: BuildProvenance


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


def load_users(
    path: str,
    *,
    expected_case: str,
    expected_build: str,
    expected_profile: str,
) -> UserSelection:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict) or not isinstance(data.get("addresses"), list):
        raise ValueError("user address file must be an object with an addresses list")
    if not isinstance(data.get("function_bounds"), list):
        raise ValueError("user address file must contain a function_bounds list")
    if data.get("schema_version") != USERS_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported user address schema_version: {data.get('schema_version')!r}"
        )
    for key, expected in (
        ("case", expected_case),
        ("build", expected_build),
        ("profile", expected_profile),
    ):
        if data.get(key) != expected:
            raise ValueError(
                f"user address {key} mismatch: expected {expected!r}, "
                f"got {data.get(key)!r}"
            )
    raw_addresses = data["addresses"]

    addresses: set[int] = set()
    for value in raw_addresses:
        if isinstance(value, int):
            addresses.add(value)
        elif isinstance(value, str):
            addresses.add(int(value, 0))
        else:
            raise ValueError(f"invalid user address: {value!r}")

    function_bounds: dict[int, int] = {}
    for index, item in enumerate(data["function_bounds"]):
        if not isinstance(item, dict) or set(item) != {"address", "size"}:
            raise ValueError(
                f"function_bounds[{index}] must contain exactly address/size"
            )
        address_value = item["address"]
        if isinstance(address_value, int):
            address = address_value
        elif isinstance(address_value, str):
            address = int(address_value, 0)
        else:
            raise ValueError(f"invalid function bound address: {address_value!r}")
        size = item["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError(f"invalid function bound size at 0x{address:x}: {size!r}")
        if address in function_bounds:
            raise ValueError(f"duplicate function bound address: 0x{address:x}")
        function_bounds[address] = size

    missing_bounds = addresses - set(function_bounds)
    if missing_bounds:
        missing = ", ".join(f"0x{addr:x}" for addr in sorted(missing_bounds))
        raise ValueError(f"listed user address(es) have no symbol extent: {missing}")

    provenance = parse_provenance(data.get("provenance"), where="users.provenance")
    return UserSelection(
        addresses=addresses,
        function_bounds=function_bounds,
        provenance=provenance,
    )


def is_probably_import(func: R2Function) -> bool:
    return func.name.startswith("sym.imp.") or func.kind == "sym"


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
        self._call_cache: dict[tuple[int, int | None], Counter[int]] = {}

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

        functions: list[R2Function] = []
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
            if not self.include_imports and is_probably_import(func):
                continue
            functions.append(func)

        functions.sort(key=lambda f: f.addr)
        self.functions = functions
        self.by_addr = {f.addr: f for f in functions}
        self._call_cache.clear()

    def list_functions(self) -> None:
        for func in self.functions:
            print(f"{self._function_id(func.addr)}  raw={func.addr:#x}  {func.name}  size={func.size}")

    def resolve_root(self, root: str | None) -> R2Function:
        if root:
            resolved = self._resolve_function_spec(root)
            if resolved is None:
                raise ValueError(f"cannot resolve root function: {root}")
            return resolved

        entry_root = self._root_from_libc_start_main()
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

    def _root_from_libc_start_main(self) -> R2Function | None:
        entry = self._resolve_function_spec("entry0")
        if entry is None:
            return None

        wrapper_addr = self._libc_start_main_wrapper_addr(entry)
        if wrapper_addr is None:
            return None

        self._ensure_function_at(wrapper_addr)
        rust_main_addr = self._rust_main_from_start_wrapper(wrapper_addr)
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

    def _rust_main_from_start_wrapper(self, wrapper_addr: int) -> int | None:
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
                break

        return None

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
        if symbol_size is None:
            pdf = self.r2.cmdj(f"pdfj @ {func.addr}") or {}
            ops = pdf.get("ops") or []
            for op in ops:
                target_func = self._direct_call_target(func, op)
                if target_func is None:
                    continue
                if not self.include_imports and is_probably_import(target_func):
                    continue
                counts[target_func.addr] += 1
        else:
            counts = self._direct_calls_from_symbol_extent(func, symbol_size)

        self._call_cache[cache_key] = counts.copy()
        return counts

    def _direct_calls_from_symbol_extent(
        self,
        func: R2Function,
        size: int,
    ) -> Counter[int]:
        try:
            from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_MODE_64, Cs
            from capstone.x86_const import X86_OP_IMM
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
        counts: Counter[int] = Counter()

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
            if len(instruction.operands) != 1:
                continue
            operand = instruction.operands[0]
            if operand.type != X86_OP_IMM:
                continue

            target_func = self._resolve_direct_target(
                func,
                int(operand.imm),
                is_call=is_call,
                is_tail_jump=is_tail_jump,
            )
            if target_func is None:
                continue
            if not self.include_imports and is_probably_import(target_func):
                continue
            counts[target_func.addr] += 1

        if expected != end:
            raise ValueError(
                f"incomplete symbol-extent decode for 0x{func.addr:x}: "
                f"expected end 0x{end:x}, got 0x{expected:x}"
            )
        return counts

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
    ) -> R2Function | None:
        target = self._direct_code_target(op)
        if target is None:
            return None

        return self._resolve_direct_target(
            current_func,
            target,
            is_call=self._is_call_op(op),
            is_tail_jump=self._is_tail_call_jump_op(op),
        )

    def _resolve_direct_target(
        self,
        current_func: R2Function,
        target: int,
        *,
        is_call: bool,
        is_tail_jump: bool,
    ) -> R2Function | None:

        if is_call:
            return self.function_containing(target)

        if is_tail_jump:
            # O3 often lowers `call f; ret` to `jmp f`.
            # Count it only when the jump target is exactly another function's
            # start address. This avoids ordinary in-function branches and most
            # switch/case labels that radare2 may expose as pseudo-functions.
            target_func = self.by_addr.get(target)
            if target_func is not None and target_func.addr != current_func.addr:
                return target_func

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
            return value
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

    The normal workflow does not chase library/runtime internals.
    It emits:
      - the root anchor,
      - all listed user functions,
      - direct callees of listed user functions as one-hop anchors.

    If --score-root is used, root is treated as a user context source too.
    """
    selected = {root_addr} | set(user_addrs)
    context_sources = set(user_addrs)
    if score_root:
        context_sources.add(root_addr)

    for src in context_sources:
        for target in graph.get(src, {}):
            if target in allowed_addrs:
                selected.add(target)

    return selected & allowed_addrs


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
            allowed_targets = selected
        else:
            node_type = "user" if addr in user_addrs or (score_root and is_root) else "anchor"
            if node_type == "user":
                allowed_targets = selected
            elif is_root:
                allowed_targets = user_addrs
            else:
                allowed_targets = set()

        calls = [
            {"target": function_id(target, id_bias=id_bias), "count": count}
            for target, count in sorted(graph.get(addr, {}).items())
            if target in allowed_targets and count > 0
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
        "user mode emits root plus listed users plus direct callees "
        "of listed users only; "
        "root anchor retains edges to listed users; "
        "non-root anchors are terminal/scored=false; "
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


def extract_fixture(args: argparse.Namespace) -> dict[str, Any]:
    extractor = BinaryExtractor(
        args.binary,
        include_imports=args.include_imports,
        id_bias=args.id_bias,
    )
    try:
        extractor.analyze()

        if args.list_functions:
            extractor.list_functions()
            return {}

        user_selection = (
            load_users(
                args.users,
                expected_case=args.case,
                expected_build=args.build,
                expected_profile=args.profile,
            )
            if args.users
            else None
        )
        root = extractor.resolve_root(args.root)
        user_addrs = user_selection.addresses if user_selection is not None else None
        function_bounds = (
            user_selection.function_bounds if user_selection is not None else {}
        )
        graph = extractor.build_call_graph(function_bounds=function_bounds)
        boundary_mismatches = extractor.boundary_mismatches(function_bounds)
        provenance = getattr(args, "provenance", None)
        if provenance is None:
            raise ValueError("verified build provenance is required for fixture extraction")
        if user_selection is not None and user_selection.provenance != provenance:
            raise ValueError("users/fixture build provenance mismatch")

        if user_addrs is not None:
            missing_starts = user_addrs - set(extractor.by_addr)
            if missing_starts:
                missing = ", ".join(f"0x{addr:x}" for addr in sorted(missing_starts))
                raise ValueError(
                    "user address(es) are not radare2 function starts "
                    f"in stripped binary: {missing}"
                )

            selected = select_user_context(
                graph,
                root.addr,
                user_addrs,
                allowed_addrs=set(extractor.by_addr),
                score_root=args.score_root,
            )
        else:
            selected = select_reachable(graph, root.addr)

        return make_fixture_json(
            case=args.case,
            build=args.build,
            profile=args.profile,
            binary_path=args.binary,
            root=root,
            functions=extractor.by_addr,
            graph=graph,
            selected=selected,
            score_root=args.score_root,
            user_addrs=user_addrs,
            users_path=args.users,
            id_bias=args.id_bias,
            boundary_mode="symbol-extent" if user_selection is not None else "radare2",
            boundary_mismatches=boundary_mismatches,
            provenance=provenance,
        )
    finally:
        extractor.close()


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
            "output path. If omitted, writes "
            "fixtures/<profile>/<case>.<build>.fixture.json."
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

    if not Path(args.binary).exists():
        args.binary = resolve_fixture_binary(case, build, args.profile)

    if not Path(args.binary).exists():
        parser.error(f"binary not found: {args.binary}")

    if args.case == DEFAULT_CASE:
        args.case = case
    args.build = build

    if args.output is None:
        args.output = fixture_json_for(args.case, build, args.profile)

    default_users = resolve_users_json(args.case, build, args.profile)
    if args.users is None and Path(default_users).exists():
        args.users = default_users
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
        fixture = extract_fixture(args)
        if args.list_functions:
            return 0
        write_fixture(fixture, args.output)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {args.output}")
    print(f"nodes={len(fixture.get('nodes', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
