import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import binary_extractor as binary_extractor_module
from binary_extractor import (
    BinaryExtractor,
    R2Function,
    make_fixture_json,
    select_user_context,
)
from provenance import BuildProvenance


PROVENANCE = BuildProvenance(
    build_id="test-build",
    source_sha256="1" * 64,
    non_stripped_sha256="2" * 64,
    stripped_sha256="3" * 64,
)


class FakeR2:
    def __init__(self, responses):
        self.responses = responses

    def cmdj(self, command):
        return self.responses[command]


def check_missing_radare2_error() -> int:
    original_which = binary_extractor_module.shutil.which
    binary_extractor_module.shutil.which = lambda _name: None

    try:
        try:
            binary_extractor_module.ensure_radare2_available()
        except RuntimeError as exc:
            message = str(exc)
            if "radare2" not in message or "binary_extractor.py" not in message:
                print(f"FAIL missing radare2 message is not actionable: {message}")
                return 1
            return 0

        print("FAIL missing radare2 executable was not rejected")
        return 1
    finally:
        binary_extractor_module.shutil.which = original_which


def check_rust_startup_main_detection() -> int:
    extractor = BinaryExtractor.__new__(BinaryExtractor)
    extractor.r2 = FakeR2(
        {
            "pdfj @ 4096": {
                "ops": [
                    {
                        "opcode": "lea rdi, [rip + 0xe81]",
                        "disasm": "lea rdi, [0x00014bd0]",
                        "ptr": 0x14BD0,
                    },
                    {
                        "opcode": "call qword [rip + 0x4175b]",
                        "disasm": "call qword [reloc.__libc_start_main]",
                    },
                ]
            },
            "pdj 64 @ 84944": [
                {"opcode": "push rax", "type": "rpush"},
                {
                    "opcode": "lea rax, [rip - 0xbbe]",
                    "disasm": "lea rax, [rip - 0xbbe]",
                    "ptr": 0x14020,
                },
                {"opcode": "mov qword [rsp], rax", "type": "mov"},
                {"opcode": "call qword [rip + 0x4091b]", "type": "ircall"},
                {"opcode": "ret", "type": "ret"},
            ],
            "pdfj @ 84944": {},
        }
    )

    entry = R2Function(addr=0x1000, name="entry0", size=0x40, kind="fcn")

    wrapper_addr = extractor._libc_start_main_wrapper_addr(entry)
    if wrapper_addr != 0x14BD0:
        print("FAIL: __libc_start_main first argument wrapper was not detected")
        return 1

    rust_main_addr = extractor._rust_main_from_start_wrapper(wrapper_addr)
    if rust_main_addr != 0x14020:
        print("FAIL: Rust startup wrapper first main argument was not detected")
        return 1

    return 0


def check_rust_startup_rdi_tail_detection() -> int:
    extractor = BinaryExtractor.__new__(BinaryExtractor)
    extractor.r2 = FakeR2(
        {
            "pdj 64 @ 84928": [
                {"opcode": "mov rdx, rsi", "type": "mov"},
                {
                    "opcode": "lea rdi, [rip - 0xb8d]",
                    "disasm": "lea rdi, [0x00014040]",
                    "ptr": 0x14040,
                    "type": "lea",
                },
                {"opcode": "xor ecx, ecx", "type": "xor"},
                {"opcode": "jmp 0x14be0", "jump": 0x14BE0, "type": "jmp"},
            ],
            "pdfj @ 84928": {},
        }
    )

    rust_main_addr = extractor._rust_main_from_start_wrapper(0x14BC0)
    if rust_main_addr != 0x14040:
        print("FAIL: rdi/tail-call Rust main argument was not detected")
        return 1

    return 0


def check_rust_startup_lto_trampoline_detection() -> int:
    extractor = BinaryExtractor.__new__(BinaryExtractor)
    extractor.r2 = FakeR2(
        {
            "pdfj @ 61696": {
                "ops": [
                    {
                        "opcode": "lea rdi, [rip - 0xfe0]",
                        "ptr": 0xE570,
                        "type": "lea",
                    },
                    {
                        "opcode": "call 0xf0f0",
                        "jump": 0xF0F0,
                        "type": "call",
                    },
                ],
            },
            "pdj 8 @ 61680": [
                {"opcode": "push rax", "type": "push"},
                {"opcode": "call rdi", "type": "rcall"},
                {"opcode": "ret", "type": "ret"},
            ],
        }
    )

    rust_main_addr = extractor._rust_main_from_start_wrapper(0xF100)
    if rust_main_addr != 0xE570:
        print("FAIL: LTO inlined startup trampoline did not reveal Rust main")
        return 1

    return 0


def check_user_address_mode() -> int:
    functions = {
        0x1000: R2Function(addr=0x1000, name="real_main", size=0x40, kind="fcn"),
        0x2000: R2Function(addr=0x2000, name="user_fn", size=0x20, kind="fcn"),
        0x3000: R2Function(addr=0x3000, name="library_fn", size=0x20, kind="fcn"),
        0x4000: R2Function(addr=0x4000, name="library_internal", size=0x20, kind="fcn"),
    }
    graph = {
        0x1000: Counter({0x2000: 1, 0x3000: 1}),
        0x2000: Counter({0x3000: 2}),
        0x3000: Counter({0x3000: 7, 0x4000: 1}),
        0x4000: Counter(),
    }
    selected = select_user_context(
        graph,
        root_addr=0x1000,
        user_addrs={0x2000},
        allowed_addrs=set(functions),
        score_root=False,
    )
    if selected != {0x1000, 0x2000, 0x3000}:
        print(
            "FAIL user context should include root, users, and direct "
            f"user callees only, got {sorted(selected)}"
        )
        return 1

    disconnected_selected = select_user_context(
        graph,
        root_addr=0x1000,
        user_addrs={0x2000, 0x4000},
        allowed_addrs=set(functions),
        score_root=False,
    )
    if disconnected_selected != {0x1000, 0x2000, 0x3000, 0x4000}:
        print(
            "FAIL listed users must remain authoritative when root reachability "
            f"is incomplete, got {sorted(disconnected_selected)}"
        )
        return 1

    fixture = make_fixture_json(
        case="fg-test",
        build="O3S",
        profile="plain",
        binary_path="bin/test.bin",
        root=functions[0x1000],
        functions=functions,
        graph=graph,
        selected=selected,
        score_root=False,
        user_addrs={0x2000},
        users_path="users/test.users.json",
        id_bias=0x100000,
        provenance=PROVENANCE,
    )

    nodes = {node["id"]: node for node in fixture["nodes"]}
    expected_types = {
        "FUN_00101000": ("anchor", False),
        "FUN_00102000": ("user", True),
        "FUN_00103000": ("anchor", False),
    }
    actual_types = {
        node_id: (node["type"], node["scored"])
        for node_id, node in nodes.items()
    }
    if actual_types != expected_types:
        print(f"FAIL expected user mode {expected_types}, got {actual_types}")
        return 1

    expected_user_calls = [{"target": "FUN_00103000", "count": 2}]
    if nodes["FUN_00102000"]["calls"] != expected_user_calls:
        print(
            "FAIL listed user node should retain edges to emitted "
            f"anchors, got {nodes['FUN_00102000']['calls']}"
        )
        return 1
    expected_root_calls = [{"target": "FUN_00102000", "count": 1}]
    if nodes["FUN_00101000"]["calls"] != expected_root_calls:
        print(
            "FAIL root anchor should retain only edges to listed users, "
            f"got {nodes['FUN_00101000']['calls']}"
        )
        return 1
    if nodes["FUN_00103000"]["calls"] != []:
        print(
            "FAIL one-hop library anchor should not retain self or transitive "
            f"library internals, got {nodes['FUN_00103000']['calls']}"
        )
        return 1

    return 0


def check_symbol_extent_call_extraction() -> int:
    extractor = BinaryExtractor.__new__(BinaryExtractor)
    extractor.r2 = FakeR2({
        "p8j 32 @ 4096": [
            0xE8, 0xFB, 0x0F, 0x00, 0x00,
            *([0x90] * 11),
            0xE8, 0xEB, 0x0F, 0x00, 0x00,
            *([0x90] * 11),
        ],
    })
    extractor.include_imports = False
    extractor.id_bias = 0x100000
    extractor._call_cache = {}
    caller = R2Function(addr=0x1000, name="truncated_main", size=0x10, kind="fcn")
    callee = R2Function(addr=0x2000, name="user_fn", size=0x20, kind="fcn")
    extractor.functions = [caller, callee]
    extractor.by_addr = {caller.addr: caller, callee.addr: callee}

    calls = extractor.direct_calls(caller, symbol_size=0x20)
    if calls != Counter({0x2000: 2}):
        print(f"FAIL symbol extent should recover calls after r2 boundary, got {calls}")
        return 1

    mismatches = extractor.boundary_mismatches({0x1000: 0x20})
    expected = [{
        "id": "FUN_00101000",
        "address": "0x1000",
        "symbol_size": 0x20,
        "radare2_size": 0x10,
    }]
    if mismatches != expected:
        print(f"FAIL expected boundary mismatch {expected}, got {mismatches}")
        return 1
    return 0


def main() -> int:
    if check_missing_radare2_error() != 0:
        return 1

    if check_rust_startup_main_detection() != 0:
        return 1
    if check_rust_startup_rdi_tail_detection() != 0:
        return 1
    if check_rust_startup_lto_trampoline_detection() != 0:
        return 1

    if check_user_address_mode() != 0:
        return 1
    if check_symbol_extent_call_extraction() != 0:
        return 1

    extractor = BinaryExtractor.__new__(BinaryExtractor)
    extractor.include_imports = False
    extractor.by_addr = {
        0x1000: R2Function(addr=0x1000, name="caller", size=0x40, kind="fcn"),
        0x2000: R2Function(addr=0x2000, name="callee", size=0x20, kind="fcn"),
        0x4D6B3: R2Function(addr=0x4D6B3, name="oversized_lib", size=0xDA9E, kind="fcn"),
    }

    caller = extractor.by_addr[0x1000]

    tail = extractor._direct_call_target(
        caller,
        {"type": "jmp", "opcode": "jmp 0x2000", "jump": 0x2000},
    )
    if tail != extractor.by_addr[0x2000]:
        print("FAIL: unconditional jmp to another function start must count as tail call")
        return 1

    internal_branch = extractor._direct_call_target(
        caller,
        {"type": "jmp", "opcode": "jmp 0x1010", "jump": 0x1010},
    )
    if internal_branch is not None:
        print("FAIL: jmp inside current function must not count as call edge")
        return 1

    conditional_branch = extractor._direct_call_target(
        caller,
        {"type": "cjmp", "opcode": "jne 0x2000", "jump": 0x2000},
    )
    if conditional_branch is not None:
        print("FAIL: conditional jump must not count as tail call")
        return 1

    indirect_memory_call = extractor._direct_call_target(
        caller,
        {
            "type": "ircall",
            "opcode": "call qword [rip + 0x4168c]",
            "ptr": 0x55FC0,
        },
    )
    if indirect_memory_call is not None:
        print("FAIL: indirect memory call ptr must not be treated as callee")
        return 1

    print("binary extractor startup/tail-call handling PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
