import os
import shutil
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import binary_extractor as binary_extractor_module
from binary_extractor import (
    BinaryExtractor,
    R2Function,
    make_fixture_json,
    select_user_context,
)
from graph_evidence import ELF_RELOCATION_RESOLVER
from function_boundaries import load_function_boundaries
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


def check_rust_startup_lto_full_extent_detection() -> int:
    wrapper_addr = 0x37C40
    rust_main_addr = 0x35440
    trampoline_addr = 0x1D8E0
    lea_offset = 0x450
    symbol_size = 0x54A
    code = bytearray(b"\x90" * symbol_size)

    lea_addr = wrapper_addr + lea_offset
    lea = b"\x48\x8d\x3d" + struct.pack(
        "<i", rust_main_addr - (lea_addr + 7)
    )
    code[lea_offset:lea_offset + len(lea)] = lea

    call_offset = lea_offset + len(lea)
    call_addr = wrapper_addr + call_offset
    call = b"\xe8" + struct.pack(
        "<i", trampoline_addr - (call_addr + 5)
    )
    code[call_offset:call_offset + len(call)] = call

    extractor = BinaryExtractor.__new__(BinaryExtractor)
    extractor.r2 = FakeR2(
        {
            # This models the truncated pdfj output that misses main+0x450.
            f"pdfj @ {wrapper_addr}": {
                "ops": [{"opcode": "push rbp", "type": "push"}],
            },
            f"p8j {symbol_size} @ {wrapper_addr}": list(code),
            f"pdj 8 @ {trampoline_addr}": [
                {"opcode": "push rax", "type": "push"},
                {"opcode": "call rdi", "type": "rcall"},
                {"opcode": "ret", "type": "ret"},
            ],
        }
    )

    detected = extractor._rust_main_from_start_wrapper(
        wrapper_addr,
        symbol_size=symbol_size,
    )
    if detected != rust_main_addr:
        print(
            "FAIL: full C main symbol extent did not reveal the LTO Rust main "
            f"pointer: {detected!r}"
        )
        return 1
    return 0


def check_rust_startup_plain_actual_bytes_detection() -> int:
    wrapper_addr = 0x3CB60
    rust_main_addr = 0x38800
    # Exact 0x27-byte C main extent from plain billing-client.O3S.
    code = bytes.fromhex(
        "50 "
        "48 89 f1 "
        "48 63 d7 "
        "48 8d 05 92 bc ff ff "
        "48 89 04 24 "
        "48 8d 35 0f ed 06 00 "
        "48 89 e7 "
        "45 31 c0 "
        "ff 15 db 1d 07 00 "
        "59 "
        "c3"
    )
    extractor = BinaryExtractor.__new__(BinaryExtractor)
    extractor.r2 = FakeR2({
        f"p8j {len(code)} @ {wrapper_addr}": list(code),
    })

    detected = extractor._rust_main_from_start_wrapper(
        wrapper_addr,
        symbol_size=len(code),
    )
    if detected != rust_main_addr:
        print(
            "FAIL: exact plain C main bytes did not reveal reconcile::main: "
            f"{detected!r}"
        )
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
    if selected != {0x1000, 0x2000, 0x3000, 0x4000}:
        print(
            "FAIL user context should include the complete outgoing closure, "
            f"got {sorted(selected)}"
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
        "FUN_00104000": ("anchor", False),
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
    expected_root_calls = [
        {"target": "FUN_00102000", "count": 1},
        {"target": "FUN_00103000", "count": 1},
    ]
    if nodes["FUN_00101000"]["calls"] != expected_root_calls:
        print(
            "FAIL root anchor should retain every selected outgoing edge, "
            f"got {nodes['FUN_00101000']['calls']}"
        )
        return 1
    expected_anchor_calls = [
        {"target": "FUN_00103000", "count": 7},
        {"target": "FUN_00104000", "count": 1},
    ]
    if nodes["FUN_00103000"]["calls"] != expected_anchor_calls:
        print(
            "FAIL library anchor should retain self and transitive "
            f"library internals, got {nodes['FUN_00103000']['calls']}"
        )
        return 1

    return 0


def check_symbol_bound_function_recovery() -> int:
    extractor = BinaryExtractor.__new__(BinaryExtractor)
    existing = R2Function(addr=0x1000, name="root", size=0x40, kind="fcn")
    extractor.functions = [existing]
    extractor.by_addr = {existing.addr: existing}

    added = extractor.add_symbol_bound_functions({
        0x1000: 0x40,
        0x2000: 0x30,
    })
    if added != [0x2000]:
        print(f"FAIL expected one recovered symbol start, got {added}")
        return 1
    recovered = extractor.by_addr.get(0x2000)
    if (
        recovered is None
        or recovered.size != 0x30
        or recovered.kind != "symbol"
    ):
        print(f"FAIL invalid recovered symbol-bound function: {recovered}")
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


def check_transfer_site_deduplication() -> int:
    transfer = binary_extractor_module.TransferEvidence(
        source=0x1000,
        callsite=0x1010,
        instruction="call 0x2000",
        kind="call",
        operand_kind="immediate",
        status="resolved",
        target=0x2000,
        resolver="direct-immediate",
        confidence="exact",
    )
    got = BinaryExtractor._deduplicate_transfer_sites([transfer, transfer])
    if got != [transfer]:
        print(f"FAIL duplicate radare2 callsite was not normalized: {got}")
        return 1
    conflicting = binary_extractor_module.TransferEvidence(
        source=0x1000,
        callsite=0x1010,
        instruction="call rax",
        kind="call",
        operand_kind="register",
        status="unresolved",
        target=None,
        resolver=None,
        confidence="unknown",
    )
    try:
        BinaryExtractor._deduplicate_transfer_sites([transfer, conflicting])
    except ValueError:
        return 0
    print("FAIL conflicting evidence at one callsite was not rejected")
    return 1


def check_filtered_import_evidence() -> int:
    extractor = BinaryExtractor.__new__(BinaryExtractor)
    caller = R2Function(addr=0x1000, name="caller", size=0x20, kind="fcn")
    imported = R2Function(
        addr=0x3000,
        name="sym.imp.memcpy",
        size=0,
        kind="sym",
    )
    extractor.r2 = FakeR2({
        "pdfj @ 4096": {
            "ops": [{
                "offset": 0x1004,
                "type": "call",
                "opcode": "call 0x3000",
                "jump": 0x3000,
            }],
        },
    })
    extractor.include_imports = False
    extractor.functions = [caller]
    extractor.by_addr = {caller.addr: caller}
    extractor.all_functions = [caller, imported]
    extractor.all_by_addr = {caller.addr: caller, imported.addr: imported}

    transfers = extractor._r2_transfer_evidence(caller)
    if len(transfers) != 1:
        print(f"FAIL expected one filtered import transfer, got {transfers}")
        return 1
    transfer = transfers[0]
    if (
        transfer.status != "filtered"
        or transfer.target != imported.addr
        or transfer.filter_reason != "import"
        or transfer.confidence != "exact"
    ):
        print(f"FAIL import was not recorded as resolved-but-filtered: {transfer}")
        return 1
    return 0


def check_unmapped_immediate_evidence() -> int:
    extractor = BinaryExtractor.__new__(BinaryExtractor)
    caller = R2Function(addr=0x1000, name="caller", size=0x20, kind="fcn")
    extractor.r2 = FakeR2({
        "pdfj @ 4096": {
            "ops": [{
                "offset": 0x1004,
                "type": "call",
                "opcode": "call 0x4000",
                "jump": 0x4000,
            }],
        },
    })
    extractor.include_imports = False
    extractor.functions = [caller]
    extractor.by_addr = {caller.addr: caller}
    extractor.all_functions = [caller]
    extractor.all_by_addr = {caller.addr: caller}

    transfer = extractor._r2_transfer_evidence(caller)[0]
    if (
        transfer.status != "unmapped"
        or transfer.target != 0x4000
        or transfer.resolver != "direct-immediate"
        or transfer.confidence != "exact"
    ):
        print(f"FAIL decoded direct target was reported as unresolved: {transfer}")
        return 1
    return 0


def check_indirect_tail_transfer_recovery() -> int:
    caller = R2Function(addr=0x1000, name="caller", size=0x20, kind="fcn")
    target = R2Function(addr=0x2000, name="target", size=0x20, kind="fcn")
    slot = 0x3000
    displacement = slot - (caller.addr + 6)

    extractor = BinaryExtractor.__new__(BinaryExtractor)
    extractor.include_imports = False
    extractor.relocation_targets = {slot: target.addr}
    extractor.functions = [caller, target]
    extractor.by_addr = {caller.addr: caller, target.addr: target}
    extractor.all_functions = extractor.functions
    extractor.all_by_addr = extractor.by_addr
    extractor.r2 = FakeR2({
        f"p8j 6 @ {caller.addr}": list(
            b"\xff\x25" + struct.pack("<i", displacement)
        ),
    })

    relocation = extractor._symbol_extent_transfer_evidence(caller, 6)
    if (
        len(relocation) != 1
        or relocation[0].kind != "tail-call"
        or relocation[0].operand_kind != "memory"
        or relocation[0].status != "resolved"
        or relocation[0].target != target.addr
        or relocation[0].resolver != ELF_RELOCATION_RESOLVER
    ):
        print(f"FAIL RIP-relative relocation tail-call: {relocation}")
        return 1

    extractor.relocation_targets = {slot: target.addr + 1}
    interior = extractor._symbol_extent_transfer_evidence(caller, 6)
    if (
        len(interior) != 1
        or interior[0].status != "unmapped"
        or interior[0].target != target.addr + 1
        or interior[0].resolver != ELF_RELOCATION_RESOLVER
    ):
        print(f"FAIL relocation target inside function became exact: {interior}")
        return 1

    extractor.r2 = FakeR2({
        f"pdfj @ {caller.addr}": {
            "ops": [{
                "offset": caller.addr,
                "type": "call",
                "opcode": "call qword [rip + 0x10]",
                "ptr": slot,
            }],
        },
    })
    r2_interior = extractor._r2_transfer_evidence(caller)
    if (
        len(r2_interior) != 1
        or r2_interior[0].status != "unmapped"
        or r2_interior[0].target != target.addr + 1
        or r2_interior[0].resolver != ELF_RELOCATION_RESOLVER
    ):
        print(f"FAIL r2 relocation target inside function became exact: {r2_interior}")
        return 1

    extractor.r2 = FakeR2({
        f"p8j 2 @ {caller.addr}": list(b"\xff\xe0"),
    })
    unresolved = extractor._symbol_extent_transfer_evidence(caller, 2)
    if (
        len(unresolved) != 1
        or unresolved[0].kind != "tail-call"
        or unresolved[0].operand_kind != "register"
        or unresolved[0].status != "unresolved"
    ):
        print(f"FAIL unresolved indirect tail-call evidence: {unresolved}")
        return 1

    extractor.r2 = FakeR2({
        f"pdfj @ {caller.addr}": {
            "ops": [{
                "offset": caller.addr,
                "type": "irjmp",
                "opcode": "jmp rax",
            }],
        },
    })
    r2_unresolved = extractor._r2_transfer_evidence(caller)
    if len(r2_unresolved) != 1 or r2_unresolved[0].kind != "tail-call":
        print(f"FAIL radare2 indirect tail-call evidence: {r2_unresolved}")
        return 1

    extractor.r2 = FakeR2({
        f"pdfj @ {caller.addr}": {
            "ops": [{
                "offset": caller.addr,
                "type": "mov",
                "opcode": "mov rax, qword [rip + 0x10]",
                "ptr": slot,
            }],
        },
    })
    ordinary_load = extractor._r2_transfer_evidence(caller)
    if ordinary_load:
        print(f"FAIL ordinary relocation-backed load became transfer: {ordinary_load}")
        return 1
    return 0


def check_billing_expected_relocation() -> int:
    if shutil.which(binary_extractor_module.R2_EXECUTABLE) is None:
        print("billing-client relocation regression SKIP (radare2 not found)")
        return 0

    root = Path(__file__).resolve().parent.parent
    binary = root / "bin/plain/billing-client.O3S.fixture.bin"
    boundaries_path = (
        root / "boundaries/plain/billing-client.O3S.boundaries.json"
    )
    if not binary.exists() or not boundaries_path.exists():
        print("FAIL canonical billing-client relocation artifacts are missing")
        return 1

    boundaries = load_function_boundaries(
        str(boundaries_path),
        expected_case="billing-client",
        expected_build="O3S",
        expected_profile="plain",
    )
    extractor = BinaryExtractor(str(binary))
    try:
        extractor.analyze()
        extractor.add_symbol_bound_functions(boundaries.bounds)
        transfer = extractor.transfer_evidence(
            extractor.by_addr[0x406B0],
            symbol_size=boundaries.bounds[0x406B0],
        )
    finally:
        extractor.close()

    if (
        len(transfer) != 1
        or transfer[0].kind != "tail-call"
        or transfer[0].status != "resolved"
        or transfer[0].target != 0x56410
        or transfer[0].resolver != ELF_RELOCATION_RESOLVER
        or transfer[0].confidence != "exact"
    ):
        print(f"FAIL billing-client 0x406b0 relocation tail-call: {transfer}")
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
    if check_rust_startup_lto_full_extent_detection() != 0:
        return 1
    if check_rust_startup_plain_actual_bytes_detection() != 0:
        return 1

    if check_user_address_mode() != 0:
        return 1
    if check_symbol_bound_function_recovery() != 0:
        return 1
    if check_symbol_extent_call_extraction() != 0:
        return 1
    if check_transfer_site_deduplication() != 0:
        return 1
    if check_filtered_import_evidence() != 0:
        return 1
    if check_unmapped_immediate_evidence() != 0:
        return 1
    if check_indirect_tail_transfer_recovery() != 0:
        return 1
    if check_billing_expected_relocation() != 0:
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
