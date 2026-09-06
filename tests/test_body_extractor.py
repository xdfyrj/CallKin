from __future__ import annotations

import os
import hashlib
import json
import struct
import sys
import tempfile
from collections import Counter
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def make_test_elf(
    payload: bytes,
    *,
    machine: int = 62,
    file_size: int | None = None,
    memory_size: int | None = None,
    segment_type: int = 1,
) -> bytes:
    segment_offset = 0x100
    segment_address = 0x400000
    declared_file_size = len(payload) if file_size is None else file_size
    declared_memory_size = (
        declared_file_size if memory_size is None else memory_size
    )
    identification = bytearray(16)
    identification[:7] = b"\x7fELF\x02\x01\x01"
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(identification),
        2,
        machine,
        1,
        segment_address,
        64,
        0,
        0,
        64,
        56,
        1,
        64,
        0,
        0,
    )
    program_header = struct.pack(
        "<IIQQQQQQ",
        segment_type,
        5,
        segment_offset,
        segment_address,
        segment_address,
        declared_file_size,
        declared_memory_size,
        0x1000,
    )
    padding = b"\x00" * (segment_offset - len(header) - len(program_header))
    return header + program_header + padding + payload


def rejects_value_error(action, label: str) -> int:
    try:
        action()
    except ValueError:
        return 0
    except Exception as exc:
        print(f"FAIL {label} raised {type(exc).__name__}: {exc}")
        return 1
    print(f"FAIL {label} was accepted")
    return 1


def check_decode_nop_ret() -> int:
    try:
        from body_evidence import DecodedInstruction
        from body_extractor import decode_x86_64
    except ImportError as exc:
        print(f"FAIL exact decoder is unavailable: {exc}")
        return 1

    instructions = decode_x86_64(b"\x90\xc3", 0x401000)
    expected = (
        DecodedInstruction(
            offset=0,
            size=1,
            mnemonic="nop",
            operand_text="",
            operand_kinds=(),
            groups=(),
        ),
        DecodedInstruction(
            offset=1,
            size=1,
            mnemonic="ret",
            operand_text="",
            operand_kinds=(),
            groups=("ret", "mode64"),
        ),
    )
    if instructions != expected:
        print(f"FAIL nop/ret exact decode: {instructions!r}")
        return 1

    try:
        instructions[0].size = 2
    except FrozenInstanceError:
        return 0
    print("FAIL decoded instruction evidence is mutable")
    return 1


def check_decode_operand_evidence() -> int:
    from body_extractor import decode_x86_64

    instructions = decode_x86_64(
        bytes.fromhex("48 8b 05 78 56 34 12 48 83 c0 05"),
        0x401000,
    )
    actual = [
        (item.offset, item.operand_text, item.operand_kinds)
        for item in instructions
    ]
    expected = [
        (0, "rax, qword ptr [rip + 0x12345678]", ("register", "memory")),
        (7, "rax, 5", ("register", "immediate")),
    ]
    if actual != expected:
        print(f"FAIL exact operand evidence: {actual!r}")
        return 1
    return 0


def check_undecodable_suffix_is_incomplete() -> int:
    try:
        from body_extractor import build_function_evidence
    except ImportError as exc:
        print(f"FAIL function body builder is unavailable: {exc}")
        return 1

    actual = build_function_evidence(b"\x90\x06", 0x401000, 2)
    expected_core = {
        "id": "FUN_00501000",
        "address": "0x401000",
        "size": 2,
        "byte_sha256": (
            "3c7e464b3ff64f3b3b54cef043c0cfbd8ab05f63d7a46ebfd415546f50c729f3"
        ),
        "instructions": [
            {
                "offset": 0,
                "size": 1,
                "mnemonic": "nop",
                "operand_text": "",
                "operand_kinds": [],
                "groups": [],
            }
        ],
    }
    expected = {
        **expected_core,
        "normalized_instructions": [{
            "offset": 0,
            "size": 1,
            "mnemonic_class": "NOP",
            "operands": [],
            "control_flow": "fallthrough",
            "branch_target_offset": None,
            "slots": [],
            "constants": [],
        }],
        "blocks": [{
            "label": "B0",
            "start_offset": 0,
            "end_offset": 2,
            "instruction_offsets": [0],
        }],
        "cfg_edges": [],
        "summary": {
            "byte_size": 2,
            "instruction_count": 1,
            "decoded_byte_count": 1,
            "block_count": 1,
            "cfg_edge_count": 0,
            "branch_count": 0,
            "callsite_count": 0,
            "unresolved_callsite_count": 0,
            "load_count": 0,
            "store_count": 0,
        },
        "quality": {"complete_decode": False, "opaque_indirect_jumps": 0},
    }
    if actual != expected:
        print(f"FAIL undecodable suffix evidence: {actual!r}")
        return 1
    return 0


def check_normalization_contract() -> int:
    from body_evidence import DecodedInstruction, normalize_instruction

    def decoded(
        mnemonic: str,
        operand_text: str,
        operand_kinds: tuple[str, ...],
        *,
        offset: int = 0,
        size: int = 1,
        groups: tuple[str, ...] = (),
    ) -> DecodedInstruction:
        return DecodedInstruction(
            offset=offset,
            size=size,
            mnemonic=mnemonic,
            operand_text=operand_text,
            operand_kinds=operand_kinds,
            groups=groups,
        )

    first_call = normalize_instruction(
        decoded("call", "0x500000", ("immediate",), size=5, groups=("call",)),
        function_address=0x400000,
    )
    second_call = normalize_instruction(
        decoded("call", "0x600000", ("immediate",), size=5, groups=("call",)),
        function_address=0x400000,
    )
    if first_call.token != second_call.token or first_call.token != "CALL call_target":
        print(f"FAIL direct-call normalization: {first_call.token!r}")
        return 1
    if first_call.slots[0].value is not None or second_call.slots[0].value is not None:
        print("FAIL normalized evidence leaked concrete direct-call targets")
        return 1

    rax = normalize_instruction(decoded("mov", "rax, rbx", ("register", "register")))
    eax = normalize_instruction(decoded("mov", "eax, ebx", ("register", "register")))
    stack = normalize_instruction(
        decoded("mov", "rax, qword ptr [rsp + 0x20]", ("register", "memory"))
    )
    rip = normalize_instruction(
        decoded(
            "mov",
            "rax, qword ptr [rip + 0x12345678]",
            ("register", "memory"),
            size=7,
        ),
        function_address=0x400000,
    )
    if (rax.token, eax.token) != ("MOV reg64 reg64", "MOV reg32 reg32"):
        print(f"FAIL register-width normalization: {rax.token!r}, {eax.token!r}")
        return 1
    xmm = normalize_instruction(decoded(
        "movdqu", "xmm0, xmm1", ("register", "register")
    ))
    ymm = normalize_instruction(decoded(
        "vmovdqu", "ymm0, ymm1", ("register", "register")
    ))
    zmm = normalize_instruction(decoded(
        "vmovdqu64", "zmm0, zmm1", ("register", "register")
    ))
    if (xmm.token, ymm.token, zmm.token) != (
        "MOVDQU reg128 reg128",
        "VMOVDQU reg256 reg256",
        "VMOVDQU64 reg512 reg512",
    ):
        print(
            "FAIL SIMD register-width normalization: "
            f"{xmm.token!r}, {ymm.token!r}, {zmm.token!r}"
        )
        return 1
    if stack.token == rip.token or "ip_data_slot" not in rip.token:
        print(f"FAIL memory-shape normalization: {stack.token!r}, {rip.token!r}")
        return 1
    if not any(slot.kind == "data" for slot in rip.slots):
        print(f"FAIL RIP-relative data slot was lost: {rip.slots!r}")
        return 1

    branch = normalize_instruction(
        decoded(
            "jne",
            "0x400002",
            ("immediate",),
            offset=5,
            size=2,
            groups=("jump",),
        ),
        function_address=0x400000,
        function_size=16,
    )
    if (
        branch.operands != ("local_block_target",)
        or branch.branch_target_offset != 2
        or branch.constants
    ):
        print(f"FAIL internal branch normalization: {branch.to_dict()!r}")
        return 1
    return 0


def check_cfg_contract() -> int:
    from body_evidence import NormalizedInstruction, build_cfg

    def normalized(offset: int, size: int, **kwargs) -> NormalizedInstruction:
        return NormalizedInstruction(
            offset=offset,
            size=size,
            mnemonic_class=kwargs.pop("mnemonic_class", "MOV"),
            operands=kwargs.pop("operands", ()),
            control_flow=kwargs.pop("control_flow", "fallthrough"),
            branch_target_offset=kwargs.pop("branch_target_offset", None),
            slots=(),
            constants=(),
        )

    loop = build_cfg((
        normalized(0, 1),
        normalized(
            1, 2,
            mnemonic_class="JCC",
            operands=("local_block_target",),
            control_flow="conditional_branch",
            branch_target_offset=6,
        ),
        normalized(3, 1),
        normalized(
            4, 2,
            mnemonic_class="JMP",
            operands=("local_block_target",),
            control_flow="local_jump",
            branch_target_offset=0,
        ),
        normalized(6, 1, mnemonic_class="RET", control_flow="return"),
    ), 7)
    edge_set = {(edge.source, edge.target, edge.kind) for edge in loop.edges}
    required_edges = {
        ("B0", "B2", "conditional_target"),
        ("B0", "B1", "fallthrough"),
        ("B1", "B0", "direct_jump"),
    }
    covered = sum(len(block.instruction_offsets) for block in loop.blocks)
    if not required_edges.issubset(edge_set) or covered != 5:
        print(f"FAIL loop CFG construction: edges={edge_set!r}, covered={covered}")
        return 1
    if any(edge.source == "B2" for edge in loop.edges):
        print(f"FAIL returning block has successors: {loop.edges!r}")
        return 1

    opaque = build_cfg((
        normalized(0, 1),
        normalized(
            1, 2,
            mnemonic_class="JMP",
            operands=("opaque_target",),
            control_flow="indirect_jump",
        ),
    ), 3)
    if opaque.opaque_indirect_jumps != 1 or not any(
        edge.target == "OPAQUE" and edge.kind == "opaque_successor"
        for edge in opaque.edges
    ):
        print(f"FAIL opaque indirect-jump CFG: {opaque.to_dict()!r}")
        return 1
    return 0


def check_local_only_normalization_invariances() -> int:
    from body_evidence import DecodedInstruction, normalize_instruction

    def decoded(
        mnemonic: str,
        operand_text: str,
        operand_kinds: tuple[str, ...],
        *,
        offset: int = 0,
        size: int = 1,
        groups: tuple[str, ...] = (),
    ) -> DecodedInstruction:
        return DecodedInstruction(
            offset=offset,
            size=size,
            mnemonic=mnemonic,
            operand_text=operand_text,
            operand_kinds=operand_kinds,
            groups=groups,
        )

    def skeleton(item) -> tuple:
        return (
            item.token,
            item.control_flow,
            item.branch_target_offset,
            tuple(item.constants),
            tuple(
                (slot.kind, slot.value, slot.status)
                for slot in item.slots
                if slot.kind != "call"
            ),
        )

    relocated_bodies = []
    raw_operand_texts = []
    for base in (0x400000, 0x500000):
        instructions = [
            decoded(
                "mov", "rax, qword ptr [rbp - 0x20]", ("register", "memory"),
                offset=0, size=4,
            ),
            decoded(
                "call", f"0x{base + 0x1234:x}", ("immediate",),
                offset=4, size=5, groups=("call",),
            ),
            decoded("cmp", "rax, 10", ("register", "immediate"),
                    offset=9, size=4),
            decoded(
                "jne", f"0x{base + 0x30:x}", ("immediate",),
                offset=13, size=6, groups=("jump",),
            ),
        ]
        relocated_bodies.append(tuple(
            normalize_instruction(
                item,
                function_address=base,
                function_size=0x40,
            )
            for item in instructions
        ))
        raw_operand_texts.append([item.operand_text for item in instructions])

    left, right = relocated_bodies
    if [skeleton(item) for item in left] != [skeleton(item) for item in right]:
        print("FAIL relocation changed the normalized comparison skeleton")
        return 1
    if raw_operand_texts[0] == raw_operand_texts[1]:
        print("FAIL relocation test did not vary raw addresses")
        return 1

    allocation_pairs = (
        (
            ("rax", "qword ptr [rbp - 0x20]"),
            ("rbx", "qword ptr [rsp - 0x20]"),
        ),
        (("rcx", "rsi"), ("rdx", "rdi")),
    )
    for first_operands, second_operands in allocation_pairs:
        kinds = tuple("register" if not item.startswith(("qword",)) else "memory"
                      for item in first_operands)
        first = normalize_instruction(decoded(
            "mov",
            ", ".join(first_operands),
            kinds,
            offset=0,
            size=3,
        ))
        second_kinds = tuple(
            "register" if not item.startswith(("qword",)) else "memory"
            for item in second_operands
        )
        second = normalize_instruction(decoded(
            "mov",
            ", ".join(second_operands),
            second_kinds,
            offset=0,
            size=3,
        ))
        if first.operands != second.operands:
            print(
                "FAIL register allocation changed operand classes: "
                f"{first.operands!r} != {second.operands!r}"
            )
            return 1

    load = normalize_instruction(decoded(
        "mov", "rax, qword ptr [rbp - 0x20]", ("register", "memory"),
        offset=0, size=4,
    ))
    store = normalize_instruction(decoded(
        "mov", "qword ptr [rsp], rax", ("memory", "register"),
        offset=0, size=4,
    ))
    call = normalize_instruction(decoded(
        "call", "0x501000", ("immediate",), offset=0, size=5, groups=("call",)
    ))
    branch = normalize_instruction(decoded(
        "jne", "0x400002", ("immediate",), offset=0, size=2, groups=("jump",)
    ), function_address=0x400000, function_size=16)
    categories = {
        load.control_flow + ":" + ":".join(load.operands),
        store.control_flow + ":" + ":".join(store.operands),
        call.control_flow + ":" + ":".join(call.operands),
        branch.control_flow + ":" + ":".join(branch.operands),
    }
    if len(categories) != 4:
        print(f"FAIL load/store/call/branch categories collapsed: {categories!r}")
        return 1

    reg32 = normalize_instruction(decoded("mov", "eax, ebx", ("register", "register")))
    reg64 = normalize_instruction(decoded("mov", "rax, rbx", ("register", "register")))
    mem32 = normalize_instruction(decoded(
        "mov", "eax, dword ptr [rsp]", ("register", "memory")
    ))
    mem64 = normalize_instruction(decoded(
        "mov", "rax, qword ptr [rsp]", ("register", "memory")
    ))
    widths = {reg32.token, reg64.token, mem32.token, mem64.token}
    if len(widths) != 4:
        print(f"FAIL operand-width evidence collapsed: {widths!r}")
        return 1

    if call.control_flow != "call" or call.branch_target_offset is not None:
        print(f"FAIL external call looked like a branch: {call.to_dict()!r}")
        return 1
    if (
        branch.control_flow != "conditional_branch"
        or branch.branch_target_offset != 2
    ):
        print(f"FAIL internal branch was not preserved: {branch.to_dict()!r}")
        return 1
    return 0


def check_memory_width_without_register_operand() -> int:
    from body_extractor import build_function_evidence

    cases = {
        "byte": bytes.fromhex("fe00"),
        "dword": bytes.fromhex("ff00"),
        "qword": bytes.fromhex("48ff00"),
    }
    tokens = {
        name: build_function_evidence(code, 0x400000, len(code))
        ["normalized_instructions"][0]["operands"][0]
        for name, code in cases.items()
    }
    if len(set(tokens.values())) != len(tokens):
        print(f"FAIL memory operand width was erased: {tokens!r}")
        return 1
    return 0


def check_indirect_call_is_unresolved() -> int:
    from body_extractor import build_function_evidence

    artifact = build_function_evidence(bytes.fromhex("ffd0"), 0x400000, 2)
    instruction = artifact["normalized_instructions"][0]
    if instruction["slots"][0]["status"] != "unresolved":
        print(f"FAIL indirect call status: {instruction!r}")
        return 1
    if artifact["summary"]["unresolved_callsite_count"] != 1:
        print(f"FAIL indirect call count: {artifact['summary']!r}")
        return 1
    return 0


def check_loop_is_conditional_control_flow() -> int:
    from body_extractor import build_function_evidence

    artifact = build_function_evidence(bytes.fromhex("e2fe"), 0x400000, 2)
    instruction = artifact["normalized_instructions"][0]
    if instruction["control_flow"] != "conditional_branch":
        print(f"FAIL loop control-flow classification: {instruction!r}")
        return 1
    if instruction["branch_target_offset"] != 0:
        print(f"FAIL loop target classification: {instruction!r}")
        return 1
    return 0


def check_unknown_operand_kind_is_retained() -> int:
    import body_extractor

    class Operand:
        type = 999

    class Instruction:
        address = 0x400000
        size = 1
        mnemonic = "test"
        op_str = "st(0)"
        operands = (Operand(),)
        groups = ()

        @staticmethod
        def group_name(_: int) -> str:
            return ""

    class Decoder:
        detail = False
        skipdata = True

        @staticmethod
        def disasm(_: bytes, __: int):
            return (Instruction(),)

    with patch.object(body_extractor, "Cs", lambda *_: Decoder()):
        decoded = body_extractor.decode_x86_64(b"\x90", 0x400000)
    if decoded[0].operand_kinds != ("unknown",):
        print(f"FAIL unsupported operand kind was not retained: {decoded!r}")
        return 1
    return 0


def check_raw_instructions_are_unchanged() -> int:
    from body_extractor import build_function_evidence, decode_x86_64

    code = b"\x90\xc3"
    decoded = decode_x86_64(code, 0x401000)
    artifact = build_function_evidence(code, 0x401000, len(code))
    if tuple(artifact["instructions"]) != tuple(
        item.to_dict() for item in decoded
    ):
        print("FAIL F2/F3 changed the F1 raw instruction record")
        return 1
    return 0


def check_elf_extent_mapping() -> int:
    try:
        from body_extractor import read_elf_extent
    except ImportError as exc:
        print(f"FAIL ELF extent reader is unavailable: {exc}")
        return 1

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        binary = root / "mapped.elf"
        binary.write_bytes(make_test_elf(b"\x90\xc3\xaa\xbb"))
        if read_elf_extent(str(binary), 0x400001, 2) != b"\xc3\xaa":
            print("FAIL PT_LOAD virtual address did not map to exact file bytes")
            return 1

        invalid_ranges = (
            (lambda: read_elf_extent(str(binary), 0x400000, 0), "zero extent"),
            (lambda: read_elf_extent(str(binary), 0x400000, -1), "negative extent"),
            (lambda: read_elf_extent(str(binary), 0x3fffff, 1), "unmapped extent"),
            (
                lambda: read_elf_extent(str(binary), 0x400003, 2),
                "cross-boundary extent",
            ),
        )
        for action, label in invalid_ranges:
            if rejects_value_error(action, label):
                return 1

        non_elf = root / "not-elf.bin"
        non_elf.write_bytes(b"not an ELF")
        if rejects_value_error(
            lambda: read_elf_extent(str(non_elf), 0x400000, 1),
            "non-ELF input",
        ):
            return 1

        wrong_machine = root / "i386.elf"
        wrong_machine.write_bytes(make_test_elf(b"\x90", machine=3))
        if rejects_value_error(
            lambda: read_elf_extent(str(wrong_machine), 0x400000, 1),
            "non-x86-64 input",
        ):
            return 1

        non_load = root / "non-load.elf"
        non_load.write_bytes(make_test_elf(b"\x90", segment_type=4))
        if rejects_value_error(
            lambda: read_elf_extent(str(non_load), 0x400000, 1),
            "non-PT_LOAD extent",
        ):
            return 1

        bss_only = root / "bss.elf"
        bss_only.write_bytes(
            make_test_elf(b"\x90", file_size=1, memory_size=2)
        )
        if rejects_value_error(
            lambda: read_elf_extent(str(bss_only), 0x400001, 1),
            "non-file-backed extent",
        ):
            return 1

        truncated = root / "truncated.elf"
        truncated.write_bytes(make_test_elf(b"\x90", file_size=2))
        if rejects_value_error(
            lambda: read_elf_extent(str(truncated), 0x400000, 1),
            "truncated PT_LOAD",
        ):
            return 1
    return 0


def check_ripgrep_read_by_line_extents() -> int:
    from binary_extractor import DEFAULT_ID_BIAS
    from candidate_selection import load_candidate_selection

    root = Path(__file__).resolve().parents[1]
    users_path = (
        root / "users/rust-nonstd/plain/ripgrep-main.O3S.users.json"
    )
    gt_path = (
        root / "ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json"
    )
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    origin = "grep_searcher::searcher::glue::ReadByLine<M,R,S>::run"
    matching = [item for item in gt["origins"] if item["origin"] == origin]
    if len(matching) != 1 or len(matching[0]["members"]) != 30:
        print(f"FAIL pinned ReadByLine origin membership: {matching!r}")
        return 1

    selection = load_candidate_selection(
        str(users_path),
        expected_case="ripgrep-main",
        expected_build="O3S",
        expected_profile="plain",
    )
    sizes = Counter(
        selection.function_bounds[int(member.removeprefix("FUN_"), 16) - DEFAULT_ID_BIAS]
        for member in matching[0]["members"]
    )
    if sizes != Counter({826: 10, 890: 10, 813: 10}):
        print(f"FAIL pinned ReadByLine extents: {sizes!r}")
        return 1
    return 0


def _write_synthetic_inputs(root: Path) -> tuple[Path, Path, Path]:
    from build_manifest import sha256_file
    from graph_evidence import make_raw_graph, write_raw_graph
    from provenance import BuildProvenance

    binary = root / "tiny.fixture.bin"
    binary.write_bytes(make_test_elf(b"\x90\xc3\x90\x06"))
    provenance = BuildProvenance(
        build_id="body-test",
        source_sha256="1" * 64,
        non_stripped_sha256="2" * 64,
        stripped_sha256=sha256_file(binary),
    )
    users = root / "tiny.users.json"
    users.write_text(
        json.dumps(
            {
                "case": "tiny",
                "build": "O3S",
                "profile": "plain",
                "schema_version": 6,
                "provenance": provenance.to_dict(),
                "source": "synthetic test",
                "addresses": ["0x400002", "0x400000"],
                "function_bounds": [
                    {"address": "0x400002", "size": 2},
                    {"address": "0x400000", "size": 2},
                ],
                "scope": "rust-nonstd",
                "root_namespace": "tiny",
                "namespaces": [],
                "excluded_namespaces": ["core", "alloc", "std", "__rustc"],
            }
        ),
        encoding="utf-8",
    )
    raw_path = root / "tiny.raw.json"
    raw = make_raw_graph(
        case="tiny",
        build="O3S",
        profile="plain",
        binary_path=str(binary),
        provenance=provenance,
        boundary_input_sha256="4" * 64,
        root_address=0x400000,
        functions=[
            {
                "address": "0x400000",
                "name": "FUN_00400000",
                "size": 2,
                "boundary_source": "symbol-oracle",
                "discovered_by_radare2": True,
            }
        ],
        transfers=[],
        boundary_mode="symbol-extent",
        boundary_mismatches=[],
    )
    write_raw_graph(raw, str(raw_path))
    return binary, users, raw_path


def check_body_artifact_contract() -> int:
    try:
        from body_evidence import body_evidence_bytes
        from body_extractor import extract_body_evidence
    except ImportError as exc:
        print(f"FAIL body artifact builder is unavailable: {exc}")
        return 1

    with tempfile.TemporaryDirectory() as directory:
        binary, users, raw = _write_synthetic_inputs(Path(directory))
        artifact = extract_body_evidence(
            binary_path=str(binary),
            selection_path=str(users),
            raw_graph_path=str(raw),
            expected_case="tiny",
            expected_build="O3S",
            expected_profile="plain",
        )
        repeated = extract_body_evidence(
            binary_path=str(binary),
            selection_path=str(users),
            raw_graph_path=str(raw),
            expected_case="tiny",
            expected_build="O3S",
            expected_profile="plain",
        )
        addresses = [item["address"] for item in artifact["functions"]]
        if addresses != ["0x400000", "0x400002"]:
            print(f"FAIL body artifact address order/universe: {addresses!r}")
            return 1
        if artifact["functions"][1]["id"] != "FUN_00500002":
            print(f"FAIL DEFAULT_ID_BIAS node ID: {artifact['functions'][1]!r}")
            return 1
        completeness = [
            item["quality"]["complete_decode"]
            for item in artifact["functions"]
        ]
        if completeness != [True, False]:
            print(f"FAIL incomplete body retention: {completeness!r}")
            return 1
        if artifact["provenance"]["stripped_sha256"] != hashlib.sha256(binary.read_bytes()).hexdigest():
            print("FAIL body artifact stripped digest")
            return 1
        users_data = json.loads(users.read_text(encoding="utf-8"))
        expected_users_sha = hashlib.sha256(
            json.dumps(
                users_data,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if artifact["provenance"]["candidate_selection_sha256"] != expected_users_sha:
            print("FAIL body artifact candidate selection digest")
            return 1
        raw_data = json.loads(raw.read_text(encoding="utf-8"))
        expected_raw_sha = hashlib.sha256(
            (json.dumps(raw_data, indent=2, ensure_ascii=False) + "\n").encode(
                "utf-8"
            )
        ).hexdigest()
        if artifact["provenance"]["raw_graph_sha256"] != expected_raw_sha:
            print("FAIL body artifact raw graph digest")
            return 1
        if set(artifact) != {
            "schema_version", "case", "build", "profile", "scope",
            "provenance", "functions",
        } or artifact["schema_version"] != 2 or artifact["scope"] != "rust-nonstd":
            print(f"FAIL body artifact top-level schema: {artifact.keys()!r}")
            return 1
        if set(artifact["functions"][0]) != {
            "id", "address", "size", "byte_sha256", "instructions",
            "normalized_instructions", "cfg_edges", "blocks", "summary", "quality",
        }:
            print("FAIL body artifact function schema")
            return 1
        function = artifact["functions"][0]
        expected_summary_fields = {
            "byte_size", "instruction_count", "decoded_byte_count",
            "block_count", "cfg_edge_count", "branch_count", "callsite_count",
            "unresolved_callsite_count", "load_count", "store_count",
        }
        if set(function["summary"]) != expected_summary_fields:
            print(f"FAIL normalized body summary schema: {function['summary'].keys()!r}")
            return 1
        if not function["normalized_instructions"]:
            print("FAIL normalized instruction evidence is absent")
            return 1
        raw_instruction = function["instructions"][0]
        required_raw = {"offset", "size", "mnemonic", "operand_text", "operand_kinds", "groups"}
        if set(raw_instruction) != required_raw:
            print(f"FAIL F1 raw instruction was changed: {raw_instruction.keys()!r}")
            return 1
        if body_evidence_bytes(artifact) != body_evidence_bytes(repeated):
            print("FAIL body artifact serialization is nondeterministic")
            return 1
        if json.loads(body_evidence_bytes(artifact)) != artifact:
            print("FAIL serialized body artifact does not preserve its content")
            return 1
        from paths import body_evidence_for
        if body_evidence_for("tiny", "O3S", "plain") != (
            "body_evidence/plain/tiny.O3S.body.json"
        ):
            print("FAIL canonical body evidence path")
            return 1
        if body_evidence_for(
            "tiny", "O3S", "plain", "subject"
        ) != "body_evidence/subject/plain/tiny.O3S.body.json":
            print("FAIL candidate scope did not separate body artifact paths")
            return 1
    return 0


def check_binary_hash_mismatch_rejected() -> int:
    from body_extractor import extract_body_evidence

    with tempfile.TemporaryDirectory() as directory:
        binary, users, raw = _write_synthetic_inputs(Path(directory))
        binary.write_bytes(binary.read_bytes() + b"changed")
        return rejects_value_error(
            lambda: extract_body_evidence(
                binary_path=str(binary),
                selection_path=str(users),
                raw_graph_path=str(raw),
                expected_case="tiny",
                expected_build="O3S",
                expected_profile="plain",
            ),
            "stripped SHA mismatch",
        )


def check_mid_extraction_mutation_rejected() -> int:
    import body_extractor

    with tempfile.TemporaryDirectory() as directory:
        binary, users, raw = _write_synthetic_inputs(Path(directory))
        original_reader = body_extractor.read_elf_extent
        mutated = False

        def mutate_then_read(path: str, address: int, size: int) -> bytes:
            nonlocal mutated
            if not mutated:
                content = bytearray(binary.read_bytes())
                content[0x100] = 0xCC
                binary.write_bytes(content)
                mutated = True
            return original_reader(path, address, size)

        with patch.object(body_extractor, "read_elf_extent", mutate_then_read):
            return rejects_value_error(
                lambda: body_extractor.extract_body_evidence(
                    binary_path=str(binary),
                    selection_path=str(users),
                    raw_graph_path=str(raw),
                    expected_case="tiny",
                    expected_build="O3S",
                    expected_profile="plain",
                ),
                "mid-extraction binary mutation",
            )


CHECKS = {
    "decode_nop_ret": check_decode_nop_ret,
    "decode_operand_evidence": check_decode_operand_evidence,
    "normalization_contract": check_normalization_contract,
    "cfg_contract": check_cfg_contract,
    "local_only_invariances": check_local_only_normalization_invariances,
    "memory_width_without_register": check_memory_width_without_register_operand,
    "indirect_call_status": check_indirect_call_is_unresolved,
    "loop_control_flow": check_loop_is_conditional_control_flow,
    "unknown_operand_kind": check_unknown_operand_kind_is_retained,
    "raw_instructions_unchanged": check_raw_instructions_are_unchanged,
    "undecodable_suffix": check_undecodable_suffix_is_incomplete,
    "elf_extent_mapping": check_elf_extent_mapping,
    "ripgrep_read_by_line_extents": check_ripgrep_read_by_line_extents,
    "body_artifact_contract": check_body_artifact_contract,
    "binary_hash_mismatch": check_binary_hash_mismatch_rejected,
    "mid_extraction_mutation": check_mid_extraction_mutation_rejected,
}


def main() -> int:
    requested = sys.argv[1:] or list(CHECKS)
    for name in requested:
        check = CHECKS.get(name)
        if check is None:
            print(f"FAIL unknown body extractor check: {name}")
            return 1
        if check() != 0:
            return 1
    print("body extractor exact decoding PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
