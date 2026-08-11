from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from angr_adapter import analyze_indirect_calls
from binary_extractor import load_elf_relocation_targets
from graph_evidence import TransferEvidence, make_raw_graph
from provenance import BuildProvenance


ASSEMBLY = r"""
.text

.globl target
.type target, @function
target:
    lea 1(%rdi), %eax
    ret
.size target, .-target

.section .data.rel.ro
.align 8
.globl target_slot
.type target_slot, @object
target_slot:
    .quad target
.size target_slot, .-target_slot

.text
.globl caller
.type caller, @function
caller:
    call *target_slot(%rip)
    ret
.size caller, .-caller

.globl tail_caller
.type tail_caller, @function
tail_caller:
    jmp *target_slot(%rip)
.size tail_caller, .-tail_caller

.globl main
.type main, @function
main:
    xor %edi, %edi
    call caller
    call tail_caller
    ret
.size main, .-main
"""


def _symbol_address(project, name: str) -> tuple[int, int]:
    symbol = project.loader.main_object.get_symbol(name)
    if symbol is None:
        raise RuntimeError(f"missing test symbol: {name}")
    load_bias = (
        project.loader.main_object.mapped_base
        - project.loader.main_object.linked_base
    )
    return symbol.rebased_addr - load_bias, symbol.size


def _indirect_transfer_site(project, caller: int, mnemonic: str) -> int:
    load_bias = (
        project.loader.main_object.mapped_base
        - project.loader.main_object.linked_base
    )
    block = project.factory.block(caller + load_bias)
    for instruction in block.capstone.insns:
        if instruction.mnemonic == mnemonic and "rip" in instruction.op_str:
            return instruction.address - load_bias
    raise RuntimeError(
        f"test binary does not contain the expected indirect {mnemonic}"
    )


def main() -> int:
    if platform.system() != "Linux":
        print("actual angr integration SKIP (Linux ELF test)")
        return 0
    compiler = shutil.which("cc")
    if compiler is None:
        print("actual angr integration SKIP (cc not found)")
        return 0

    try:
        import angr
    except ImportError:
        print("actual angr integration SKIP (angr not installed)")
        return 0

    with tempfile.TemporaryDirectory(prefix="callkin-angr-test-") as directory:
        source = Path(directory) / "indirect.s"
        binary = Path(directory) / "indirect.elf"
        source.write_text(ASSEMBLY, encoding="ascii")
        completed = subprocess.run(
            [
                compiler,
                "-nostdlib",
                "-pie",
                "-Wl,-e,main",
                str(source),
                "-o",
                str(binary),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            print(f"FAIL building actual angr fixture: {completed.stderr.strip()}")
            return 1

        project = angr.Project(str(binary), auto_load_libs=False)
        target, target_size = _symbol_address(project, "target")
        target_slot, _target_slot_size = _symbol_address(project, "target_slot")
        caller, caller_size = _symbol_address(project, "caller")
        tail_caller, tail_caller_size = _symbol_address(project, "tail_caller")
        root, root_size = _symbol_address(project, "main")
        callsite = _indirect_transfer_site(project, caller, "call")
        tail_callsite = _indirect_transfer_site(project, tail_caller, "jmp")
        relocation_targets = load_elf_relocation_targets(str(binary))
        if relocation_targets.get(target_slot) != target:
            print(
                "FAIL actual ELF relocation resolution: "
                f"slot=0x{target_slot:x}, expected=0x{target:x}, "
                f"got={relocation_targets.get(target_slot)!r}"
            )
            return 1

        provenance = BuildProvenance(
            build_id="actual-angr-test",
            source_sha256="1" * 64,
            non_stripped_sha256="2" * 64,
            stripped_sha256="3" * 64,
        )
        raw = make_raw_graph(
            case="actual-angr-test",
            build="O3S",
            profile="plain",
            binary_path=str(binary),
            provenance=provenance,
            boundary_input_sha256="4" * 64,
            root_address=root,
            functions=[
                {
                    "address": f"0x{address:x}",
                    "name": name,
                    "size": size,
                    "boundary_source": "symbol-oracle",
                    "discovered_by_radare2": True,
                }
                for name, address, size in (
                    ("target", target, target_size),
                    ("caller", caller, caller_size),
                    ("tail_caller", tail_caller, tail_caller_size),
                    ("main", root, root_size),
                )
            ],
            transfers=[
                TransferEvidence(
                    source=caller,
                    callsite=callsite,
                    instruction="call qword ptr [rip + target_slot]",
                    kind="call",
                    operand_kind="memory",
                    status="unresolved",
                    target=None,
                    resolver=None,
                    confidence="unknown",
                ),
                TransferEvidence(
                    source=tail_caller,
                    callsite=tail_callsite,
                    instruction="jmp qword ptr [rip + target_slot]",
                    kind="tail-call",
                    operand_kind="memory",
                    status="unresolved",
                    target=None,
                    resolver=None,
                    confidence="unknown",
                ),
            ],
            boundary_mode="symbol-extent",
            boundary_mismatches=[],
        )

        resolutions, version = analyze_indirect_calls(str(binary), raw)
        actual = {
            (resolution.source, resolution.callsite): resolution.targets
            for resolution in resolutions
        }
        expected = {
            (caller, callsite): (target,),
            (tail_caller, tail_callsite): (target,),
        }
        if actual != expected:
            print(
                "FAIL actual angr singleton call/tail-call resolution: "
                f"expected {expected}, got {actual}"
            )
            return 1

    print(f"actual angr indirect-call integration PASS (angr {version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
