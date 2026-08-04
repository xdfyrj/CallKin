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
target_slot:
    .quad target

.text
.globl caller
.type caller, @function
caller:
    call *target_slot(%rip)
    ret
.size caller, .-caller

.globl main
.type main, @function
main:
    xor %edi, %edi
    call caller
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


def _indirect_callsite(project, caller: int) -> int:
    load_bias = (
        project.loader.main_object.mapped_base
        - project.loader.main_object.linked_base
    )
    block = project.factory.block(caller + load_bias)
    for instruction in block.capstone.insns:
        if instruction.mnemonic == "call" and "rip" in instruction.op_str:
            return instruction.address - load_bias
    raise RuntimeError("test binary does not contain the expected indirect call")


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
                "-no-pie",
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
        caller, caller_size = _symbol_address(project, "caller")
        root, root_size = _symbol_address(project, "main")
        callsite = _indirect_callsite(project, caller)

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
                )
            ],
            boundary_mode="symbol-extent",
            boundary_mismatches=[],
        )

        resolutions, version = analyze_indirect_calls(str(binary), raw)
        actual = {
            resolution.targets
            for resolution in resolutions
            if resolution.source == caller and resolution.callsite == callsite
        }
        if actual != {(target,)}:
            print(
                "FAIL actual angr singleton resolution: "
                f"expected {(target,)}, got {sorted(actual)}"
            )
            return 1

    print(f"actual angr indirect-call integration PASS (angr {version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
