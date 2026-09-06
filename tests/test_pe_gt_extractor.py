import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pe_gt_extractor import (
    PdbProcedure,
    anonymous_groups_json,
    anonymous_functions_json,
    collect_functions,
    parse_llvm_pdb_symbols,
    parse_pdb_summary,
    verify_codeview_identity,
)


def main():
    pdb_text = """
100 | S_GPROC32 [size = 44] `demo::parse::<i32>`
      parent = 0, end = 196, addr = 0001:0032, code size = 16
200 | S_LPROC32_ID [size = 44] `demo::parse::<u64>`
      parent = 0, end = 296, addr = 0001:0064, code size = 16
250 | S_LPROC32 [size = 44] `demo::parse<bool>`
      parent = 0, end = 346, addr = 0001:0080, code size = 16
300 | S_GPROC32 [size = 44] `core::fmt::write`
      parent = 0, end = 396, addr = 0001:0096, code size = 16
400 | S_GPROC32 [size = 44] `demo::single::<bool>`
      parent = 0, end = 496, addr = 0001:0128, code size = 16
500 | S_GPROC32 [size = 44] `demo::duplicated`
      parent = 0, end = 596, addr = 0001:0160, code size = 16
600 | S_GPROC32 [size = 44] `demo::duplicated`
      parent = 0, end = 696, addr = 0001:0192, code size = 16
"""
    procedures = parse_llvm_pdb_symbols(pdb_text, {1: 0x1000})
    assert [(p.section, p.offset, p.size) for p in procedures] == [
        (1, 0x20, 16),
        (1, 0x40, 16),
        (1, 0x50, 16),
        (1, 0x60, 16),
        (1, 0x80, 16),
        (1, 0xA0, 16),
        (1, 0xC0, 16),
    ]

    records = collect_functions(
        procedures,
        {1: 0x1000},
        [(0x1000, 0x2000)],
        candidate_scope="rust-nonstd",
        root_namespace="demo",
    )
    selected = [record for record in records if record.selected]
    assert [record.member_id for record in selected] == [
        "FUN_00001020",
        "FUN_00001040",
        "FUN_00001050",
        "FUN_00001080",
        "FUN_000010a0",
        "FUN_000010c0",
    ]
    assert [record.origin for record in selected] == [
        "demo::parse",
        "demo::parse",
        "demo::parse",
        "demo::single",
        "demo::duplicated",
        "demo::duplicated",
    ]

    functions = anonymous_functions_json(
        stripped_binary_sha256="0" * 64,
        records=records,
    )
    serialized_functions = json.dumps(functions)
    assert "demo" not in serialized_functions
    assert "core" not in serialized_functions
    assert "origin" not in serialized_functions
    assert {item["role"] for item in functions["functions"]} == {"target", "context"}

    groups = anonymous_groups_json(
        binary_sha256="0" * 64,
        records=records,
    )
    serialized = json.dumps(groups)
    assert '"case"' not in serialized
    assert "demo" not in serialized
    assert "core" not in serialized
    assert groups["groups"] == [
        {
            "group": "G0001",
            "members": ["FUN_00001020", "FUN_00001040", "FUN_00001050"],
        }
    ]

    summary = parse_pdb_summary(
        "Age: 1\nGUID: {0B355641-86A0-A249-896F-9988FAE52FF0}\n"
    )
    assert summary == {
        "age": 1,
        "guid": "0b355641-86a0-a249-896f-9988fae52ff0",
    }
    assert verify_codeview_identity(
        {"codeview": [summary]}, summary
    ) == summary
    try:
        verify_codeview_identity(
            {"codeview": [{"guid": summary["guid"], "age": 2}]}, summary
        )
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched CodeView Age was accepted")
    print("test_pe_gt_extractor: PASS")


if __name__ == "__main__":
    main()
