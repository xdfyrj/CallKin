from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gt_extractor import (
    make_all_rust_catalog,
    normalize_all_rust_origin,
    parse_nm_lines,
    validate_all_rust_catalog,
)
from provenance import BuildProvenance


PROVENANCE = BuildProvenance(
    build_id="catalog-test",
    source_sha256="1" * 64,
    non_stripped_sha256="2" * 64,
    stripped_sha256="3" * 64,
)


def main() -> int:
    symbols = parse_nm_lines([
        "0000000000001000 0000000000000010 t core::ptr::drop_in_place<alloc::string::String>",
        "0000000000001020 0000000000000010 t core::ptr::drop_in_place<billing_client::Invoice>",
        "0000000000001040 0000000000000010 t serde_json::de::parse::<u64>",
        "0000000000001060 0000000000000010 t serde_json::de::parse::<i32>",
        "0000000000001080 0000000000000010 t reconcile::main",
        "00000000000010a0 0000000000000010 t <billing_client::Invoice as core::fmt::Display>::fmt",
        "00000000000010c0 0000000000000010 T main",
    ])
    catalog = make_all_rust_catalog(
        symbols=symbols,
        case="billing-client",
        build="O3S",
        profile="plain",
        root_namespace="reconcile",
        id_bias=0,
        binary_path="gt_bin/plain/billing-client.O3S.gt.bin",
        provenance=PROVENANCE,
    )
    validate_all_rust_catalog(catalog)
    origins = {group["origin"]: group["members"] for group in catalog["origins"]}
    if origins.get("core::ptr::drop_in_place") != ["FUN_00001000", "FUN_00001020"]:
        print(f"FAIL drop_in_place generic family: {origins}")
        return 1
    if origins.get("serde_json::de::parse") != ["FUN_00001040", "FUN_00001060"]:
        print(f"FAIL serde generic family: {origins}")
        return 1
    if any("reconcile::main" == origin for origin in origins):
        print("FAIL source root main entered all-Rust catalog")
        return 1
    if catalog["owners"]["FUN_00001000"] != "core":
        print(f"FAIL core owner: {catalog['owners']}")
        return 1
    expected_impl = "<alloc::vec::Vec as billing_client::LocalTrait>::method"
    actual_impl = normalize_all_rust_origin(
        "<alloc::vec::Vec<T> as billing_client::LocalTrait>::method"
    )
    if actual_impl != expected_impl:
        print(f"FAIL all-Rust impl generic normalization: {actual_impl}")
        return 1

    alias_catalog = make_all_rust_catalog(
        symbols=parse_nm_lines([
            "0000000000002000 0000000000000010 t core::first_origin",
            "0000000000002000 0000000000000010 t std::second_origin",
        ]),
        case="billing-client",
        build="O3S",
        profile="plain",
        root_namespace="reconcile",
        id_bias=0,
        binary_path="gt_bin/plain/billing-client.O3S.gt.bin",
        provenance=PROVENANCE,
    )
    if (
        alias_catalog["origins"] != [{
            "origin": "shared-address@FUN_00002000",
            "members": ["FUN_00002000"],
        }]
        or alias_catalog["cross_origin_aliases"] != [{
            "member": "FUN_00002000",
            "origins": ["core::first_origin", "std::second_origin"],
        }]
    ):
        print(f"FAIL all-Rust cross-origin alias preservation: {alias_catalog}")
        return 1

    print("all-Rust catalog PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
