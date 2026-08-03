import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gt_extractor import (
    is_rust_nonstd_candidate,
    make_ground_truth,
    make_function_boundaries_json,
    make_users_json,
    parse_nm_lines,
    rust_function_bounds,
    user_addresses,
    user_function_bounds,
)
from candidate_selection import parse_candidate_selection
from function_boundaries import parse_function_boundaries
from provenance import BuildProvenance


PROVENANCE = BuildProvenance(
    build_id="test-build",
    source_sha256="1" * 64,
    non_stripped_sha256="2" * 64,
    stripped_sha256="3" * 64,
)


def main() -> int:
    symbols = parse_nm_lines([
        "0000000000014000 0000000000000100 t family_graph_02::process_beta",
        "0000000000014120 0000000000000080 t family_graph_02::process_beta::<i32>",
        "0000000000014af0 0000000000000060 t family_graph_02::c_process_alpha_i32",
        "0000000000014af0 0000000000000060 t family_graph_02::c_process_alpha_i32::<u64>",
        "0000000000014c10 0000000000000040 t family_graph_02::decoy_alpha",
        "0000000000015030 0000000000000200 t family_graph_02::main",
        "0000000000099999 0000000000000010 t core::fmt::something",
    ])

    gt = make_ground_truth(
        symbols=symbols,
        case="fg02",
        build="O3S",
        profile="plain",
        namespaces=("family_graph_02",),
        id_bias=0x100000,
        provenance=PROVENANCE,
        candidate_scope="subject",
    )

    expected = {
        "case": "fg02",
        "build": "O3S",
        "profile": "plain",
        "schema_version": 5,
        "provenance": PROVENANCE.to_dict(),
        "origins": [
            {
                "origin": "process_beta",
                "members": ["FUN_00114000", "FUN_00114120"],
            },
            {
                "origin": "c_process_alpha_i32",
                "members": ["FUN_00114af0"],
            },
            {
                "origin": "decoy_alpha",
                "members": ["FUN_00114c10"],
            },
        ],
        "symbols": {
            "FUN_00114000": ["family_graph_02::process_beta"],
            "FUN_00114120": ["family_graph_02::process_beta::<i32>"],
            "FUN_00114af0": [
                "family_graph_02::c_process_alpha_i32",
                "family_graph_02::c_process_alpha_i32::<u64>",
            ],
            "FUN_00114c10": ["family_graph_02::decoy_alpha"],
        },
        "note": (
            "address aliases/duplicates: FUN_00114af0: duplicate symbol "
            "for origin 'c_process_alpha_i32' kept once "
            "(family_graph_02::c_process_alpha_i32::<u64>)"
        ),
    }

    if gt != expected:
        print(f"FAIL expected {expected}, got {gt}")
        return 1

    alias_symbols = parse_nm_lines([
        "0000000000014000 0000000000000010 t family_graph_02::first_origin",
        "0000000000014000 0000000000000010 t family_graph_02::second_origin",
    ])
    try:
        make_ground_truth(
            symbols=alias_symbols,
            case="fg02",
            build="O3S",
            profile="plain",
            namespaces=("family_graph_02",),
            id_bias=0x100000,
            provenance=PROVENANCE,
            candidate_scope="subject",
        )
    except ValueError as exc:
        if "cross-origin address alias" not in str(exc):
            print(f"FAIL unexpected cross-origin alias error: {exc}")
            return 1
    else:
        print("FAIL cross-origin address alias should stop GT generation")
        return 1

    addresses = user_addresses(
        symbols=symbols,
        namespaces=("family_graph_02",),
        candidate_scope="subject",
    )
    expected_addresses = [0x14000, 0x14120, 0x14AF0, 0x14C10]
    if addresses != expected_addresses:
        print(f"FAIL expected user addresses {expected_addresses}, got {addresses}")
        return 1

    bounds = user_function_bounds(
        symbols=symbols,
        namespaces=("family_graph_02",),
        candidate_scope="subject",
    )
    expected_bounds = {
        0x14000: 0x100,
        0x14120: 0x80,
        0x14AF0: 0x60,
        0x14C10: 0x40,
        0x15030: 0x200,
    }
    if bounds != expected_bounds:
        print(f"FAIL expected function bounds {expected_bounds}, got {bounds}")
        return 1

    users_json = make_users_json(
        addresses=addresses,
        function_bounds=bounds,
        case="fg02",
        build="O3S",
        profile="plain",
        binary_path="gt_bin/family_graph_02.gt.bin",
        namespaces=("family_graph_02",),
        provenance=PROVENANCE,
    )
    expected_users_json = {
        "case": "fg02",
        "build": "O3S",
        "profile": "plain",
        "schema_version": 5,
        "provenance": PROVENANCE.to_dict(),
        "source": "gt_bin/family_graph_02.gt.bin",
        "namespaces": ["family_graph_02"],
        "addresses": ["0x14000", "0x14120", "0x14af0", "0x14c10"],
        "function_bounds": [
            {"address": "0x14000", "size": 0x100},
            {"address": "0x14120", "size": 0x80},
            {"address": "0x14af0", "size": 0x60},
            {"address": "0x14c10", "size": 0x40},
            {"address": "0x15030", "size": 0x200},
        ],
    }
    if users_json != expected_users_json:
        print(f"FAIL expected users JSON {expected_users_json}, got {users_json}")
        return 1

    cargo_symbols = parse_nm_lines([
        "0000000000020000 0000000000000010 t billing_client::same_name::<i32>",
        "0000000000020020 0000000000000010 t reconcile::same_name",
        (
            "0000000000020040 0000000000000010 t "
            "billing_client::resources::_::<impl serde::Deserialize for "
            "billing_client::resources::Invoice>::deserialize"
        ),
        (
            "0000000000020060 0000000000000010 t "
            "billing_client::resources::_::<impl serde::Deserialize for "
            "billing_client::resources::Customer>::deserialize"
        ),
        (
            "0000000000020080 0000000000000010 t "
            "<reconcile::transport::ProxyTransport as "
            "billing_client::http::Transport>::execute"
        ),
        "00000000000200a0 0000000000000010 t reconcile::main",
        (
            "00000000000200c0 0000000000000010 t "
            "core::ptr::drop_in_place<billing_client::resources::Invoice>"
        ),
        (
            "00000000000200e0 0000000000000010 t "
            "billing_client::resources::<impl billing_client::client::Client>::same"
        ),
        (
            "0000000000020100 0000000000000010 t "
            "billing_client::resources::<impl billing_client::resources::Invoice>::same"
        ),
    ])
    cargo_gt = make_ground_truth(
        symbols=cargo_symbols,
        case="billing-client",
        build="O3S",
        profile="plain",
        namespaces=("billing_client", "reconcile"),
        id_bias=0,
        provenance=PROVENANCE,
        candidate_scope="subject",
    )
    cargo_origins = {group["origin"] for group in cargo_gt["origins"]}
    expected_cargo_origins = {
        "billing_client::same_name",
        "reconcile::same_name",
        (
            "billing_client::resources::_::impl_for="
            "billing_client::resources::Invoice::deserialize"
        ),
        (
            "billing_client::resources::_::impl_for="
            "billing_client::resources::Customer::deserialize"
        ),
        (
            "<reconcile::transport::ProxyTransport as "
            "billing_client::http::Transport>::execute"
        ),
        (
            "billing_client::resources::impl="
            "billing_client::client::Client::same"
        ),
        (
            "billing_client::resources::impl="
            "billing_client::resources::Invoice::same"
        ),
    }
    if cargo_origins != expected_cargo_origins:
        print(
            f"FAIL expected Cargo origins {expected_cargo_origins}, "
            f"got {cargo_origins}"
        )
        return 1

    broad_symbols = parse_nm_lines([
        "0000000000030000 0000000000000010 t core::ptr::drop_in_place<billing_client::Invoice>",
        "0000000000030020 0000000000000010 t alloc::vec::Vec<T>::len",
        "0000000000030040 0000000000000010 t std::io::read_to_string",
        "0000000000030060 0000000000000010 t serde_json::de::parse::<u64>",
        (
            "0000000000030080 0000000000000010 t "
            "<alloc::vec::Vec<T> as billing_client::LocalTrait>::method"
        ),
        (
            "00000000000300a0 0000000000000010 t "
            "<billing_client::Invoice as core::fmt::Display>::fmt"
        ),
        "00000000000300c0 0000000000000010 t <&T as core::fmt::Debug>::fmt",
        "00000000000300e0 0000000000000010 t <f64 as zmij::Sealed>::write",
        "0000000000030100 0000000000000010 t reconcile::main",
        "0000000000030120 0000000000000010 T _start",
    ])
    broad_gt = make_ground_truth(
        symbols=broad_symbols,
        case="billing-client",
        build="O3S",
        profile="plain",
        namespaces=("billing_client", "reconcile"),
        id_bias=0,
        provenance=PROVENANCE,
        candidate_scope="rust-nonstd",
        root_namespace="reconcile",
    )
    broad_origins = {group["origin"] for group in broad_gt["origins"]}
    expected_broad = {
        "serde_json::de::parse",
        "<alloc::vec::Vec<T> as billing_client::LocalTrait>::method",
        "<billing_client::Invoice as core::fmt::Display>::fmt",
        "<f64 as zmij::Sealed>::write",
    }
    if broad_origins != expected_broad:
        print(f"FAIL rust-nonstd origins: {broad_origins}")
        return 1
    if is_rust_nonstd_candidate(
        "core::ptr::drop_in_place<billing_client::Invoice>",
        root_namespace="reconcile",
    ):
        print("FAIL core-owned specialization became a candidate")
        return 1

    broad_alias_symbols = parse_nm_lines([
        "0000000000031000 0000000000000010 t serde_json::same_body",
        "0000000000031000 0000000000000010 t memchr::same_body",
    ])
    broad_alias_gt = make_ground_truth(
        symbols=broad_alias_symbols,
        case="billing-client",
        build="O3S",
        profile="plain",
        namespaces=("billing_client", "reconcile"),
        id_bias=0,
        provenance=PROVENANCE,
        candidate_scope="rust-nonstd",
        root_namespace="reconcile",
    )
    if (
        broad_alias_gt["schema_version"] != 6
        or broad_alias_gt["origins"] != [{
            "origin": "shared-address@FUN_00031000",
            "members": ["FUN_00031000"],
        }]
        or broad_alias_gt["cross_origin_aliases"] != [{
            "member": "FUN_00031000",
            "origins": ["memchr::same_body", "serde_json::same_body"],
        }]
    ):
        print(f"FAIL broad shared-address GT: {broad_alias_gt}")
        return 1

    broad_addresses = user_addresses(
        symbols=broad_symbols,
        namespaces=("billing_client", "reconcile"),
        candidate_scope="rust-nonstd",
        root_namespace="reconcile",
    )
    broad_bounds = user_function_bounds(
        symbols=broad_symbols,
        namespaces=("billing_client", "reconcile"),
        candidate_scope="rust-nonstd",
        root_namespace="reconcile",
    )
    broad_users = make_users_json(
        addresses=broad_addresses,
        function_bounds=broad_bounds,
        case="billing-client",
        build="O3S",
        profile="plain",
        binary_path="gt_bin/plain/billing-client.O3S.gt.bin",
        namespaces=("billing_client", "reconcile"),
        provenance=PROVENANCE,
        candidate_scope="rust-nonstd",
        root_namespace="reconcile",
    )
    parsed_selection = parse_candidate_selection(
        broad_users,
        expected_case="billing-client",
        expected_build="O3S",
        expected_profile="plain",
    )
    if parsed_selection.scope != "rust-nonstd":
        print("FAIL rust-nonstd candidate selection scope was not preserved")
        return 1

    all_bounds = rust_function_bounds(broad_symbols)
    if 0x30120 in all_bounds or len(all_bounds) != 9:
        print(f"FAIL scope-independent Rust boundaries: {all_bounds}")
        return 1
    boundary_json = make_function_boundaries_json(
        function_bounds=all_bounds,
        case="billing-client",
        build="O3S",
        profile="plain",
        binary_path="gt_bin/plain/billing-client.O3S.gt.bin",
        provenance=PROVENANCE,
    )
    parsed_boundaries = parse_function_boundaries(
        boundary_json,
        expected_case="billing-client",
        expected_build="O3S",
        expected_profile="plain",
    )
    if parsed_boundaries.bounds != all_bounds:
        print("FAIL function boundary artifact did not round-trip")
        return 1

    print("ground truth extractor symbol grouping PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
