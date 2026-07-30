import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gt_extractor import (
    make_ground_truth,
    make_users_json,
    parse_nm_lines,
    user_addresses,
    user_function_bounds,
)
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
    )
    expected_addresses = [0x14000, 0x14120, 0x14AF0, 0x14C10]
    if addresses != expected_addresses:
        print(f"FAIL expected user addresses {expected_addresses}, got {addresses}")
        return 1

    bounds = user_function_bounds(
        symbols=symbols,
        namespaces=("family_graph_02",),
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

    print("ground truth extractor symbol grouping PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
