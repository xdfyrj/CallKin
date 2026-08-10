from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flirt_audit import build_flirt_audit
from gt_extractor import make_all_rust_catalog, parse_nm_lines
from oxidizer_adapter import validate_label_artifact
from provenance import BuildProvenance


PROVENANCE = BuildProvenance(
    build_id="audit-test",
    source_sha256="1" * 64,
    non_stripped_sha256="2" * 64,
    stripped_sha256="3" * 64,
)


def _label(address: int, name: str, origin: str, owner: str) -> dict[str, str]:
    return {
        "address": f"0x{address:x}",
        "mapped_address": f"0x{address + 0x400000:x}",
        "name": name,
        "canonical_origin": origin,
        "owner": owner,
        "evidence": "direct-flirt",
    }


def main() -> int:
    catalog = make_all_rust_catalog(
        symbols=parse_nm_lines([
            "0000000000001000 0000000000000010 t core::ptr::drop_in_place<alloc::string::String>",
            "0000000000001020 0000000000000010 t core::ptr::drop_in_place<billing_client::Invoice>",
            "0000000000001040 0000000000000010 t std::mem::replace::<u64>",
            "0000000000001060 0000000000000010 t serde_json::de::parse::<u64>",
            "0000000000001080 0000000000000010 t serde_json::de::parse::<i32>",
            "00000000000010a0 0000000000000010 t serde_json::de::other",
            "00000000000010c0 0000000000000010 t reconcile::main",
        ]),
        case="billing-client",
        build="O3S",
        profile="plain",
        root_namespace="reconcile",
        id_bias=0,
        binary_path="gt_bin/plain/billing-client.O3S.gt.bin",
        provenance=PROVENANCE,
    )
    labels = {
        "schema_version": 1,
        "case": "billing-client",
        "build": "O3S",
        "profile": "plain",
        "provenance": PROVENANCE.to_dict(),
        "stripped_sha256": PROVENANCE.stripped_sha256,
        "raw_graph_sha256": "4" * 64,
        "analysis": {
            "input": "stripped-only",
            "address_space": "ELF linked virtual address",
            "boundary_oracle": "CallKin raw graph symbol-boundary oracle",
            "seed_policy": "direct-flirt-only",
        },
        "tool": {"oxidizer_commit": "test"},
        "execution": {
            "timeout_seconds": None,
            "memory_limit_mb": None,
            "cache_reused": False,
        },
        "matches": [
            _label(0x1000, "core::ptr::drop_in_place<alloc::string::String>", "core::ptr::drop_in_place", "core"),
            # Wrong standard-library identity, but still a correct std classification.
            _label(0x1040, "std::mem::swap::<u64>", "std::mem::swap", "std"),
            _label(0x1060, "serde_json::de::parse::<u64>", "serde_json::de::parse", "serde_json"),
            _label(0x10A0, "std::mem::replace", "std::mem::replace", "std"),
            # The source root may join the raw graph but is absent from the all-Rust catalog.
            _label(0x10C0, "reconcile::main", "reconcile::main", "reconcile"),
        ],
        "propagated_wrappers": [],
        "cleanup_heuristics": [],
        "unmatched_addresses": [],
    }
    validate_label_artifact(labels)
    audit = build_flirt_audit(catalog=catalog, labels=labels)
    direct = audit["direct_flirt"]
    if {
        "raw_graph_joined_match_count": direct["raw_graph_joined_match_count"],
        "catalog_joined_match_count": direct["catalog_joined_match_count"],
        "catalog_unmatched_count": direct["catalog_unmatched_count"],
    } != {
        "raw_graph_joined_match_count": 5,
        "catalog_joined_match_count": 4,
        "catalog_unmatched_count": 1,
    }:
        print(f"FAIL direct-FLIRT join counts: {direct}")
        return 1
    identity = direct["exact_identity"]
    if identity != {
        "matched_member_count": 4,
        "correct_match_count": 2,
        "incorrect_match_count": 2,
        "precision": 0.5,
        "catalog_member_coverage": 0.333333,
        "incorrect_labels": [
            {
                "member": "FUN_00001040",
                "label_origin": "std::mem::swap",
                "catalog_origin": "std::mem::replace",
                "label_owner": "std",
                "catalog_owner": "std",
            },
            {
                "member": "FUN_000010a0",
                "label_origin": "std::mem::replace",
                "catalog_origin": "serde_json::de::other",
                "label_owner": "std",
                "catalog_owner": "serde_json",
            },
        ],
    }:
        print(f"FAIL direct FLIRT catalog audit: {direct}")
        return 1
    standard = direct["std_classification"]
    if standard != {
        "true_positive": 2,
        "false_positive": 1,
        "false_negative": 1,
        "true_negative": 2,
        "precision": 0.666667,
        "recall": 0.666667,
    }:
        print(f"FAIL standard direct-FLIRT P/R: {standard}")
        return 1
    mixed = audit["mixed_families"]
    if (
        mixed["family_count"] != 1
        or mixed["cross_boundary_same_family_pair_count"] != 1
        or len(audit["drop_in_place_families"]) != 1
        or mixed["families"][0]["known_direct_flirt_instances"] != 1
        or mixed["families"][0]["unknown_instances"] != 1
    ):
        print(f"FAIL known/unknown mixed-family audit: {mixed}")
        return 1

    print("direct-FLIRT mixed-family audit PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
