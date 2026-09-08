#!/usr/bin/env python3
"""Verify the fd source-ambiguity overlay and frozen prediction sensitivity."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections import Counter
from itertools import combinations
from math import comb
from pathlib import Path
from typing import Any, Mapping

REQUIRED_PYTHON = (3, 10, 14)
if sys.version_info[:3] != REQUIRED_PYTHON:
    raise SystemExit(
        "verify_source_ambiguity.py requires Python 3.10.14 exactly; "
        f"found {sys.version.split()[0]}. Run it with python3.10."
    )

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

sys.dont_write_bytecode = True

AUDIT = Path(__file__).resolve().parent
WORKTREE = AUDIT.parents[2]
CALLKIN = AUDIT.parents[4]
OLD = WORKTREE / "experiments/followup-2026-09-08"
REL = WORKTREE / "experiments/relation-control-2026-09-08"
EVIDENCE = AUDIT / "evidence.json"
OVERLAY = AUDIT / "fd.source-ambiguity.v2.linkage.json"
SENSITIVITY = AUDIT / "sensitivity.json"
TARGET = "FUN_003b0160"
ORIGIN = "regex_automata::meta::regex::Builder::build_many_from_hir::{{closure}}"
CLONE_ORIGIN = "<regex_automata::meta::regex::Regex as core::clone::Clone>::clone::{{closure}}"
FIELDS = ("TP", "FP", "FN", "TN", "precision", "recall", "f1",
          "macro_origin_recall", "exact_group_rate", "positive_pairs",
          "scored_pairs", "neutral_pairs", "positive_first_outcome",
          "comparison_cost")

sys.path.insert(0, str(CALLKIN))
sys.path.insert(0, str(WORKTREE))
sys.path.insert(0, str(OLD))
from body_similarity import load_body_evidence  # noqa: E402
from linkage_overlay import (  # noqa: E402
    AMBIGUOUS_NEUTRAL, DUPLICATE_NEUTRAL, NEGATIVE, POSITIVE,
    UNRESOLVED_NEUTRAL, label_pair, load_overlay,
)
from score_followup import metrics, truth_index  # noqa: E402


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_once(path: Path, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path.exists():
        assert path.read_text(encoding="utf-8") == encoded, path
    else:
        path.write_text(encoded, encoding="utf-8")
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def compact(result: Mapping[str, Any]) -> dict[str, Any]:
    neutral = dict(result["neutral_pairs"])
    return {
        "TP": result["TP"], "FP": result["FP"], "FN": result["FN"],
        "TN": result["TN"], "precision": result["precision"],
        "recall": result["recall"], "F1": result["f1"],
        "macro_R": result["macro_origin_recall"],
        "exact_group_rate": result["exact_group_rate"],
        "P": result["positive_pairs"],
        "N": result["scored_pairs"] - result["positive_pairs"],
        "scored_pairs": result["scored_pairs"],
        "neutral_pairs": neutral,
        "neutral_total": sum(neutral.values()),
        "positive_first_outcome": result.get("positive_first_outcome"),
        "candidate_positive_pairs": result.get("candidate_positive_pairs"),
        "candidate_positive_recall": result.get("candidate_positive_recall"),
    }


def universe(ids: list[str], audit: Mapping[str, Any]) -> dict[str, Any]:
    _origins, _identities, positive, _per_origin, negative, neutral = truth_index(ids, audit)
    all_pairs = comb(len(ids), 2)
    neutral = dict(neutral)
    return {
        "target_count": len(ids), "all_pair_count": all_pairs,
        "P": len(positive), "N": negative,
        "neutral_pairs": neutral, "neutral_total": sum(neutral.values()),
        "scored_pairs": len(positive) + negative,
        "conserved": len(positive) + negative + sum(neutral.values()) == all_pairs,
    }


def touched(address: str, ids: list[str], audit: Mapping[str, Any]) -> dict[str, Any]:
    origins, identities = load_overlay(audit)
    counts = Counter()
    for other in ids:
        if other == address:
            continue
        pair = tuple(sorted((address, other)))
        counts[label_pair(pair[0], pair[1],
                           origins_by_address=origins,
                           identities_by_address=identities)] += 1
    return {
        "address": address,
        "pair_count": len(ids) - 1,
        "label_counts": {key: counts.get(key, 0) for key in (
            POSITIVE, NEGATIVE, AMBIGUOUS_NEUTRAL,
            DUPLICATE_NEUTRAL, UNRESOLVED_NEUTRAL)},
        "scored_other_endpoint_count": counts[POSITIVE] + counts[NEGATIVE],
    }


def rank(rows: Mapping[str, Mapping[str, Any]], field: str) -> list[str]:
    return sorted(rows, key=lambda arm: (-float(rows[arm][field]), arm))


def direction(left: float, right: float) -> str:
    return "C3>B2" if left > right else "C3<B2" if left < right else "equal"


def verify_elf(evidence: Mapping[str, Any]) -> None:
    binary = Path(evidence["inputs"]["retained_non_stripped_elf"]["path"])
    expected_body = evidence["target_function_body"]
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name(".text")
        symbols = {
            int(symbol["st_value"]): symbol
            for symbol in elf.get_section_by_name(".symtab").iter_symbols()
            if symbol["st_info"]["type"] == "STT_FUNC"
        }
        relocations = {}
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                for relocation in section.iter_relocations():
                    if relocation["r_info_type"] == 8:
                        relocations[int(relocation["r_offset"])] = int(relocation["r_addend"])
        for member in evidence["members"]:
            address = int(member["elf_address"], 16)
            size = member["function_extent"]["size"]
            raw = text.data()[address - text["sh_addr"]:address - text["sh_addr"] + size]
            assert raw.hex() == expected_body["raw_bytes_hex"] == member["raw_bytes_hex"]
            assert hashlib.sha256(raw).hexdigest() == expected_body["byte_sha256"]
            assert symbols[address].name == member["raw_symbol"]
        for table in (evidence["members"][2]["closure_vtable"], evidence["shared_body_evidence"]["clone_vtable"]):
            for slot in ("fnonce_slot", "fnmut_slot", "fn_slot"):
                entry = table[slot]
                assert relocations[int(entry["address"], 16)] == int(entry["relocation_target"], 16)


def main() -> None:
    evidence = read(EVIDENCE)
    source = Path(evidence["pinned_source"]["source_file"])
    binary = Path(evidence["inputs"]["retained_non_stripped_elf"]["path"])
    assert sha(source) == evidence["pinned_source"]["source_file_sha256"]
    assert sha(binary) == evidence["inputs"]["retained_non_stripped_elf"]["sha256"]
    verify_elf(evidence)
    assert TARGET == evidence["conclusion"]["source_origin_ambiguity"]["address"]

    old_link_path = OLD / "audit-corrections/fd.linkage.v1.json"
    old_gt_path = OLD / "audit-corrections/fd.gt.v1.json"
    original_link_path = CALLKIN / "worktrees/v0-engine-py-f1/results/fd/plain/fd.O3S.gt-mangled-audit.json"
    original_gt_path = CALLKIN / "ground_truth/rust-nonstd/plain/fd.O3S.gt.json"
    old_link = read(old_link_path)
    old_gt = read(old_gt_path)
    original_link = read(original_link_path)
    original_gt = read(original_gt_path)
    old_link_hash = sha(old_link_path)
    evidence_hash = sha(EVIDENCE)

    overlay = copy.deepcopy(old_link)
    record = overlay["addresses"][TARGET]
    assert record["origins"] == [ORIGIN]
    assert record["identities"] == old_link["addresses"][TARGET]["identities"]
    record["origins"] = [ORIGIN, CLONE_ORIGIN]
    overlay["provenance"] = {
        **old_link.get("provenance", {}),
        "parent_sha256": old_link_hash,
        "source_file_sha256": evidence["pinned_source"]["source_file_sha256"],
        "evidence_sha256": evidence_hash,
        "reason": "Distinct Builder and Regex::clone source closures construct separate vtables whose Fn/FnMut slots both relocate to FUN_003b0160; add clone origin for ambiguity sensitivity only.",
        "derived_from": str(old_link_path),
    }
    overlay["source_ambiguity"] = {
        "member": TARGET,
        "elf_address": "0x2b0160",
        "added_origin": CLONE_ORIGIN,
        "source_file": str(source),
        "source_line": 1916,
        "builder_source_line": 3613,
        "builder_vtable": "0x439cf8",
        "clone_vtable": "0x439f68",
        "status": "secondary-sensitivity-overlay",
    }
    assert set(overlay["addresses"]) == set(old_link["addresses"])
    assert overlay["manual_source_site_overrides"] == old_link["manual_source_site_overrides"]
    for address in old_link["addresses"]:
        if address != TARGET:
            assert overlay["addresses"][address] == old_link["addresses"][address]
    assert overlay["addresses"][TARGET]["identities"] == old_link["addresses"][TARGET]["identities"]
    overlay_hash = write_once(OVERLAY, overlay)

    body_path = Path(evidence["inputs"]["input_manifest"]["body_path"])
    bodies = load_body_evidence(body_path)
    eligible = {
        member for member, body in bodies.items()
        if body.complete and int(body.quality.get("opaque_indirect_jumps", 0)) == 0
    }
    stored = read(REL / "fd-results.json")
    assert [row["arm"] for row in stored] == [
        "C3-k16", "B2-body-score", "random-0", "random-1",
        "random-2", "random-3", "random-4",
    ]
    baseline_rows: dict[str, dict[str, Any]] = {}
    after_rows: dict[str, dict[str, Any]] = {}
    original_rows: dict[str, dict[str, Any]] = {}
    predictions: dict[str, dict[str, Any]] = {}
    ids: list[str] | None = None
    for stored_row in stored:
        arm = stored_row["arm"]
        pred_path = REL / "runs/fd" / arm / "prediction.json"
        candidate_path = (
            OLD / "cache/fd/combined3-k16.candidates.json"
            if arm == "C3-k16"
            else REL / "candidates/fd" / f"{arm}.candidates.json"
        )
        pred = read(pred_path)
        candidate = read(candidate_path)
        metadata = read(REL / "runs/fd" / arm / "metadata.json")
        assert metadata["status"] == "completed"
        assert metadata["prediction_sha256"] == sha(pred_path)
        assert metadata["candidate_sha256"] == sha(candidate_path)
        pairs = {tuple(record["pair"]) for record in candidate["pairs"]}
        ids = list(pred["universe"]["target_ids"]) if ids is None else ids
        assert ids == pred["universe"]["target_ids"]
        baseline = metrics(pred, old_gt, old_link, eligible, pairs)
        original = metrics(pred, original_gt, original_link, eligible, pairs)
        after = metrics(pred, old_gt, overlay, eligible, pairs)
        assert all(baseline[field] == stored_row["metrics"][field] for field in FIELDS)
        assert all(original[field] == stored_row["secondary_metrics"][field] for field in FIELDS)
        baseline_rows[arm] = compact(baseline)
        original_rows[arm] = compact(original)
        after_rows[arm] = compact(after)
        predictions[arm] = {
            "path": str(pred_path), "sha256": sha(pred_path),
            "candidate_path": str(candidate_path), "candidate_sha256": sha(candidate_path),
        }
    assert ids is not None
    before_universe = universe(ids, old_link)
    after_universe = universe(ids, overlay)
    before_touch = touched(TARGET, ids, old_link)
    after_touch = touched(TARGET, ids, overlay)
    assert before_universe["conserved"] and after_universe["conserved"]
    assert before_touch["label_counts"][POSITIVE] == 2
    assert after_touch["label_counts"][AMBIGUOUS_NEUTRAL] == len(ids) - 1
    assert after_universe["P"] == before_universe["P"] - 2
    assert after_universe["N"] < before_universe["N"]
    assert after_universe["scored_pairs"] < before_universe["scored_pairs"]
    assert after_touch["scored_other_endpoint_count"] == 0

    rank_fields = {
        "precision": "precision", "recall": "recall", "F1": "F1",
        "macro_R": "macro_R", "exact_group_rate": "exact_group_rate",
    }
    rank_changes = {}
    for label, field in rank_fields.items():
        before_order, after_order = rank(baseline_rows, field), rank(after_rows, field)
        before_c3 = baseline_rows["C3-k16"][field]
        before_b2 = baseline_rows["B2-body-score"][field]
        after_c3 = after_rows["C3-k16"][field]
        after_b2 = after_rows["B2-body-score"][field]
        rank_changes[label] = {
            "before_order": before_order, "after_order": after_order,
            "c3_vs_b2_before": direction(before_c3, before_b2),
            "c3_vs_b2_after": direction(after_c3, after_b2),
            "c3_vs_b2_direction_changed": direction(before_c3, before_b2) != direction(after_c3, after_b2),
            "all_arm_order_changed": before_order != after_order,
        }

    sensitivity = {
        "schema_version": 2,
        "study": "callkin-relation-control-2026-09-08",
        "case": "fd",
        "status": "posthoc-source-ambiguity-sensitivity",
        "primary_results_immutable": True,
        "new_defid_oracle_used": False,
        "scorer": {
            "path": str(OLD / "score_followup.py"),
            "sha256": sha(OLD / "score_followup.py"),
            "exact_conditional": "label_pair returns ambiguous-neutral when len(origins[left]) > 1 or len(origins[right]) > 1; truth_index excludes non-clean addresses from positive/negative and counts their pairs as ambiguous-neutral.",
            "prediction_count": len(stored),
            "arms": [row["arm"] for row in stored],
        },
        "provenance": {
            "parent_linkage": {"path": str(old_link_path), "sha256": old_link_hash},
            "parent_linkage_provenance_parent_sha256": old_link["provenance"]["parent_sha256"],
            "overlay": {"path": str(OVERLAY), "sha256": overlay_hash},
            "source_file": {"path": str(source), "sha256": evidence["pinned_source"]["source_file_sha256"]},
            "evidence": {"path": str(EVIDENCE), "sha256": evidence_hash},
            "frozen_fd_results": {"path": str(REL / "fd-results.json"), "sha256": sha(REL / "fd-results.json")},
            "predictions": predictions,
        },
        "overlay_record": {
            "member": TARGET, "elf_address": "0x2b0160",
            "origins_before": [ORIGIN],
            "origins_after": [ORIGIN, CLONE_ORIGIN],
            "identities_preserved": True,
            "raw_mangled_identity_is_operational_only": True,
            "semantic_monomorphization_claim": False,
        },
        "scored_universe": {
            "before": before_universe,
            "after": after_universe,
            "delta": {
                "P": after_universe["P"] - before_universe["P"],
                "N": after_universe["N"] - before_universe["N"],
                "scored_pairs": after_universe["scored_pairs"] - before_universe["scored_pairs"],
                "neutral_total": after_universe["neutral_total"] - before_universe["neutral_total"],
                "ambiguous_neutral": after_universe["neutral_pairs"].get(AMBIGUOUS_NEUTRAL, 0) - before_universe["neutral_pairs"].get(AMBIGUOUS_NEUTRAL, 0),
            },
            "pairs_touching_ambiguous_address": {
                "before": before_touch, "after": after_touch,
                "newly_removed_positive": before_touch["label_counts"][POSITIVE],
                "newly_removed_negative": before_touch["label_counts"][NEGATIVE],
                "newly_added_ambiguous_neutral": after_touch["label_counts"][AMBIGUOUS_NEUTRAL] - before_touch["label_counts"][AMBIGUOUS_NEUTRAL],
            },
        },
        "arms": {
            arm: {
                "prediction": predictions[arm],
                "baseline_primary_v1": baseline_rows[arm],
                "after_ambiguity_v2": after_rows[arm],
                "original_v1": original_rows[arm],
                "original_v1_verification": {
                    "status": "matched-frozen-fd-results-secondary_metrics",
                    "fields": list(FIELDS[:-1]),
                },
                "delta_after_minus_before": {
                    field: after_rows[arm][field] - baseline_rows[arm][field]
                    if isinstance(after_rows[arm][field], (int, float))
                    and isinstance(baseline_rows[arm][field], (int, float))
                    else None
                    for field in ("TP", "FP", "FN", "TN", "precision", "recall",
                                  "F1", "macro_R", "exact_group_rate", "P", "N",
                                  "scored_pairs", "neutral_total")
                },
            }
            for arm in baseline_rows
        },
        "rank_direction": rank_changes,
        "interpretation": {
            "remaining_positive_pair": "FUN_00347e80__FUN_003804f0",
            "pairs_touching_FUN_003b0160": "ambiguous-neutral under the authorized overlay, including negative pairs that were scored before",
            "identity_limit": "Remaining raw mangled identities and differing codegen locations are operational linkage proxies; this sensitivity does not assert semantic MonoItem distinctness.",
        },
    }
    write_once(SENSITIVITY, sensitivity)
    print(json.dumps({
        "status": sensitivity["status"],
        "overlay_sha256": overlay_hash,
        "sensitivity_sha256": sha(SENSITIVITY),
        "arms": list(baseline_rows),
        "before_universe": before_universe,
        "after_universe": after_universe,
        "touching_before": before_touch,
        "touching_after": after_touch,
        "rank_direction": rank_changes,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
