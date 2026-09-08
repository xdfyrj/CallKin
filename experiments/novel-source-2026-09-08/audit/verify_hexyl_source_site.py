#!/usr/bin/env python3
"""Build and verify the Hexyl source-site label sensitivity."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from itertools import combinations
from pathlib import Path
from typing import Any

if sys.version_info[:3] != (3, 12, 3):
    raise SystemExit(
        "verify_hexyl_source_site.py requires Python 3.12.3 exactly; "
        f"found {sys.version.split()[0]}. Run it with python3.12."
    )
sys.dont_write_bytecode = True

AUDIT = Path(__file__).resolve().parent
WORKTREE = AUDIT.parents[2]
REPO = AUDIT.parents[4]
NOVEL = WORKTREE / "experiments/novel-source-2026-09-08"
OBS = NOVEL / "observations/hexyl-v0170"
PRED = NOVEL / "predictions/hexyl-v0170"
CAND = NOVEL / "candidates/hexyl-v0170"
OLD_GT = OBS / "hexyl-v0170.O3S.gt.json"
OLD_LINK = OBS / "hexyl-v0170.O3S.linkage.json"
SOURCE_AUDIT = AUDIT / "hexyl-source-audit.json"
NEW_GT = AUDIT / "hexyl.gt.v2.json"
NEW_LINK = AUDIT / "hexyl.linkage.v2.json"
OUT = AUDIT / "hexyl-source-site-sensitivity.json"
EXPOSED = NOVEL / "exposed-origins.json"
VERIFIER = Path(__file__).resolve()
ORIGIN = "hexyl::run::{{closure}}"
SITE342 = "hexyl::run::{{closure}}@src/main.rs:342"
SITE353 = "hexyl::run::{{closure}}@src/main.rs:353"
TARGETS = ("FUN_0015b1a0", "FUN_0015b260")
ARMS = ("V0-relation", "exact-token-hash", "B2-token-cfg",
        "C3-token-cfg-relation", "B2-body-score", "C3-rescue")
CANDIDATE_PATHS = {
    "B2-token-cfg": CAND / "B2-token-cfg.candidates.json",
    "C3-token-cfg-relation": CAND / "C3-token-cfg-relation.candidates.json",
    "B2-body-score": CAND / "B2-body-score.candidates.json",
    "C3-rescue": CAND / "C3-rescue-input.candidates.json",
}

for path in (REPO, WORKTREE, WORKTREE / "experiments/followup-2026-09-08"):
    sys.path.insert(0, str(path))
from body_similarity import load_body_evidence  # noqa: E402
from gt_extractor import belongs_to_subject  # noqa: E402
from linkage_overlay import NEGATIVE, label_pair  # noqa: E402
from score_followup import metrics, truth_index  # noqa: E402


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_once(path: Path, value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path.exists():
        if path.read_text(encoding="utf-8") != text:
            raise ValueError(f"refusing to overwrite retained output: {path}")
    else:
        path.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode()).hexdigest()


def candidate_pairs(arm: str) -> set[tuple[str, str]] | None:
    path = CANDIDATE_PATHS.get(arm)
    if path is None:
        return None
    return {tuple(sorted(x["pair"])) for x in read(path)["pairs"]}


def clipped(prediction: dict[str, Any], mask: set[str]) -> dict[str, Any]:
    result = copy.deepcopy(prediction)
    result["universe"] = {"target_ids": sorted(mask)}
    result["clusters"] = [
        {"members": sorted(set(group["members"]) & mask), "status": group["status"]}
        for group in prediction.get("clusters", ())
        if len(set(group.get("members", ())) & mask) >= 2
    ]
    return result


def score_view(prediction: dict[str, Any], gt: dict[str, Any],
               linkage: dict[str, Any], mask: set[str],
               eligible: set[str]) -> dict[str, Any]:
    result = metrics(clipped(prediction, mask), gt, linkage, eligible & mask)
    if result["positive_pairs"] == 0:
        result["recall"] = None
        result["macro_origin_recall"] = None
        result["exact_group_rate"] = None
    return result


def bundle(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: result.get(key)
        for key in ("TP", "FP", "FN", "TN", "precision", "recall",
                    "f1", "macro_origin_recall", "exact_group_rate",
                    "positive_pairs", "scored_pairs", "neutral_pairs",
                    "positive_first_outcome")
    } | {
        "P": result["positive_pairs"],
        "N": result["scored_pairs"] - result["positive_pairs"],
    }


def assert_metric_match(actual: dict[str, Any], expected: dict[str, Any]) -> None:
    for key in ("TP", "FP", "FN", "TN", "precision", "recall", "f1",
                "macro_origin_recall", "exact_group_rate", "positive_pairs",
                "scored_pairs", "neutral_pairs", "positive_first_outcome"):
        if actual.get(key) != expected.get(key):
            raise AssertionError(f"legacy metric mismatch: {key}")


def universe(ids: list[str], linkage: dict[str, Any]) -> dict[str, Any]:
    _, _, positive, _, negative, neutral = truth_index(ids, linkage)
    neutral = dict(neutral)
    total = len(positive) + negative + sum(neutral.values())
    return {
        "target_count": len(ids),
        "all_pairs": len(ids) * (len(ids) - 1) // 2,
        "P": len(positive),
        "N": negative,
        "neutral_pairs": neutral,
        "scored_pairs": len(positive) + negative,
        "conserved": total == len(ids) * (len(ids) - 1) // 2,
    }


def rank(rows: dict[str, dict[str, Any]], field: str) -> dict[str, Any]:
    before = sorted(rows, key=lambda arm: (-float(rows[arm]["before"][field]), arm))
    after = sorted(rows, key=lambda arm: (-float(rows[arm]["after"][field]), arm))
    return {"before": before, "after": after, "changed": before != after}


def main() -> None:
    audit = read(SOURCE_AUDIT)
    old_gt = read(OLD_GT)
    old_link = read(OLD_LINK)
    old_gt_sha, old_link_sha = sha(OLD_GT), sha(OLD_LINK)
    assert old_gt_sha == audit["provenance"]["ground_truth"]["sha256"]
    assert old_link_sha == audit["provenance"]["linkage"]["sha256"]

    gt = copy.deepcopy(old_gt)
    groups = []
    for group in gt["origins"]:
        if group["origin"] == ORIGIN:
            groups.extend([
                {"origin": SITE353, "members": ["FUN_0015b1a0"]},
                {"origin": SITE342, "members": ["FUN_0015b260"]},
            ])
        else:
            groups.append(group)
    gt["origins"] = groups
    gt["parent_ground_truth_sha256"] = old_gt_sha
    gt["provenance"] = {
        **old_gt["provenance"],
        "source_audit_sha256": sha(SOURCE_AUDIT),
        "source_file_sha256": audit["provenance"]["source"]["main_rs_sha256"],
        "reason": "Split the normalized run::{{closure}} group using the two source-site closures proven by retained body semantics and direct callers.",
    }
    gt["source_site_correction"] = {
        "status": "versioned-secondary-sensitivity",
        "parent_sha256": old_gt_sha,
        "old_origin": ORIGIN,
        "site_labels": {
            SITE342: ["FUN_0015b260"],
            SITE353: ["FUN_0015b1a0"],
        },
    }
    gt_sha = write_once(NEW_GT, gt)

    linkage = copy.deepcopy(old_link)
    assert set(linkage["addresses"]) == set(old_link["addresses"])
    assert linkage["addresses"]["FUN_0015b1a0"]["origins"] == [ORIGIN]
    assert linkage["addresses"]["FUN_0015b260"]["origins"] == [ORIGIN]
    linkage["addresses"]["FUN_0015b1a0"]["origins"] = [SITE353]
    linkage["addresses"]["FUN_0015b260"]["origins"] = [SITE342]
    split_sites = ((SITE353, "FUN_0015b1a0"), (SITE342, "FUN_0015b260"))
    identities_by_target = {
        address: old_link["addresses"][address]["identities"]
        for _, address in split_sites
    }
    assert all(len(ids) == 1 for ids in identities_by_target.values())
    split_origin_records = [
        {
            "classification": "distinct_linkage_identities",
            "identity_count": 1,
            "members": [address],
            "origin": origin,
            "raw_symbols": list(identities_by_target[address]),
            "raw_symbols_by_member": {address: list(identities_by_target[address])},
            "shape": "clean",
        }
        for origin, address in split_sites
    ]
    linkage["origins"] = [
        replacement
        for record in linkage["origins"]
        for replacement in (split_origin_records if record["origin"] == ORIGIN else [record])
    ]
    split_linkage_records = [
        {
            "address_count": 1,
            "addresses_by_identity": {ids[0]: [address]},
            "has_duplication": False,
            "has_folding": False,
            "identities_by_address": {address: list(ids)},
            "identity_count": 1,
            "origin": origin,
            "shape": "clean",
            "unobservable_identity_pairs": 0,
        }
        for origin, address in split_sites
        for ids in (identities_by_target[address],)
    ]
    linkage["linkage"] = [
        replacement
        for record in linkage["linkage"]
        for replacement in (split_linkage_records if record["origin"] == ORIGIN else [record])
    ]
    assert len(linkage["origins"]) == len(old_link["origins"]) + 1
    assert len(linkage["linkage"]) == len(old_link["linkage"]) + 1
    linkage["summary"]["family_counts"]["distinct_linkage_identities"] += 1
    linkage["summary"]["multimember_origin_count"] -= 1
    linkage["summary"]["shape_counts"]["clean"] += 1
    linkage["provenance"] = {
        **old_link["provenance"],
        "parent_sha256": old_link_sha,
        "parent_ground_truth_sha256": old_link["provenance"]["ground_truth_sha256"],
        "ground_truth_sha256": gt_sha,
        "source_audit_sha256": sha(SOURCE_AUDIT),
        "source_file_sha256": audit["provenance"]["source"]["main_rs_sha256"],
        "reason": "Split the normalized run::{{closure}} group using the two source-site closures proven by retained body semantics and direct callers.",
    }
    linkage["source_site_correction"] = gt["source_site_correction"]
    link_sha = write_once(NEW_LINK, linkage)
    for address in old_link["addresses"]:
        if address not in TARGETS:
            assert linkage["addresses"][address] == old_link["addresses"][address]
    assert linkage["addresses"][TARGETS[0]]["identities"] == old_link["addresses"][TARGETS[0]]["identities"]
    assert linkage["addresses"][TARGETS[1]]["identities"] == old_link["addresses"][TARGETS[1]]["identities"]

    scores = read(NOVEL / "scores/hexyl-v0170/scores.json")
    body = load_body_evidence(OBS / "hexyl-v0170.O3S.body.json")
    eligible = {member for member, item in body.items()
                if item.complete and not item.quality.get("opaque_indirect_jumps", 0)}
    origins = {str(m): tuple(r["origins"]) for m, r in old_link["addresses"].items()}
    new_origins = {str(m): tuple(r["origins"]) for m, r in linkage["addresses"].items()}
    identities = {str(m): tuple(r["identities"]) for m, r in old_link["addresses"].items()}
    new_identities = {str(m): tuple(r["identities"]) for m, r in linkage["addresses"].items()}
    split_pair = tuple(sorted(TARGETS))
    inventory = set(read(EXPOSED))
    project_old = {m for m, names in origins.items()
                   if len(names) == 1 and belongs_to_subject(names[0], ("hexyl",))}
    project_new = {m for m, names in new_origins.items()
                   if len(names) == 1 and belongs_to_subject(names[0], ("hexyl",))}
    unobserved_old = {m for m, names in origins.items()
                      if len(names) == 1 and names[0] not in inventory}
    unobserved_new = {m for m, names in new_origins.items()
                      if len(names) == 1 and names[0] not in inventory}
    assert project_old == project_new and unobserved_old == unobserved_new
    ids = None
    rows: dict[str, dict[str, Any]] = {}
    for arm in ARMS:
        prediction = read(PRED / arm / "prediction.json")
        ids = list(prediction["universe"]["target_ids"]) if ids is None else ids
        assert ids == prediction["universe"]["target_ids"]
        assert set(split_pair) <= set(ids)
        assert label_pair(*split_pair, origins_by_address=origins, identities_by_address=identities) == "positive"
        assert label_pair(*split_pair, origins_by_address=new_origins, identities_by_address=new_identities) == NEGATIVE
        pairs = candidate_pairs(arm)
        before = metrics(prediction, old_gt, old_link, eligible, pairs)
        after = metrics(prediction, gt, linkage, eligible, pairs)
        assert_metric_match(before, scores["arms"][arm]["metrics"])
        before_views = {}
        after_views = {}
        for name, old_mask, new_mask in (
            ("project_owned", project_old, project_new),
            ("previously_unobserved_normalized_origin", unobserved_old, unobserved_new),
        ):
            b = score_view(prediction, old_gt, old_link, old_mask, eligible)
            a = score_view(prediction, gt, linkage, new_mask, eligible)
            assert_metric_match(b, scores["arms"][arm]["secondary"][name]["metrics"])
            before_views[name] = {"mask_size": len(old_mask), "metrics": bundle(b)}
            after_views[name] = {"mask_size": len(new_mask), "metrics": bundle(a)}
        rows[arm] = {
            "prediction": {
                "path": str(PRED / arm / "prediction.json"),
                "sha256": sha(PRED / arm / "prediction.json"),
            },
            "before": bundle(before),
            "after": bundle(after),
            "primary_delta": {
                key: after.get(key) - before.get(key)
                if isinstance(after.get(key), (int, float))
                and isinstance(before.get(key), (int, float))
                else None
                for key in ("TP", "FP", "FN", "TN", "positive_pairs", "scored_pairs")
            },
            "views_before": before_views,
            "views_after": after_views,
        }
    for row in rows.values():
        assert row["primary_delta"] == {
            "TP": 0, "FP": 0, "FN": -1, "TN": 1,
            "positive_pairs": -1, "scored_pairs": 0,
        }
    rank_changes = {
        name: rank(rows, name)
        for name in ("precision", "recall", "f1", "macro_origin_recall", "exact_group_rate")
    }
    output = {
        "schema_version": 2,
        "case": "hexyl-v0170",
        "status": "source-site-secondary-sensitivity",
        "scoring_python": "3.12.3",
        "primary_results_immutable": True,
        "new_defid_oracle_used": False,
        "provenance": {
            "source_audit": {"path": str(SOURCE_AUDIT), "sha256": sha(SOURCE_AUDIT)},
            "parent_ground_truth": {"path": str(OLD_GT), "sha256": old_gt_sha},
            "parent_linkage": {"path": str(OLD_LINK), "sha256": old_link_sha},
            "ground_truth_v2": {"path": str(NEW_GT), "sha256": gt_sha},
            "linkage_v2": {"path": str(NEW_LINK), "sha256": link_sha},
            "scores": {"path": str(NOVEL / "scores/hexyl-v0170/scores.json"),
                       "sha256": sha(NOVEL / "scores/hexyl-v0170/scores.json")},
            "exposed_origins": {"path": str(EXPOSED), "sha256": sha(EXPOSED)},
            "verifier": {"path": str(VERIFIER), "sha256": sha(VERIFIER)},
        },
        "source_site_split": {
            "old_origin": ORIGIN,
            "site342": {
                "origin": SITE342, "address": "FUN_0015b260",
                "project_owned_by_prefix": belongs_to_subject(SITE342, ("hexyl",)),
                "in_frozen_exposed_origin_inventory": SITE342 in inventory,
            },
            "site353": {
                "origin": SITE353, "address": "FUN_0015b1a0",
                "project_owned_by_prefix": belongs_to_subject(SITE353, ("hexyl",)),
                "in_frozen_exposed_origin_inventory": SITE353 in inventory,
            },
            "split_pair": {
                "addresses": list(split_pair),
                "old_label_pair": "positive",
                "new_label_pair": NEGATIVE,
            },
            "identities_preserved": True,
            "mask_sizes": {
                "project_owned": {"before": len(project_old), "after": len(project_new)},
                "previously_unobserved_normalized_origin": {
                    "before": len(unobserved_old), "after": len(unobserved_new)
                },
            },
        },
        "scored_universe": {
            "before": universe(ids, old_link),
            "after": universe(ids, linkage),
            "label_pair_effect": "The split removes the old one-pair closure positive and creates one negative pair; all frozen predictions leave that pair unpredicted.",
        },
        "arms": rows,
        "rank_changes": rank_changes,
        "interpretation": {
            "anyhow": "The Anyhow pair remains a normalized origin with a plausible single dependency-method location; this audit makes no source-definition confirmation or correction for it.",
            "identity_limit": "Mangled identities and addresses remain operational linkage evidence; no semantic MonoItem or DefId claim is made.",
        },
    }
    sens_sha = write_once(OUT, output)
    print(json.dumps({
        "status": output["status"],
        "ground_truth_v2_sha256": gt_sha,
        "linkage_v2_sha256": link_sha,
        "sensitivity_sha256": sens_sha,
        "primary_universe_before": output["scored_universe"]["before"],
        "primary_universe_after": output["scored_universe"]["after"],
        "rank_changes": rank_changes,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
