"""Independently verify a retained novel-source rescore bundle.

This checker uses only the bundled predictions, original GT/linkage, pinned
exposure labels, and the bundled linkage policy. It does not rebuild a source,
observe a binary, or rerun inference.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import defaultdict
from itertools import combinations
from math import comb
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from linkage_overlay import NEGATIVE, POSITIVE, label_pair, load_overlay

CASES = ("hexyl-v0170", "hyperfine-v1200", "tokei-v1500")
ARMS = (
    "V0-relation", "exact-token-hash", "B2-token-cfg",
    "C3-token-cfg-relation", "B2-body-score", "C3-rescue",
)
QUALITY_KEYS = (
    "TP", "FP", "FN", "TN", "precision", "recall", "f1",
    "macro_origin_recall", "exact_group_rate", "positive_pairs", "scored_pairs",
)


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def target_ids(artifact: dict[str, Any]) -> tuple[str, ...]:
    values = artifact.get("universe", {}).get("target_ids")
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values) or len(set(values)) != len(values):
        raise ValueError("invalid prediction target universe")
    return tuple(sorted(values))


def truth(ids: tuple[str, ...], linkage: dict[str, Any]):
    origins, identities = load_overlay(linkage)
    valid = [item for item in ids if origins.get(item) and identities.get(item)]
    clean = [item for item in valid if len(set(origins[item])) == 1]
    groups: dict[str, list[str]] = defaultdict(list)
    for item in clean:
        groups[origins[item][0]].append(item)
    positive: set[tuple[str, str]] = set()
    per_origin: dict[str, set[tuple[str, str]]] = {}
    within = 0
    for origin, members in groups.items():
        within += comb(len(members), 2)
        pairs = {
            pair for pair in combinations(sorted(members), 2)
            if label_pair(pair[0], pair[1], origins_by_address=origins, identities_by_address=identities) == POSITIVE
        }
        positive.update(pairs)
        per_origin[origin] = pairs
    negative = comb(len(clean), 2) - within
    return origins, identities, positive, per_origin, negative


def score_prediction(prediction: dict[str, Any], gt: dict[str, Any], linkage: dict[str, Any]) -> dict[str, Any]:
    ids = target_ids(prediction)
    origins, identities, positive, per_origin_pairs, negative = truth(ids, linkage)
    target = set(ids)
    predicted: set[tuple[str, str]] = set()
    seen: set[str] = set()
    groups = []
    for group in prediction.get("clusters", ()):
        if group.get("status") != "accepted":
            continue
        members = set(group.get("members", ()))
        if not members <= target or members & seen:
            raise ValueError("invalid accepted prediction partition")
        seen.update(members)
        groups.append(members)
        predicted.update(combinations(sorted(members), 2))
    tp = sum(label_pair(a, b, origins_by_address=origins, identities_by_address=identities) == POSITIVE for a, b in predicted)
    fp = sum(label_pair(a, b, origins_by_address=origins, identities_by_address=identities) == NEGATIVE for a, b in predicted)
    fn, tn = len(positive) - tp, negative - fp
    gt_groups = {group["origin"]: set(group["members"]) & target for group in gt.get("origins", ()) if isinstance(group, dict)}
    per_origin = []
    for origin, pairs in sorted(per_origin_pairs.items()):
        if not pairs:
            continue
        members = gt_groups.get(origin, set())
        hits = len(pairs & predicted)
        per_origin.append({"origin": origin, "positive_pairs": len(pairs), "recovered_pairs": hits, "recall": hits / len(pairs), "target_members": len(members), "exact_group": bool(members) and any(group == members for group in groups)})
    return {
        "target_count": len(ids), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "positive_pairs": len(positive), "scored_pairs": len(positive) + negative,
        "per_origin": per_origin,
        "macro_origin_recall": sum(item["recall"] for item in per_origin) / len(per_origin) if per_origin else None,
        "exact_group_rate": sum(item["exact_group"] for item in per_origin) / len(per_origin) if per_origin else None,
    }


def clip(prediction: dict[str, Any], mask: set[str]) -> dict[str, Any]:
    clipped = {**prediction, "universe": {"target_ids": sorted(mask)}}
    clipped["clusters"] = []
    for group in prediction.get("clusters", ()):
        members = sorted(set(group.get("members", ())) & mask)
        if len(members) >= 2:
            clipped["clusters"].append({"members": members, "status": group.get("status", "accepted")})
    return clipped


def exposed(root: Path, manifest: dict[str, Any]) -> set[str]:
    descriptor = manifest["exposure_inventory"]["normalized_origin_label_set"]
    path = root / "study" / "exposed-origins.json"
    if digest(path) != descriptor["sha256"]:
        raise ValueError("exposed-origin artifact hash mismatch")
    labels = read(path)
    if not isinstance(labels, list) or labels != sorted(set(labels)) or any(not isinstance(label, str) for label in labels):
        raise ValueError("exposed-origin artifact is not sorted and unique")
    if digest(path) != descriptor["sha256"] or hashlib.sha256(canonical(labels)).hexdigest() != descriptor["sha256"]:
        raise ValueError("exposed-origin canonical hash mismatch")
    return set(labels)


def masks(config: dict[str, Any], case: str, linkage: dict[str, Any], ids: tuple[str, ...], known: set[str]) -> dict[str, set[str]]:
    source = next(item for item in config["sources"] if item.get("id") == case)
    namespaces = tuple(source["namespaces"])
    origins, _ = load_overlay(linkage)
    project = {item for item in ids if len(origins.get(item, ())) == 1 and (origins[item][0].startswith(tuple(f"{n}::" for n in namespaces)) or any(origins[item][0].startswith(f"<{n}::") for n in namespaces))}
    unobserved = {item for item in ids if len(origins.get(item, ())) == 1 and origins[item][0] not in known}
    return {"project_owned": project, "previously_unobserved_normalized_origin": unobserved}


def close(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isclose(float(a), float(b), rel_tol=1e-12, abs_tol=1e-12)
    return a == b


def compare(expected: dict[str, Any], actual: dict[str, Any], label: str) -> None:
    for key in QUALITY_KEYS:
        if not close(expected.get(key), actual.get(key)):
            raise ValueError(f"{label} metric mismatch: {key}: {expected.get(key)!r} != {actual.get(key)!r}")
    if not isinstance(expected.get("per_origin"), list):
        raise ValueError(f"{label} omitted per-origin report")
    stages = expected.get("positive_first_outcome")
    if stages is not None and sum(stages.values()) != expected.get("positive_pairs"):
        raise ValueError(f"{label} stage totals do not conserve positive pairs")


def verify(root: Path) -> dict[str, Any]:
    manifest = read(root / "manifest.json")
    members = manifest.get("members")
    if not isinstance(members, dict) or manifest.get("member_count") != len(members):
        raise ValueError("bundle manifest is invalid")
    for name, expected in members.items():
        path = root / name
        if not path.is_file() or digest(path) != expected:
            raise ValueError(f"bundle member hash mismatch: {name}")
        if name.endswith((".log", ".sh", ".resource.txt")):
            raise ValueError(f"raw Real dump was included: {name}")
    config = read(root / "study/config.json")
    hash_manifest = read(root / "study/hash-manifest.json")
    protocol_path = root / "study/protocol.md"
    if config.get("protocol_sha256") != digest(protocol_path):
        raise ValueError("bundled protocol/config identity mismatch")
    if manifest.get("evaluator_sha256") != digest(root / "study/evaluator.py"):
        raise ValueError("bundled evaluator hash mismatch")
    implementation_hashes = hash_manifest.get("implementation_sha256")
    if not isinstance(implementation_hashes, dict) or not implementation_hashes:
        raise ValueError("bundled implementation hashes are not frozen")
    known = exposed(root, hash_manifest)
    if tuple(config.get("cases", ())) != CASES:
        raise ValueError("bundled case order mismatch")
    verified_predictions = verified_views = 0
    for case in CASES:
        gt = read(root / f"labels/{case}/ground_truth.json")
        linkage = read(root / f"labels/{case}/linkage.json")
        ids: tuple[str, ...] | None = None
        predictions: dict[str, dict[str, Any]] = {}
        score_file = read(root / f"scores/{case}/scores.json")
        if score_file.get("status") != "scored":
            raise ValueError(f"{case} score is not marked scored")
        score_provenance = score_file.get("provenance", {})
        if score_provenance.get("config_sha256") != digest(root / "study/config.json") or score_provenance.get("protocol_sha256") != digest(root / "study/protocol.md"):
            raise ValueError(f"{case} score config/protocol identity mismatch")
        if score_provenance.get("scoring_python") != "3.12.3":
            raise ValueError(f"{case} score Python identity mismatch")
        for arm in ARMS:
            directory = root / f"predictions/{case}/{arm}"
            metadata, prediction_path = read(directory / "metadata.json"), directory / "prediction.json"
            if metadata.get("status") != "completed" or metadata.get("case") != case or metadata.get("arm") != arm:
                raise ValueError(f"{case}/{arm} metadata identity mismatch")
            if metadata.get("prediction_sha256") != digest(prediction_path):
                raise ValueError(f"{case}/{arm} prediction hash mismatch")
            if metadata.get("implementation_sha256") != implementation_hashes:
                raise ValueError(f"{case}/{arm} implementation hash mismatch")
            prediction = read(prediction_path)
            actual_ids = target_ids(prediction)
            ids = actual_ids if ids is None else ids
            if actual_ids != ids:
                raise ValueError(f"{case}/{arm} target universe mismatch")
            if prediction.get("artifact") == "novel-source-prediction" and prediction.get("arm") != arm:
                raise ValueError(f"{case}/{arm} simple prediction arm mismatch")
            provenance = prediction.get("provenance", {})
            if provenance.get("candidate_artifact_sha256") not in (None, metadata.get("candidate_sha256")):
                raise ValueError(f"{case}/{arm} candidate provenance mismatch")
            predictions[arm] = prediction
            verified_predictions += 1
        if ids is None:
            raise ValueError(f"{case} has no predictions")
        origins = gt.get("origins", ())
        gt_ids = {member for group in origins if isinstance(group, dict) for member in group.get("members", ())}
        linkage_ids = set(linkage.get("addresses", {}))
        if gt_ids != set(ids) or linkage_ids != set(ids):
            raise ValueError(f"{case} label target universe mismatch")
        views = {"primary": set(ids), **masks(config, case, linkage, ids, known)}
        scored_arms = score_file.get("arms", {})
        for arm, prediction in predictions.items():
            row = scored_arms.get(arm)
            if not isinstance(row, dict):
                raise ValueError(f"{case}/{arm} score row is missing")
            actual_primary = score_prediction(prediction, gt, linkage)
            compare(row.get("metrics", {}), actual_primary, f"{case}/{arm}/primary")
            verified_views += 1
            for view, mask in views.items():
                if view == "primary":
                    continue
                actual = score_prediction(clip(prediction, mask), gt, linkage)
                expected = row.get("secondary", {}).get(view, {}).get("metrics")
                if not isinstance(expected, dict):
                    raise ValueError(f"{case}/{arm}/{view} score row is missing")
                compare(expected, actual, f"{case}/{arm}/{view}")
                if expected.get("mask_size") != len(mask) or expected.get("mask_positive_pairs") != actual["positive_pairs"]:
                    raise ValueError(f"{case}/{arm}/{view} mask accounting mismatch")
                verified_views += 1
        csv_path = root / f"scores/{case}/summary.csv"
        rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
        if len(rows) != len(ARMS) * 3 or {row["label_view"] for row in rows} != set(views):
            raise ValueError(f"{case} compact CSV shape mismatch")
    if verified_predictions != 18 or verified_views != 54:
        raise ValueError(f"unexpected verification counts: {verified_predictions} predictions, {verified_views} views")
    return {"status": "verified", "predictions": verified_predictions, "views": verified_views, "kind": manifest.get("kind")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify(args.root.resolve()), sort_keys=True))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
