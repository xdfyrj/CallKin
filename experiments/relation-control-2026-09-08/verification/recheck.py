"""Independently rescore retained relation-control predictions in a bundle."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import sys
from collections import defaultdict
from itertools import combinations
from math import comb
from pathlib import Path


if len(sys.argv) > 1:
    ROOT = Path(sys.argv[1]).resolve()
else:
    ROOT = Path(__file__).resolve().parents[1]
    if not (ROOT / "linkage_overlay.py").is_file():
        ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from linkage_overlay import NEGATIVE, POSITIVE, label_pair, load_overlay  # noqa: E402


METRICS = ("TP", "FP", "FN", "TN", "precision", "recall", "f1")
TERMINAL = {"completed", "budget-refused", "resource-incomplete"}


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _join(prediction, ground_truth, linkage):
    ids = prediction["universe"]["target_ids"]
    expected = set(ids)
    if len(ids) != len(expected):
        raise ValueError("prediction target IDs are not unique")
    members = [member for group in ground_truth.get("origins", []) for member in group["members"]]
    addresses = linkage.get("addresses", {})
    if len(members) != len(set(members)) or set(members) != expected:
        raise ValueError("ground-truth target join failed")
    if set(addresses) != expected:
        raise ValueError("linkage target join failed")
    return expected


def counts(prediction, ground_truth, linkage):
    ids = _join(prediction, ground_truth, linkage)
    origins, identities = load_overlay(linkage)
    clean = [member for member in ids if identities.get(member) and len(set(origins.get(member, ()))) == 1]
    by_origin = defaultdict(list)
    for member in clean:
        by_origin[origins[member][0]].append(member)
    positives = 0
    within = 0
    for members in by_origin.values():
        within += comb(len(members), 2)
        positives += sum(
            label_pair(left, right, origins_by_address=origins, identities_by_address=identities) == POSITIVE
            for left, right in combinations(members, 2)
        )
    negatives = comb(len(clean), 2) - within
    predicted, seen = set(), set()
    for group in prediction.get("clusters", []):
        if group.get("status") != "accepted":
            continue
        members = set(group["members"])
        if members & seen or not members <= ids:
            raise ValueError("invalid predicted partition")
        seen.update(members)
        predicted.update(combinations(sorted(members), 2))
    tp = sum(label_pair(left, right, origins_by_address=origins, identities_by_address=identities) == POSITIVE for left, right in predicted)
    fp = sum(label_pair(left, right, origins_by_address=origins, identities_by_address=identities) == NEGATIVE for left, right in predicted)
    result = {"TP": tp, "FP": fp, "FN": positives - tp, "TN": negatives - fp}
    if result["TP"] + result["FP"] + result["FN"] + result["TN"] != positives + negatives:
        raise ValueError("pair count conservation failed")
    result.update({
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + result["FN"]) if tp + result["FN"] else None,
        "f1": 2 * tp / (2 * tp + fp + result["FN"]) if 2 * tp + fp + result["FN"] else None,
    })
    return result


def same(a, b):
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isclose(float(a), float(b), rel_tol=1e-12, abs_tol=1e-12)
    return a == b


def check_metrics(got, expected, label):
    if expected is None:
        if got is not None:
            raise ValueError(f"{label} quality is not NA")
        return
    if not isinstance(got, dict) or not isinstance(expected, dict) or any(not same(got.get(key), expected.get(key)) for key in METRICS):
        raise ValueError(f"{label} metrics differ: {got} != {expected}")


def check_summary(expected):
    with (ROOT / "results-summary.csv").open(newline="", encoding="utf-8") as stream:
        csv_rows = list(csv.DictReader(stream))
    index = {(row["case"], row["arm"]): row for row in csv_rows}
    if len(index) != len(csv_rows):
        raise ValueError("results-summary.csv contains duplicate arm rows")
    if set(index) != {(row["case"], row["arm"]) for row in expected}:
        raise ValueError("results-summary.csv arm set differs")
    for row in expected:
        actual = index[(row["case"], row["arm"])]
        if actual["status"] != row["status"]:
            raise ValueError("results-summary.csv status differs")
        for key in ("TP", "FP", "FN", "TN", "precision", "recall", "f1"):
            value = row["primary"].get(key) if row["status"] == "completed" else None
            cell = actual[key]
            if value is None:
                if cell != "NA":
                    raise ValueError(f"noncompleted {key} is not NA")
            elif not same(float(cell), value):
                raise ValueError(f"summary {key} differs for {row['case']}/{row['arm']}")


def check_sensitivity(expected):
    sensitivity = read(ROOT / "source-corrected-sensitivity.json")
    for case in ("fd", "zoxide"):
        rows = {row["arm"]: row for row in sensitivity.get(case, {}).get("rows", [])}
        for item in (row for row in expected if row["case"] == case):
            actual = rows.get(item["arm"])
            if actual is None:
                raise ValueError(f"sensitivity row missing: {case}/{item['arm']}")
            if actual.get("prediction_sha256") != item.get("prediction_sha256"):
                raise ValueError("sensitivity prediction identity differs")
            check_metrics(actual.get("primary"), item["primary"], "sensitivity primary")
            check_metrics(actual.get("secondary"), item["original"], "sensitivity original")
    if "ripgrep-main" in sensitivity:
        raise ValueError("ripgrep-main must not claim corrected sensitivity")


def recheck():
    manifest = read(ROOT / "manifest.json")
    for name, expected in manifest.items():
        path = ROOT / name
        if not path.is_file() or digest(path) != expected:
            raise ValueError("file identity mismatch: " + name)
    config = read(ROOT / "config.json")
    snapshot = read(ROOT / "snapshot.json")
    if snapshot.get("config_sha256") != digest(ROOT / "config.json") or snapshot.get("protocol_sha256") != digest(ROOT / "protocol.md"):
        raise ValueError("frozen config/protocol identity mismatch")
    labels = read(ROOT / "labels-manifest.json")
    for case, roles in labels.items():
        for role, records in roles.items():
            for name, record in records.items():
                path = ROOT / record["path"]
                if digest(path) != record["sha256"] or (
                    record.get("expected_sha256")
                    and digest(path) != record["expected_sha256"]
                ):
                    raise ValueError(f"label identity mismatch: {case}/{role}/{name}")
    expected = read(ROOT / "expected-results.json")
    arms = (config["arms"]["treatment"], *config["arms"]["controls"])
    if {(row["case"], row["arm"]) for row in expected} != {(case, arm) for case in config["cases"] for arm in arms}:
        raise ValueError("expected-results arm set is incomplete")
    for row in expected:
        directory = ROOT / "runs" / row["case"] / row["arm"]
        metadata = read(directory / "metadata.json")
        if metadata.get("status") != row["status"] or digest(directory / "metadata.json") != row["metadata_sha256"]:
            raise ValueError("metadata identity differs")
        if row["status"] not in TERMINAL:
            raise ValueError("unknown arm status")
        if row["status"] != "completed":
            if row["primary"] is not None or row["original"] is not None or (directory / "prediction.json").exists():
                raise ValueError("NA arm contains quality or prediction")
            continue
        prediction_path = directory / "prediction.json"
        if metadata.get("prediction_sha256") != row.get("prediction_sha256") or digest(prediction_path) != row["prediction_sha256"]:
            raise ValueError("prediction identity differs")
        prediction = read(prediction_path)
        primary = labels[row["case"]]["primary"]
        original = labels[row["case"]]["original"]
        primary_counts = counts(prediction, read(ROOT / primary["ground_truth"]["path"]), read(ROOT / primary["linkage"]["path"]))
        original_counts = counts(prediction, read(ROOT / original["ground_truth"]["path"]), read(ROOT / original["linkage"]["path"]))
        check_metrics(primary_counts, row["primary"], "primary")
        check_metrics(original_counts, row["original"], "original")
    check_summary(expected)
    check_sensitivity(expected)
    print(f"PASS: {sum(row['status'] == 'completed' for row in expected)} retained predictions rescored; {sum(row['status'] != 'completed' for row in expected)} terminal NA states preserved.")


if __name__ == "__main__":
    recheck()
