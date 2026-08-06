#!/usr/bin/env python3
"""Print the important values from CallKin result JSON files.

Examples:
    python3 analysis/summary.py results/zoxide
    python3 analysis/summary.py results/zoxide/plain/angr.role.out-in.json
    python3 analysis/summary.py results
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PROFILE_ORDER = {"plain": 0, "min": 1}
TRACK_ORDER = {"direct": 0, "direct-in": 1, "angr": 2}
ANCHOR_ORDER = {"address": 0, "role": 1}
MODE_ORDER = {"full": 0, "out": 1, "in": 2, "out-in": 3}


def result_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.rglob("*.json"))
    raise FileNotFoundError(path)


def load_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for json_path in result_files(path):
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        results = data.get("results")
        summary = data.get("run_summary")
        if not isinstance(results, list) or not isinstance(summary, dict):
            continue

        for result in results:
            if not isinstance(result, dict) or "pairwise" not in result:
                continue
            records.append({
                "path": json_path,
                "result": result,
                "summary": summary,
            })
    return records


def value(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = record
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def format_value(item: Any) -> str:
    if item is None:
        return "-"
    if isinstance(item, bool):
        return "yes" if item else "no"
    if isinstance(item, int):
        return f"{item:,}"
    if isinstance(item, float):
        return f"{item:.4f}"
    return str(item)


def print_table(title: str, headers: list[str], rows: list[list[Any]]) -> None:
    rendered = [[format_value(item) for item in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in rendered:
        for index, item in enumerate(row):
            widths[index] = max(widths[index], len(item))

    print(f"\n{title}")
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rendered:
        fields = []
        for index, item in enumerate(row):
            fields.append(item.ljust(widths[index]) if index < 4 else item.rjust(widths[index]))
        print("  ".join(fields))


def run_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
    result = record["result"]
    analysis = result.get("analysis", {})
    return (
        PROFILE_ORDER.get(result.get("profile"), 99),
        TRACK_ORDER.get(analysis.get("track"), 99),
        ANCHOR_ORDER.get(analysis.get("anchor_policy"), 99),
        MODE_ORDER.get(result.get("mode"), 99),
        str(record["path"]),
    )


def first_by(records: list[dict[str, Any]], key_fn: Any) -> list[dict[str, Any]]:
    selected: dict[Any, dict[str, Any]] = {}
    for record in sorted(records, key=run_sort_key):
        selected.setdefault(key_fn(record), record)
    return list(selected.values())


def family_counts(result: dict[str, Any]) -> tuple[int, int, int, int]:
    families = [
        origin for origin in result.get("origins", [])
        if origin.get("total_pairs", 0) > 0
    ]
    complete = sum(
        origin.get("recovered_pairs") == origin.get("total_pairs")
        for origin in families
    )
    partial = sum(
        0 < origin.get("recovered_pairs", 0) < origin.get("total_pairs", 0)
        for origin in families
    )
    missed = sum(origin.get("recovered_pairs", 0) == 0 for origin in families)
    collision = sum(bool(origin.get("colliding_origins")) for origin in families)
    return complete, partial, missed, collision


def print_case(case: str, records: list[dict[str, Any]]) -> None:
    records = sorted(records, key=run_sort_key)
    print(f"\n{'=' * 8} {case} {'=' * 8}")

    gt_records = first_by(records, lambda record: record["result"].get("profile"))
    gt_rows = []
    for record in gt_records:
        result = record["result"]
        gt = value(record, "summary", "ground_truth", default={})
        size = gt.get("family_size", {})
        gt_rows.append([
            result.get("profile"),
            gt.get("candidate_count"),
            gt.get("origin_count"),
            gt.get("generic_family_count"),
            gt.get("singleton_origin_count"),
            gt.get("same_family_pair_count"),
            size.get("median"),
            size.get("max"),
        ])
    print_table(
        "Ground truth",
        ["PROFILE", "CAND", "ORIGIN", "FAMILY", "SINGLE", "TRUE_PAIRS", "FAM_MED", "FAM_MAX"],
        gt_rows,
    )

    score_rows = []
    for record in records:
        result = record["result"]
        analysis = result.get("analysis", {})
        pairwise = result.get("pairwise", {})
        complete, partial, missed, collision = family_counts(result)
        score_rows.append([
            result.get("profile"),
            analysis.get("track"),
            analysis.get("anchor_policy"),
            result.get("mode"),
            pairwise.get("TP"),
            pairwise.get("FP"),
            pairwise.get("FN"),
            pairwise.get("TN"),
            pairwise.get("precision"),
            pairwise.get("recall"),
            pairwise.get("F1"),
            pairwise.get("ARI"),
            complete,
            partial,
            missed,
            collision,
        ])
    print_table(
        "Scores and family recovery",
        [
            "PROFILE", "TRACK", "ANCHOR", "MODE", "TP", "FP", "FN", "TN",
            "PREC", "RECALL", "F1", "ARI", "COMP", "PART", "MISS", "COLL",
        ],
        score_rows,
    )

    graph_records = first_by(
        records,
        lambda record: (
            record["result"].get("profile"),
            value(record, "result", "analysis", "track"),
        ),
    )
    graph_rows = []
    for record in graph_records:
        result = record["result"]
        track = value(record, "result", "analysis", "track")
        artifact = value(record, "summary", "artifact_summary", default={})
        observable = value(record, "summary", "candidate_observability", default={})
        execution = value(record, "summary", "execution", default={})
        duration = execution.get("duration_seconds", {})
        graph_rows.append([
            result.get("profile"),
            track,
            artifact.get("fixture_node_count"),
            observable.get("reachable_from_root"),
            observable.get("unreachable_from_root"),
            observable.get("fully_isolated"),
            duration.get("total"),
            execution.get("peak_rss_mb"),
            sum(warning.get("count", 0) for warning in execution.get("warnings", [])),
        ])
    print_table(
        "Graph and execution",
        ["PROFILE", "TRACK", "NODES", "REACH", "UNREACH", "ISOLATED", "SEC", "RSS_MB", "WARN"],
        graph_rows,
    )

    indirect_rows = []
    for record in graph_records:
        result = record["result"]
        track = value(record, "result", "analysis", "track")
        summaries = value(
            record, "summary", "extraction", "indirect_call_summary", default={}
        )
        for source_name, source_label in (
            ("all_sources", "all"),
            ("candidate_sources", "candidate"),
        ):
            indirect = summaries.get(source_name, {})
            indirect_rows.append([
                result.get("profile"),
                track,
                source_label,
                indirect.get("analysis_status"),
                indirect.get("total"),
                indirect.get("resolved_internal"),
                indirect.get("resolved_import"),
                indirect.get("unresolved"),
                indirect.get("target_resolution_rate"),
                indirect.get("internal_resolution_rate"),
            ])
    print_table(
        "Indirect calls",
        [
            "PROFILE", "TRACK", "SOURCE", "STATUS", "TOTAL", "INTERNAL",
            "IMPORT", "UNRES", "TARGET_RATE", "INTERNAL_RATE",
        ],
        indirect_rows,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print compact tables from CallKin result JSON files."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="results",
        help="result JSON file or directory (default: results)",
    )
    args = parser.parse_args()

    try:
        records = load_records(Path(args.path))
    except FileNotFoundError as exc:
        parser.error(f"path not found: {exc}")

    if not records:
        parser.error(f"no CallKin score JSON found under {args.path}")

    cases: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        case = str(record["result"].get("case", "unknown"))
        cases.setdefault(case, []).append(record)

    for case in sorted(cases):
        print_case(case, cases[case])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
