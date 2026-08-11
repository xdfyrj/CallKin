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


def family_counts(result: dict[str, Any]) -> dict[str, int]:
    families = [
        origin for origin in result.get("origins", [])
        if origin.get("total_target_pairs", origin.get("total_pairs", 0)) > 0
    ]
    counts = {
        "evidence_full": 0,
        "evidence_partial": 0,
        "evidence_insufficient": 0,
        "recovery_complete": 0,
        "recovery_partial": 0,
        "recovery_missed": 0,
        "recovery_na": 0,
        "collision": 0,
    }
    for origin in families:
        scored_pairs = origin.get("total_pairs", 0)
        abstained = origin.get("abstained_instance_count", 0)
        recovered = origin.get("recovered_pairs", 0)

        if scored_pairs == 0:
            counts["evidence_insufficient"] += 1
            counts["recovery_na"] += 1
        else:
            evidence = "partial" if abstained else "full"
            counts[f"evidence_{evidence}"] += 1
            if recovered == scored_pairs:
                counts["recovery_complete"] += 1
            elif recovered == 0:
                counts["recovery_missed"] += 1
            else:
                counts["recovery_partial"] += 1
        counts["collision"] += bool(origin.get("colliding_origins"))
    return counts


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
            gt.get("target_count", gt.get("candidate_count")),
            gt.get("origin_count"),
            gt.get("generic_family_count"),
            gt.get("singleton_origin_count"),
            gt.get("same_family_pair_count"),
            size.get("median"),
            size.get("max"),
        ])
    print_table(
        "Ground truth",
        ["PROFILE", "TARGET", "ORIGIN", "FAMILY", "SINGLE", "TRUE_PAIRS", "FAM_MED", "FAM_MAX"],
        gt_rows,
    )

    score_rows = []
    coverage_rows = []
    family_rows = []
    for record in records:
        result = record["result"]
        analysis = result.get("analysis", {})
        pairwise = result.get("pairwise", {})
        coverage = result.get("coverage", {})
        families = family_counts(result)
        identity = [
            result.get("profile"),
            analysis.get("track"),
            analysis.get("anchor_policy"),
            result.get("mode"),
        ]
        score_rows.append([
            *identity,
            pairwise.get("TP"),
            pairwise.get("FP"),
            pairwise.get("FN"),
            pairwise.get("TN"),
            pairwise.get("precision"),
            pairwise.get("recall"),
            pairwise.get("F1"),
            pairwise.get("ARI"),
        ])
        target = result.get("target_count", result.get("candidate_count"))
        grouped = result.get(
            "grouped_candidate_count", result.get("candidate_count")
        )
        coverage_rows.append([
            *identity,
            target,
            grouped,
            result.get("abstained_candidate_count", 0),
            coverage.get("target_coverage", 1.0 if target == grouped else None),
            coverage.get("pair_decision_coverage"),
            coverage.get("same_family_pair_coverage"),
            coverage.get("effective_family_pair_recall"),
        ])
        family_rows.append([
            *identity,
            families["evidence_full"],
            families["evidence_partial"],
            families["evidence_insufficient"],
            families["recovery_complete"],
            families["recovery_partial"],
            families["recovery_missed"],
            families["recovery_na"],
            families["collision"],
        ])
    print_table(
        "Scores",
        [
            "PROFILE", "TRACK", "ANCHOR", "MODE", "TP", "FP", "FN", "TN",
            "PREC", "RECALL", "F1", "ARI",
        ],
        score_rows,
    )
    print_table(
        "Coverage",
        [
            "PROFILE", "TRACK", "ANCHOR", "MODE", "TARGET", "GROUPED", "ABSTAIN",
            "TARGET_COV", "PAIR_COV", "FAMILY_COV", "EFFECTIVE_RECALL",
        ],
        coverage_rows,
    )
    print_table(
        "Family status",
        [
            "PROFILE", "TRACK", "ANCHOR", "MODE", "E_FULL", "E_PART", "E_INSUFF",
            "R_COMPLETE", "R_PART", "R_MISSED", "R_N/A", "COLLISION",
        ],
        family_rows,
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
        legacy_candidate_count = observable.get("candidate_count")
        graph_rows.append([
            result.get("profile"),
            track,
            observable.get("target_count", legacy_candidate_count),
            observable.get("grouped_candidate_count", legacy_candidate_count),
            observable.get(
                "abstained_candidate_count",
                0 if legacy_candidate_count is not None else None,
            ),
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
        [
            "PROFILE", "TRACK", "TARGET", "GROUPED", "ABSTAIN", "NODES",
            "REACH", "UNREACH", "ISOLATED", "SEC", "RSS_MB", "WARN",
        ],
        graph_rows,
    )

    exact_rows = []
    indirect_rows = []
    for record in graph_records:
        result = record["result"]
        track = value(record, "result", "analysis", "track")
        exact_summaries = value(
            record,
            "summary",
            "extraction",
            "exact_static_indirect_summary",
            default={},
        )
        summaries = value(
            record, "summary", "extraction", "indirect_call_summary", default={}
        )
        for source_name, source_label in (
            ("all_sources", "all"),
            ("candidate_sources", "candidate"),
        ):
            exact = exact_summaries.get(source_name, {})
            by_resolver = exact.get("by_resolver", {})
            exact_rows.append([
                result.get("profile"),
                track,
                source_label,
                exact.get("total"),
                exact.get("resolved_internal"),
                exact.get("filtered_import"),
                exact.get("unmapped"),
                by_resolver.get("elf-relocation"),
            ])
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
        "Exact static indirect transfers",
        [
            "PROFILE", "TRACK", "SOURCE", "TOTAL", "INTERNAL", "FILTERED",
            "UNMAPPED", "ELF_RELOC",
        ],
        exact_rows,
    )
    print_table(
        "Angr unresolved indirect transfers",
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
