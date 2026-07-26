# Exact V0 baseline regression for the four canonical builds.

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from build_manifest import load_and_verify_manifest, sha256_file
from paths import build_manifest_for, fixture_json_for, gt_json_for
from scores import (
    load_ground_truth,
    reports_to_dict,
    score_case,
    score_v0_baseline,
)


CASES = [
    {
        "case": "family_graph_01",
        "build": "O3S",
        "source_sha256": "09fb7950f565fb81ab9bb980270bc8b15ec39e538bca7d6d1ae7b704a9721a6c",
        "gt_sha256": "3cf6cd7edad1fc14fdecf33ffd529eb884f9bb4cb8f819b1b90c0cdf330b9fb6",
        "fixture_sha256": "014a5de1f9baed7972fa62c70f5651fb5989d353c92413cbd6d69d1d325f5874",
        "origin_sizes": {"shared_recursive": 3, "process": 3},
        "rounds": 1,
        "counts": (6, 0, 0, 9),
        "metrics": (1.00, 1.00, 1.00, 1.00),
        "clusters": (
            ("FUN_00113c00", "FUN_00113ce0", "FUN_00113d60"),
            ("FUN_00114240", "FUN_00114420", "FUN_00114660"),
        ),
        "origin_scores": {
            "shared_recursive": (3, 1, 3, 3, ()),
            "process": (3, 1, 3, 3, ()),
        },
    },
    {
        "case": "family_graph_02",
        "build": "O3S",
        "source_sha256": "ee46b32e80732e0226b3f443d3aac63d712bf1e19c625b155beb14098f7d60e6",
        "gt_sha256": "04d8121ba4aa8903f137cdb96d90250d396dc02c18322e80c46990ebe522da17",
        "fixture_sha256": "679928784f850885448582bb2a1b228cf2721c8db80a9d23c735f1e9f2fb6c10",
        "origin_sizes": {
            "process_beta": 2,
            "recurse_beta": 2,
            "process_alpha": 2,
            "recurse_alpha": 2,
            "c_process_alpha_i32": 1,
            "c_recurse_alpha_i32": 1,
            "c_process_alpha_wide": 1,
            "c_recurse_alpha_wide": 1,
        },
        "rounds": 2,
        "counts": (4, 10, 0, 52),
        "metrics": (0.29, 1.00, 0.44, 0.39),
        "clusters": (
            ("FUN_00113db0", "FUN_00113ed0"),
            ("FUN_00114130", "FUN_001142b0"),
            ("FUN_00114370", "FUN_001145d0", "FUN_001148a0", "FUN_00114a50"),
            ("FUN_001146f0", "FUN_00114780", "FUN_001149c0", "FUN_00114cc0"),
        ),
        "origin_scores": {
            "process_beta": (2, 1, 1, 1, ()),
            "recurse_beta": (2, 1, 1, 1, ()),
            "process_alpha": (
                2, 1, 1, 1,
                ("c_process_alpha_i32", "c_process_alpha_wide"),
            ),
            "recurse_alpha": (
                2, 1, 1, 1,
                ("c_recurse_alpha_i32", "c_recurse_alpha_wide"),
            ),
            "c_process_alpha_i32": (
                1, 1, 0, 0,
                ("c_process_alpha_wide", "process_alpha"),
            ),
            "c_recurse_alpha_i32": (
                1, 1, 0, 0,
                ("c_recurse_alpha_wide", "recurse_alpha"),
            ),
            "c_process_alpha_wide": (
                1, 1, 0, 0,
                ("c_process_alpha_i32", "process_alpha"),
            ),
            "c_recurse_alpha_wide": (
                1, 1, 0, 0,
                ("c_recurse_alpha_i32", "recurse_alpha"),
            ),
        },
    },
    {
        "case": "family_graph_03",
        "build": "O3S",
        "source_sha256": "f619cb2cf6b96756592c955895dcef822081333d42c018fc5b9c5f7e204a8d4e",
        "gt_sha256": "2da5b46c84b7607b78b2a55c05822d7945f41dcc6853c91a23d70fa3cf0a2184",
        "fixture_sha256": "ceae872e6cf2c14df7952ed89744af4813a4da9cdea6cbe2222793f367d06bd3",
        "origin_sizes": {
            "share": 3,
            "leaf_p": 2,
            "decoy_a": 1,
            "decoy_b": 1,
            "drive_x": 3,
            "drive_y": 3,
        },
        "rounds": 2,
        "counts": (4, 1, 6, 67),
        "metrics": (0.80, 0.40, 0.53, 0.49),
        "clusters": (
            ("FUN_00114470", "FUN_001147f0"),
            ("FUN_00114b50",),
            ("FUN_00115040", "FUN_001152b0"),
            ("FUN_001154c0", "FUN_001155c0"),
            ("FUN_00115740", "FUN_00115990"),
            ("FUN_00115c50",),
            ("FUN_00115de0", "FUN_00116110"),
            ("FUN_00116370",),
        ),
        "origin_scores": {
            "share": (3, 2, 1, 3, ()),
            "leaf_p": (2, 1, 1, 1, ()),
            "decoy_a": (1, 1, 0, 0, ("decoy_b",)),
            "decoy_b": (1, 1, 0, 0, ("decoy_a",)),
            "drive_x": (3, 2, 1, 3, ()),
            "drive_y": (3, 2, 1, 3, ()),
        },
    },
    {
        "case": "family_graph_03",
        "build": "O3KS",
        "source_sha256": "f619cb2cf6b96756592c955895dcef822081333d42c018fc5b9c5f7e204a8d4e",
        "gt_sha256": "099e5b7b34e502f570753e5929abfeddf6e6d0902849ee3ed4a018fa4611b8c0",
        "fixture_sha256": "6f4b1310ee94899e6b0af89ebd06b3de68dd0fadd2f7508d0252e61a5329be0c",
        "origin_sizes": {
            "share": 3,
            "leaf_p": 3,
            "leaf_q": 3,
            "decoy_a": 1,
            "decoy_b": 1,
            "drive_x": 3,
            "drive_y": 3,
        },
        "rounds": 2,
        "counts": (15, 1, 0, 120),
        "metrics": (0.94, 1.00, 0.97, 0.96),
        "clusters": (
            ("FUN_00114500", "FUN_001146c0", "FUN_00114810"),
            ("FUN_00114900", "FUN_00114b70", "FUN_00114cd0"),
            ("FUN_00114ee0", "FUN_00115030", "FUN_00115220"),
            ("FUN_00115460", "FUN_00115560"),
            ("FUN_001156e0", "FUN_00115930", "FUN_00115bf0"),
            ("FUN_00115d80", "FUN_001160b0", "FUN_00116310"),
        ),
        "origin_scores": {
            "share": (3, 1, 3, 3, ()),
            "leaf_p": (3, 1, 3, 3, ()),
            "leaf_q": (3, 1, 3, 3, ()),
            "decoy_a": (1, 1, 0, 0, ("decoy_b",)),
            "decoy_b": (1, 1, 0, 0, ("decoy_a",)),
            "drive_x": (3, 1, 3, 3, ()),
            "drive_y": (3, 1, 3, 3, ()),
        },
    },
]


def main() -> int:
    all_ok = True

    for expected in CASES:
        case = expected["case"]
        build = expected["build"]
        verified = load_and_verify_manifest(
            build_manifest_for(case, build),
            expected_case=case,
            expected_build=build,
        )
        report = score_case(fixture_json_for(case, build), gt_json_for(case, build))
        gt = load_ground_truth(gt_json_for(case, build))

        origin_sizes = {group.origin: len(group.members) for group in gt.origins}
        counts = (
            report.pairwise.tp,
            report.pairwise.fp,
            report.pairwise.fn,
            report.pairwise.tn,
        )
        metrics = tuple(round(value, 2) for value in (
            report.pairwise.precision,
            report.pairwise.recall,
            report.pairwise.f1,
            report.pairwise.ari,
        ))
        clusters = tuple(cluster.member_ids for cluster in report.clusters)
        origin_scores = {
            row.origin: (
                row.k_obs,
                row.predicted_cluster_count,
                row.recovered_pairs,
                row.total_pairs,
                row.colliding_origins,
            )
            for row in report.origins
        }

        checks = {
            "source hash": sha256_file(verified.source) == expected["source_sha256"],
            "GT binary hash": sha256_file(verified.non_stripped_binary) == expected["gt_sha256"],
            "fixture binary hash": sha256_file(verified.stripped_binary) == expected["fixture_sha256"],
            "origin census": origin_sizes == expected["origin_sizes"],
            "candidate count": report.candidate_count == sum(expected["origin_sizes"].values()),
            "rounds": report.rounds == expected["rounds"],
            "pair counts": counts == expected["counts"],
            "pair total": report.pair_count == sum(counts),
            "metrics": metrics == expected["metrics"],
            "clusters": clusters == expected["clusters"],
            "origin scores": origin_scores == expected["origin_scores"],
        }
        failed = [name for name, ok in checks.items() if not ok]
        ok = not failed
        all_ok = all_ok and ok
        tag = "PASS" if ok else f"FAIL ({', '.join(failed)})"
        print(
            f"{case}/{build}: n={report.candidate_count} TP={counts[0]} FP={counts[1]} "
            f"FN={counts[2]} TN={counts[3]} PR={metrics[0]:.2f} "
            f"RE={metrics[1]:.2f} F1={metrics[2]:.2f} ARI={metrics[3]:.2f} {tag}"
        )

    baseline_path = Path(__file__).resolve().parents[1] / "results" / "v0_baseline.json"
    stored_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    generated_baseline = reports_to_dict(score_v0_baseline())
    baseline_ok = stored_baseline == generated_baseline
    all_ok = all_ok and baseline_ok
    print(f"baseline score JSON: {'PASS' if baseline_ok else 'FAIL'}")
    print("ALL PASS" if all_ok else "SOME FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
