# Exact baseline regression for the plain and min compiler profiles.

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from build_manifest import load_and_verify_manifest, sha256_file
from paths import (
    BUILD_PROFILES,
    baseline_result_for,
    build_manifest_for,
    fixture_json_for,
    gt_json_for,
    SUBJECT_CANDIDATE_SCOPE,
)
from scores import _pairwise_score, reports_to_dict, score_case, score_v0_baseline


CASES = (
    {
        "profile": "plain", "case": "family_graph_01", "build": "O3S",
        "source": "09fb7950f565fb81ab9bb980270bc8b15ec39e538bca7d6d1ae7b704a9721a6c",
        "gt": "872b47d8fb3323334e8cd67fb081a45fdc3354cdf026841f31be689e6c73f71f",
        "fixture": "dbab836138697518b9866e29036bd6836889760a5401e445654d2d86568cf056",
        "candidates": 6, "rounds": 1, "counts": (6, 0, 0, 9),
        "metrics": (1.00, 1.00, 1.00, 1.00),
    },
    {
        "profile": "plain", "case": "family_graph_02", "build": "O3S",
        "source": "ee46b32e80732e0226b3f443d3aac63d712bf1e19c625b155beb14098f7d60e6",
        "gt": "1114e027ef8560140bda90e4b1bd0f0a445c73798d4cbe09e8da8756f22307e0",
        "fixture": "36689059de093215ebee7a200c7a2e72b912fed25c66cf55e7774d551ff4aac5",
        "candidates": 12, "rounds": 2, "counts": (4, 10, 0, 52),
        "metrics": (0.29, 1.00, 0.44, 0.39),
    },
    {
        "profile": "plain", "case": "family_graph_03", "build": "O3S",
        "source": "f619cb2cf6b96756592c955895dcef822081333d42c018fc5b9c5f7e204a8d4e",
        "gt": "e36fb58c0e1ac911d5f9ab13449429915a58229e9ac9fe13cf7a584b3489901c",
        "fixture": "fa79faf3f4359e3ed083cd9222e2ae162b7f056d1363ea57391a6405e2212f80",
        "candidates": 13, "rounds": 2, "counts": (4, 1, 6, 67),
        "metrics": (0.80, 0.40, 0.53, 0.49),
    },
    {
        "profile": "plain", "case": "family_graph_03", "build": "O3KS",
        "source": "f619cb2cf6b96756592c955895dcef822081333d42c018fc5b9c5f7e204a8d4e",
        "gt": "d6460699d9cb3c5723f7133dead7a1cd02b1f84ba72600f1c75a6bcb9ed5fcdd",
        "fixture": "623ec2db63a4bbe3088e622910333e0bedaf9b072c4aae7b1e1fe7072959603e",
        "candidates": 17, "rounds": 2, "counts": (15, 1, 0, 120),
        "metrics": (0.94, 1.00, 0.97, 0.96),
    },
    {
        "profile": "min", "case": "family_graph_01", "build": "O3S",
        "source": "09fb7950f565fb81ab9bb980270bc8b15ec39e538bca7d6d1ae7b704a9721a6c",
        "gt": "f0270488b6b7fc384e11a1c1bfa6fe33de47c99f605ce28daa6ef2e937dfb6fa",
        "fixture": "e6fe21fe673971825619482646bdef76847a8283ee8982a53112e41ef05210fb",
        "candidates": 6, "rounds": 1, "counts": (6, 0, 0, 9),
        "metrics": (1.00, 1.00, 1.00, 1.00),
    },
    {
        "profile": "min", "case": "family_graph_02", "build": "O3S",
        "source": "ee46b32e80732e0226b3f443d3aac63d712bf1e19c625b155beb14098f7d60e6",
        "gt": "5f01ec9c81bcd305ada546bba34ae4efdbde24c7497c233881a8fad7ea06396c",
        "fixture": "aad46cd96981b844d73e9b3ec8c4313382fc1d4634a6c540e9f10da651b61fec",
        "candidates": 12, "rounds": 2, "counts": (4, 10, 0, 52),
        "metrics": (0.29, 1.00, 0.44, 0.39),
    },
    {
        "profile": "min", "case": "family_graph_03", "build": "O3S",
        "source": "f619cb2cf6b96756592c955895dcef822081333d42c018fc5b9c5f7e204a8d4e",
        "gt": "138d090ddf7341cd3ad47d6bdc257fa957025fad4ea80b6f56422db9af8139f6",
        "fixture": "e4bab56beebde8fac4bebda51d3830adbddf86bbf464104fa1e00c82b13e0038",
        "candidates": 13, "rounds": 2, "counts": (4, 1, 6, 67),
        "metrics": (0.80, 0.40, 0.53, 0.49),
    },
    {
        "profile": "min", "case": "family_graph_03", "build": "O3KS",
        "source": "f619cb2cf6b96756592c955895dcef822081333d42c018fc5b9c5f7e204a8d4e",
        "gt": "30122ce70a885091b80e6b94d23e1bcfada2bd0da470bffe6cacf1d7a8bedd59",
        "fixture": "9ea6ef9be73070ade6ba3f3d214b738b183549c7fe1540b89f18630021c80951",
        "candidates": 17, "rounds": 2, "counts": (15, 1, 0, 120),
        "metrics": (0.94, 1.00, 0.97, 0.96),
    },
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify exact profile baselines")
    parser.add_argument(
        "--profile",
        dest="profiles",
        action="append",
        choices=BUILD_PROFILES,
        help="profile to verify; repeat to select both. Default: both",
    )
    args = parser.parse_args(argv)
    profiles = tuple(args.profiles or BUILD_PROFILES)
    all_ok = True

    missed_only = _pairwise_score(0, 0, 3, 7)
    f1_missed_pair_ok = (
        missed_only.precision is None
        and missed_only.recall == 0.0
        and missed_only.f1 == 0.0
    )
    all_ok = all_ok and f1_missed_pair_ok
    print(
        "undefined precision with missed true pairs: "
        f"{'PASS' if f1_missed_pair_ok else 'FAIL'}"
    )
    mixed_errors = _pairwise_score(0, 2, 3, 5)
    mixed_error_f1_ok = mixed_errors.f1 == 0.0
    all_ok = all_ok and mixed_error_f1_ok
    print(
        "zero precision and recall with mixed errors: "
        f"{'PASS' if mixed_error_f1_ok else 'FAIL'}"
    )

    for expected in CASES:
        profile = expected["profile"]
        if profile not in profiles:
            continue
        case = expected["case"]
        build = expected["build"]
        verified = load_and_verify_manifest(
            build_manifest_for(case, build, profile),
            expected_case=case,
            expected_build=build,
            expected_profile=profile,
        )
        report = score_case(
            fixture_json_for(
                case, build, profile, candidate_scope=SUBJECT_CANDIDATE_SCOPE
            ),
            gt_json_for(case, build, profile, SUBJECT_CANDIDATE_SCOPE),
        )
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
        checks = {
            "identity": report.profile == profile,
            "provenance": report.provenance == verified.provenance,
            "source hash": sha256_file(verified.source) == expected["source"],
            "GT binary hash": sha256_file(verified.non_stripped_binary) == expected["gt"],
            "fixture binary hash": sha256_file(verified.stripped_binary) == expected["fixture"],
            "candidate count": report.candidate_count == expected["candidates"],
            "rounds": report.rounds == expected["rounds"],
            "pair counts": counts == expected["counts"],
            "pair total": report.pair_count == sum(counts),
            "metrics": metrics == expected["metrics"],
        }
        if profile == "min" and case == "family_graph_02" and build == "O3S":
            fixture_data = json.loads(
                Path(fixture_json_for(
                    case,
                    build,
                    profile,
                    candidate_scope=SUBJECT_CANDIDATE_SCOPE,
                )).read_text(encoding="utf-8")
            )
            root_nodes = [
                node for node in fixture_data["nodes"]
                if node["type"] == "anchor" and node["calls"]
            ]
            checks["root callsite audit"] = (
                len(root_nodes) == 1
                and len(root_nodes[0]["calls"]) == 6
                and sum(call["count"] for call in root_nodes[0]["calls"]) == 12
                and all(call["count"] == 2 for call in root_nodes[0]["calls"])
            )
            checks["main boundary audit"] = any(
                mismatch["address"] == "0xf540"
                and mismatch["symbol_size"] == 1465
                and mismatch["radare2_size"] == 951
                for mismatch in fixture_data["extraction"]["boundary_mismatches"]
            )
        failed = [name for name, ok in checks.items() if not ok]
        ok = not failed
        all_ok = all_ok and ok
        tag = "PASS" if ok else f"FAIL ({', '.join(failed)})"
        print(
            f"{profile}/{case}/{build}: n={report.candidate_count} "
            f"TP={counts[0]} FP={counts[1]} FN={counts[2]} TN={counts[3]} "
            f"PR={metrics[0]:.2f} RE={metrics[1]:.2f} F1={metrics[2]:.2f} "
            f"ARI={metrics[3]:.2f} {tag}"
        )

    for profile in profiles:
        baseline_path = Path(__file__).resolve().parents[1] / baseline_result_for(profile)
        stored = json.loads(baseline_path.read_text(encoding="utf-8"))
        generated = reports_to_dict(score_v0_baseline(profile=profile))
        ok = stored == generated
        all_ok = all_ok and ok
        print(f"{profile} baseline score JSON: {'PASS' if ok else 'FAIL'}")

    if set(profiles) == set(BUILD_PROFILES):
        try:
            score_case(
                fixture_json_for(
                    "family_graph_01", "O3S", "plain",
                    candidate_scope=SUBJECT_CANDIDATE_SCOPE,
                ),
                gt_json_for(
                    "family_graph_01", "O3S", "min", SUBJECT_CANDIDATE_SCOPE
                ),
            )
        except ValueError as exc:
            profile_join_ok = "case/build/profile mismatch" in str(exc)
        else:
            profile_join_ok = False
        all_ok = all_ok and profile_join_ok
        print(f"cross-profile join rejection: {'PASS' if profile_join_ok else 'FAIL'}")

        gt_path = gt_json_for(
            "family_graph_01", "O3S", "plain", SUBJECT_CANDIDATE_SCOPE
        )
        mismatched_gt = json.loads(Path(gt_path).read_text(encoding="utf-8"))
        mismatched_gt["provenance"]["build_id"] = "another-build-generation"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as f:
            json.dump(mismatched_gt, f)
            f.flush()
            try:
                score_case(
                    fixture_json_for(
                        "family_graph_01", "O3S", "plain",
                        candidate_scope=SUBJECT_CANDIDATE_SCOPE,
                    ),
                    f.name,
                )
            except ValueError as exc:
                provenance_join_ok = "build provenance mismatch" in str(exc)
            else:
                provenance_join_ok = False
        all_ok = all_ok and provenance_join_ok
        print(
            "cross-generation provenance rejection: "
            f"{'PASS' if provenance_join_ok else 'FAIL'}"
        )

    print("ALL PASS" if all_ok else "SOME FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
