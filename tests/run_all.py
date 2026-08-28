from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_FILES = (
    "compile.py",
    "build_profiles.py",
    "build_manifest.py",
    "provenance.py",
    "candidate_selection.py",
    "body_evidence.py",
    "body_extractor.py",
    "body_similarity.py",
    "function_boundaries.py",
    "analysis_provenance.py",
    "graph_evidence.py",
    "angr_adapter.py",
    "oxidizer_probe.py",
    "oxidizer_adapter.py",
    "graph_projector.py",
    "binary_extractor.py",
    "gt_extractor.py",
    "all_rust_catalog.py",
    "flirt_audit.py",
    "model.py",
    "loader.py",
    "engine.py",
    "v1_candidates.py",
    "v1_retrieval_views.py",
    "v1_engine.py",
    "scores.py",
    "run_case.py",
    "run_summary.py",
    "compare_profiles.py",
    "analysis/summary.py",
    "analysis/v1_feasibility.py",
    "analysis/f45_collision.py",
    "analysis/v1_candidate_eval.py",
    "analysis/gt_mangled_audit.py",
    "analysis/v1_corrected_gt.py",
    "analysis/v1_multiview_eval.py",
    "analysis/v1_pair_eval.py",
    "analysis/v1_retrieval_miss.py",
    "run_baseline.py",
    "tests/test_compile.py",
    "tests/test_engine.py",
    "tests/test_binary_extractor.py",
    "tests/test_body_extractor.py",
    "tests/test_body_similarity.py",
    "tests/test_graph_projector.py",
    "tests/test_angr_adapter.py",
    "tests/test_angr_integration.py",
    "tests/test_oxidizer_adapter.py",
    "tests/test_all_rust_catalog.py",
    "tests/test_flirt_audit.py",
    "tests/test_run_summary.py",
    "tests/test_gt_extractor.py",
    "tests/test_scores.py",
    "tests/test_v1_candidate_eval.py",
    "tests/test_v1_multiview_eval.py",
    "tests/test_v1_retrieval_miss.py",
    "tests/test_gt_mangled_audit.py",
    "tests/test_v1_corrected_gt.py",
    "tests/run_all.py",
)
TEST_FILES = (
    "tests/test_compile.py",
    "tests/test_engine.py",
    "tests/test_binary_extractor.py",
    "tests/test_body_extractor.py",
    "tests/test_body_similarity.py",
    "tests/test_graph_projector.py",
    "tests/test_angr_adapter.py",
    "tests/test_angr_integration.py",
    "tests/test_oxidizer_adapter.py",
    "tests/test_all_rust_catalog.py",
    "tests/test_flirt_audit.py",
    "tests/test_run_summary.py",
    "tests/test_gt_extractor.py",
    "tests/test_scores.py",
    "tests/test_collision_diagnostic.py",
    "tests/test_v1_candidates.py",
    "tests/test_v1_retrieval_views.py",
    "tests/test_v1_candidate_eval.py",
    "tests/test_v1_multiview_eval.py",
    "tests/test_v1_engine.py",
    "tests/test_gt_mangled_audit.py",
    "tests/test_v1_corrected_gt.py",
)


def run_step(arguments: list[str]) -> bool:
    command = [sys.executable, *arguments]
    print(f"\n+ {shlex.join(command)}", flush=True)
    return subprocess.run(command, cwd=ROOT, check=False).returncode == 0


def main() -> int:
    if not run_step(["-m", "py_compile", *PYTHON_FILES]):
        print("\nALL TESTS FAILED")
        return 1

    for test_file in TEST_FILES:
        if not run_step([test_file]):
            print("\nALL TESTS FAILED")
            return 1

    print("\nALL TESTS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
