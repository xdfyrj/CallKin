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
    "scores.py",
    "run_case.py",
    "run_summary.py",
    "compare_profiles.py",
    "run_baseline.py",
    "tests/test_compile.py",
    "tests/test_engine.py",
    "tests/test_binary_extractor.py",
    "tests/test_graph_projector.py",
    "tests/test_angr_adapter.py",
    "tests/test_angr_integration.py",
    "tests/test_oxidizer_adapter.py",
    "tests/test_all_rust_catalog.py",
    "tests/test_flirt_audit.py",
    "tests/test_run_summary.py",
    "tests/test_gt_extractor.py",
    "tests/test_scores.py",
    "tests/run_all.py",
)
TEST_FILES = (
    "tests/test_compile.py",
    "tests/test_engine.py",
    "tests/test_binary_extractor.py",
    "tests/test_graph_projector.py",
    "tests/test_angr_adapter.py",
    "tests/test_angr_integration.py",
    "tests/test_oxidizer_adapter.py",
    "tests/test_all_rust_catalog.py",
    "tests/test_flirt_audit.py",
    "tests/test_run_summary.py",
    "tests/test_gt_extractor.py",
    "tests/test_scores.py",
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
