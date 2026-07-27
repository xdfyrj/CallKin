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
    "binary_extractor.py",
    "gt_extractor.py",
    "model.py",
    "loader.py",
    "engine.py",
    "scores.py",
    "run_case.py",
    "run_baseline.py",
    "test/test_compile.py",
    "test/test_engine.py",
    "test/test_binary_extractor.py",
    "test/test_gt_extractor.py",
    "test/test_scores.py",
    "test/run_all.py",
)
TEST_FILES = (
    "test/test_compile.py",
    "test/test_engine.py",
    "test/test_binary_extractor.py",
    "test/test_gt_extractor.py",
    "test/test_scores.py",
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
