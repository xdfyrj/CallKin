from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

from paths import BUILD_PROFILES, baseline_result_for
from scores import V0_BASELINE_JOBS


ROOT = Path(__file__).resolve().parent


def run_step(arguments: list[str]) -> None:
    """Run one Python command and stop the pipeline if it fails."""
    command = [sys.executable, *arguments]
    print(f"\n+ {shlex.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"step failed with exit code {completed.returncode}: "
            f"{shlex.join(command)}"
        )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild, extract, score, and verify the canonical baselines for "
            "the plain and min compiler profiles."
        )
    )
    parser.add_argument(
        "--profile",
        dest="profiles",
        action="append",
        choices=BUILD_PROFILES,
        help="profile to rebuild; repeat to select both. Default: both profiles",
    )
    parser.add_argument(
        "--rustc-tool",
        default="rustc",
        help="rustc-compatible compiler passed to compile.py. Default: rustc",
    )
    parser.add_argument(
        "--strip-tool",
        default="strip",
        help="strip-compatible tool passed to compile.py. Default: strip",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    profiles = tuple(args.profiles or BUILD_PROFILES)

    try:
        for profile in profiles:
            for case, build in V0_BASELINE_JOBS:
                run_step([
                    "compile.py",
                    case,
                    "case",
                    "--build",
                    build,
                    "--profile",
                    profile,
                    "--rustc-tool",
                    args.rustc_tool,
                    "--strip-tool",
                    args.strip_tool,
                ])
                run_step([
                    "run_case.py",
                    case,
                    "--build",
                    build,
                    "--profile",
                    profile,
                    "--candidate-scope",
                    "subject",
                ])

            run_step([
                "scores.py",
                "--baseline",
                "--profile",
                profile,
                "--json-output",
                baseline_result_for(profile),
            ])
        test_arguments = ["tests/test_scores.py"]
        for profile in profiles:
            test_arguments.extend(["--profile", profile])
        run_step(test_arguments)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("\nV0 baseline regeneration PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
