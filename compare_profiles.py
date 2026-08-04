from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from paths import (
    CANDIDATE_SCOPES,
    DEFAULT_BUILD,
    DEFAULT_CANDIDATE_SCOPE,
    normalize_candidate_scope,
    resolve_gt_json,
    split_case_build,
)
from run_summary import compare_ground_truth_profiles
from scores import load_ground_truth


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare plain/min ground-truth universes for one build."
    )
    parser.add_argument("stem", help="case/subject stem")
    parser.add_argument("--build", help=f"build label. Default: {DEFAULT_BUILD}")
    parser.add_argument(
        "--candidate-scope",
        choices=CANDIDATE_SCOPES,
        default=DEFAULT_CANDIDATE_SCOPE,
        help=f"candidate scope. Default: {DEFAULT_CANDIDATE_SCOPE}",
    )
    parser.add_argument("--plain-gt", help="override plain ground-truth JSON")
    parser.add_argument("--min-gt", help="override min ground-truth JSON")
    parser.add_argument("--json-output", help="comparison JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    case, build = split_case_build(args.stem, args.build)
    scope = normalize_candidate_scope(args.candidate_scope)
    plain_path = args.plain_gt or resolve_gt_json(case, build, "plain", scope)
    min_path = args.min_gt or resolve_gt_json(case, build, "min", scope)
    output = args.json_output or (
        f"results/profile_comparison/{scope}/{case}.{build}.json"
    )

    try:
        plain_model = load_ground_truth(plain_path)
        min_model = load_ground_truth(min_path)
        if (
            plain_model.case != min_model.case
            or plain_model.build != min_model.build
            or plain_model.case != case
            or plain_model.build != build
        ):
            raise ValueError("plain/min ground-truth case/build mismatch")
        if plain_model.provenance.source_sha256 != min_model.provenance.source_sha256:
            raise ValueError("plain/min ground truth was not built from the same source")

        plain = json.loads(Path(plain_path).read_text(encoding="utf-8"))
        minimum = json.loads(Path(min_path).read_text(encoding="utf-8"))
        result = {
            "schema_version": 1,
            "case": case,
            "build": build,
            "candidate_scope": scope,
            "profiles": ["plain", "min"],
            **compare_ground_truth_profiles(plain, minimum),
        }
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
