from __future__ import annotations

import argparse
import sys
from pathlib import Path
from types import SimpleNamespace

from build_manifest import BUILD_TARGET, load_and_verify_manifest
from engine import (
    CG_WL_MODES,
    DEFAULT_CG_WL_MODE,
    format_cg_wl_trace,
    run_cg_wl,
)
from loader import load_case
from paths import (
    ANALYSIS_TRACKS,
    BUILD_PROFILES,
    CANDIDATE_SCOPES,
    DEFAULT_ANALYSIS_TRACK,
    DEFAULT_BUILD,
    DEFAULT_CANDIDATE_SCOPE,
    DEFAULT_PROFILE,
    boundaries_json_for,
    build_manifest_for,
    fixture_json_for,
    evidence_backend_for_track,
    gt_json_for,
    normalize_profile,
    normalize_candidate_scope,
    normalize_track,
    raw_graph_for,
    split_case_build,
    users_json_for,
)
from scores import format_report, score_all_modes, score_case, write_reports_json


def run_fixture_only(fixture_path: str, mode: str, *, trace: bool = False) -> None:
    result = run_cg_wl(load_case(fixture_path), mode=mode, trace=trace)
    print(result.mode)
    print(result.rounds)
    print(result.clusters)
    if trace:
        print(format_cg_wl_trace(result.trace))


def run_pipeline(args: argparse.Namespace) -> None:
    case_from_stem, build = split_case_build(args.stem, args.build)
    case_name = args.case or case_from_stem
    profile = normalize_profile(args.profile)
    track = normalize_track(args.track)
    candidate_scope = normalize_candidate_scope(args.candidate_scope)
    manifest_path = args.manifest or build_manifest_for(case_name, build, profile)
    verified = load_and_verify_manifest(
        manifest_path,
        expected_case=case_name,
        expected_build=build,
        expected_profile=profile,
        expected_target=BUILD_TARGET,
    )
    fixture_binary = _validated_override(
        "--fixture-binary", args.fixture_binary, verified.stripped_binary
    )
    gt_binary = _validated_override(
        "--gt-binary", args.gt_binary, verified.non_stripped_binary
    )
    fixture_json = args.fixture_json or fixture_json_for(
        case_name,
        build,
        profile,
        track,
        candidate_scope,
    )
    raw_graph_json = args.raw_graph or raw_graph_for(
        case_name,
        build,
        profile,
        evidence_backend_for_track(track),
    )
    gt_json = args.gt_json or gt_json_for(
        case_name, build, profile, candidate_scope
    )
    users_json = args.users or users_json_for(
        case_name, build, profile, candidate_scope
    )
    boundaries_json = args.boundaries or boundaries_json_for(
        case_name, build, profile
    )
    namespaces = tuple(args.namespaces or verified.candidate_namespaces)

    print(f"case: {case_name}")
    print(f"build: {build}")
    print(f"profile: {profile}")
    print(f"track: {track}")
    print(f"candidate scope: {candidate_scope}")
    print(f"build manifest: {manifest_path}")
    print(f"build id: {verified.build_id}")
    print(f"fixture binary: {fixture_binary}")
    print(f"gt binary: {gt_binary}")
    print(f"fixture json: {fixture_json}")
    print(f"raw graph: {raw_graph_json}")
    print(f"gt json: {gt_json}")
    print(f"users: {users_json}")
    print(f"function boundaries: {boundaries_json}")

    gt = extract_ground_truth(
        binary_path=gt_binary,
        output_path=gt_json,
        users_path=users_json,
        case_name=case_name,
        build=build,
        profile=profile,
        namespaces=namespaces,
        candidate_scope=candidate_scope,
        root_namespace=verified.root_namespace,
        boundaries_path=boundaries_json,
        provenance=verified.provenance,
    )
    print(f"ground-truth origins: {len(gt['origins'])}")

    fixture = extract_fixture(
        binary_path=fixture_binary,
        output_path=fixture_json,
        case_name=case_name,
        build=build,
        profile=profile,
        track=track,
        raw_graph_path=raw_graph_json,
        boundaries_path=boundaries_json,
        root=args.root,
        users_path=users_json,
        provenance=verified.provenance,
    )
    print(f"fixture nodes: {len(fixture['nodes'])}")

    from gt_extractor import validate_against_fixture

    validate_against_fixture(gt, fixture_json)

    if args.all_modes:
        reports = score_all_modes(fixture_json, gt_json, trace=args.trace)
    else:
        reports = (score_case(
            fixture_json,
            gt_json,
            mode=args.mode,
            trace=args.trace,
        ),)

    print("\n\n".join(format_report(report) for report in reports))
    if args.json_output:
        write_reports_json(reports, args.json_output)
        print(f"\nJSON: {args.json_output}")


def extract_fixture(
    *,
    binary_path: str,
    output_path: str,
    case_name: str,
    build: str,
    profile: str,
    track: str,
    raw_graph_path: str,
    boundaries_path: str,
    root: str | None,
    users_path: str | None,
    provenance,
) -> dict:
    from binary_extractor import DEFAULT_ID_BIAS, extract_artifacts, write_fixture
    from graph_evidence import write_raw_graph

    args = SimpleNamespace(
        binary=binary_path,
        case=case_name,
        build=build,
        profile=profile,
        track=track,
        root=root,
        score_root=False,
        include_imports=False,
        id_bias=DEFAULT_ID_BIAS,
        list_functions=False,
        users=users_path,
        boundaries=boundaries_path,
        provenance=provenance,
    )
    artifacts = extract_artifacts(args)
    write_raw_graph(artifacts.raw_graph, raw_graph_path)
    write_fixture(artifacts.fixture, output_path)
    return artifacts.fixture


def extract_ground_truth(
    *,
    binary_path: str,
    output_path: str,
    users_path: str,
    case_name: str,
    build: str,
    profile: str,
    namespaces: tuple[str, ...],
    candidate_scope: str,
    root_namespace: str,
    boundaries_path: str,
    provenance,
) -> dict:
    from gt_extractor import (
        DEFAULT_ID_BIAS,
        make_ground_truth,
        make_function_boundaries_json,
        make_users_json,
        parse_nm_lines,
        run_nm,
        user_addresses,
        user_function_bounds,
        rust_function_bounds,
        write_json,
    )

    symbols = parse_nm_lines(run_nm(binary_path, "nm"))
    user_addrs = user_addresses(
        symbols=symbols,
        namespaces=namespaces,
        candidate_scope=candidate_scope,
        root_namespace=root_namespace,
    )
    function_bounds = user_function_bounds(
        symbols=symbols,
        namespaces=namespaces,
        candidate_scope=candidate_scope,
        root_namespace=root_namespace,
    )
    all_boundaries = rust_function_bounds(symbols)
    gt = make_ground_truth(
        symbols=symbols,
        case=case_name,
        build=build,
        profile=profile,
        namespaces=namespaces,
        id_bias=DEFAULT_ID_BIAS,
        provenance=provenance,
        candidate_scope=candidate_scope,
        root_namespace=root_namespace,
    )
    write_json(gt, output_path)
    write_json(
        make_users_json(
            addresses=user_addrs,
            function_bounds=function_bounds,
            case=case_name,
            build=build,
            profile=profile,
            binary_path=binary_path,
            namespaces=namespaces,
            provenance=provenance,
            candidate_scope=candidate_scope,
            root_namespace=root_namespace,
        ),
        users_path,
    )
    write_json(
        make_function_boundaries_json(
            function_bounds=all_boundaries,
            case=case_name,
            build=build,
            profile=profile,
            binary_path=binary_path,
            provenance=provenance,
        ),
        boundaries_path,
    )
    return gt


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run binary extraction, GT extraction, CG-WL, and scoring for one stem."
    )
    parser.add_argument(
        "stem",
        help=(
            "example stem such as family_graph_03. If this is a .fixture.json "
            "path, only CG-WL is run on that fixture."
        ),
    )
    parser.add_argument("--fixture-binary", help="override stripped/fixture binary path")
    parser.add_argument("--gt-binary", help="override non-stripped GT binary path")
    parser.add_argument("--manifest", help="override and verify build manifest path")
    parser.add_argument("--fixture-json", help="override generated fixture JSON path")
    parser.add_argument("--raw-graph", help="override generated raw graph JSON path")
    parser.add_argument("--gt-json", help="override generated ground-truth JSON path")
    parser.add_argument("--users", help="override generated user address JSON path")
    parser.add_argument(
        "--boundaries",
        help="override generated scope-independent function boundary JSON path",
    )
    parser.add_argument("--case", help="case field written into generated JSON")
    parser.add_argument("--build", help=f"build label. Default: {DEFAULT_BUILD}")
    parser.add_argument(
        "--profile",
        choices=BUILD_PROFILES,
        default=DEFAULT_PROFILE,
        help=f"compiler profile. Default: {DEFAULT_PROFILE}",
    )
    parser.add_argument(
        "--track",
        choices=ANALYSIS_TRACKS,
        default=DEFAULT_ANALYSIS_TRACK,
        help=f"analysis track. Default: {DEFAULT_ANALYSIS_TRACK}",
    )
    parser.add_argument(
        "--candidate-scope",
        choices=CANDIDATE_SCOPES,
        default=DEFAULT_CANDIDATE_SCOPE,
        help=f"candidate scope. Default: {DEFAULT_CANDIDATE_SCOPE}",
    )
    parser.add_argument(
        "--namespace",
        dest="namespaces",
        action="append",
        help=(
            "override a subject-owned crate namespace; repeat for multiple "
            "namespaces. Default: build manifest values"
        ),
    )
    parser.add_argument("--root", help="root function name/id/address for binary extraction")
    parser.add_argument(
        "--mode",
        choices=CG_WL_MODES,
        default=DEFAULT_CG_WL_MODE,
        help=f"CG-WL relation mode. Default: {DEFAULT_CG_WL_MODE}",
    )
    parser.add_argument(
        "--all-modes",
        action="store_true",
        help="score full, out, in, and out-in modes",
    )
    parser.add_argument(
        "--json-output",
        help="write the score result set to one JSON file",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="print and optionally serialize every CG-WL round partition",
    )
    return parser


def _validated_override(option: str, override: str | None, recorded: str) -> str:
    if override is None:
        return recorded
    if Path(override).resolve() != Path(recorded).resolve():
        raise ValueError(
            f"{option} does not match the build manifest: {override!r} != {recorded!r}"
        )
    return recorded


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.stem.endswith(".fixture.json"):
            run_fixture_only(args.stem, args.mode, trace=args.trace)
        else:
            run_pipeline(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
