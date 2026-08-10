"""Create the evaluation-only catalog used to audit Oxidizer FLIRT labels."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from build_manifest import load_and_verify_manifest, sha256_file
from gt_extractor import (
    DEFAULT_ID_BIAS,
    make_all_rust_catalog,
    parse_nm_lines,
    run_nm,
    validate_all_rust_catalog,
    write_json,
)
from paths import (
    BUILD_PROFILES,
    DEFAULT_BUILD,
    DEFAULT_PROFILE,
    all_rust_catalog_for,
    build_manifest_for,
    split_case_build,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a non-stripped, scoring-only all-Rust origin catalog."
    )
    parser.add_argument("stem", help="case stem, for example billing-client")
    parser.add_argument("--build", default=DEFAULT_BUILD)
    parser.add_argument("--profile", choices=BUILD_PROFILES, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", help="override verified build manifest path")
    parser.add_argument("--gt-binary", help="override non-stripped binary path")
    parser.add_argument("--output", help="override catalog output path")
    parser.add_argument("--nm", default="nm", help="nm-compatible tool. Default: nm")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        case, build = split_case_build(args.stem, args.build)
        manifest_path = args.manifest or build_manifest_for(case, build, args.profile)
        verified = load_and_verify_manifest(
            manifest_path,
            expected_case=case,
            expected_build=build,
            expected_profile=args.profile,
        )
        binary = Path(args.gt_binary or verified.non_stripped_binary)
        if binary.resolve() != Path(verified.non_stripped_binary).resolve():
            raise ValueError("--gt-binary must match the non-stripped binary in the manifest")
        if sha256_file(binary) != verified.provenance.non_stripped_sha256:
            raise ValueError("non-stripped binary hash differs from the build manifest")
        catalog = make_all_rust_catalog(
            symbols=parse_nm_lines(run_nm(str(binary), args.nm)),
            case=case,
            build=build,
            profile=args.profile,
            root_namespace=verified.root_namespace,
            id_bias=DEFAULT_ID_BIAS,
            binary_path=str(binary),
            provenance=verified.provenance,
        )
        validate_all_rust_catalog(catalog)
        output = args.output or all_rust_catalog_for(case, build, args.profile)
        write_json(catalog, output)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    member_count = sum(len(origin["members"]) for origin in catalog["origins"])
    print(f"all-Rust members: {member_count}")
    print(f"all-Rust origins: {len(catalog['origins'])}")
    print(f"wrote: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
