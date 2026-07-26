from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from build_manifest import (
    BUILD_MANIFEST_SCHEMA_VERSION,
    BUILD_TARGET,
    sha256_file,
    write_manifest,
)
from paths import (
    DEFAULT_BUILD,
    build_manifest_for,
    fixture_binary_for,
    gt_binary_for,
    source_rs_for,
    split_case_build,
)


RUSTC_EDITION = "2024"
RUSTC_TARGET = BUILD_TARGET
STRIP_FLAGS = ["--strip-all"]

# Controlled evaluation flags derived from rust-loss scripts/lib_build.sh.
# CallKin intentionally uses panic=abort instead of rust-loss's panic=unwind.
_O3_FLAGS = [
    "-C", "opt-level=3",
    "-C", "codegen-units=1",
    "-C", "lto=off",
    "-C", "panic=abort",
    "-C", "debuginfo=0",
    "-C", "debug-assertions=off",
    "-C", "overflow-checks=off",
]

PROFILE_FLAGS: dict[str, list[str]] = {
    "O3": _O3_FLAGS,
    "O3K": _O3_FLAGS + ["--cfg", "keep"],
}

# Evaluation build -> compiled (non-stripped) source profile.
# Mirrors rust-loss source_profile_for_stripped.
COMPILED_PROFILE_BY_BUILD = {
    "O3S": "O3",
    "O3KS": "O3K",
}


def compiled_profile_for_build(build: str) -> str:
    profile = COMPILED_PROFILE_BY_BUILD.get(build)
    if profile is None:
        raise ValueError(
            f"unsupported build for compilation: {build}. "
            f"Supported builds: {sorted(COMPILED_PROFILE_BY_BUILD)}"
        )
    return profile


def rustc_command(
    *,
    source: str,
    case: str,
    profile: str,
    output: str,
    rustc_tool: str = "rustc",
) -> list[str]:
    # rust-loss uses --emit=llvm-ir,asm,link into an --out-dir. Only the
    # linked binary is needed here, and --emit=link -o produces a
    # byte-identical binary under the same rustc.
    return [
        rustc_tool,
        source,
        *PROFILE_FLAGS[profile],
        "--crate-type", "bin",
        "--crate-name", case,
        "--edition", RUSTC_EDITION,
        "--target", RUSTC_TARGET,
        "--emit=link",
        "-o", output,
    ]


def compile_gt_binary(
    *,
    source: str,
    case: str,
    profile: str,
    output: str,
    rustc_tool: str,
) -> list[str]:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = _temporary_path_for(path)

    try:
        command = rustc_command(
            source=source,
            case=case,
            profile=profile,
            output=str(temporary),
            rustc_tool=rustc_tool,
        )
        _run_tool(command)
        os.replace(temporary, path)
        return command
    finally:
        temporary.unlink(missing_ok=True)


def derive_fixture_binary(
    *,
    gt_binary: str,
    output: str,
    strip_tool: str,
) -> list[str]:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = _temporary_path_for(path)

    try:
        shutil.copyfile(gt_binary, temporary)
        shutil.copymode(gt_binary, temporary)
        command = [strip_tool, *STRIP_FLAGS, str(temporary)]
        _run_tool(command)
        os.replace(temporary, path)
        return command
    finally:
        temporary.unlink(missing_ok=True)


def _temporary_path_for(output: Path) -> Path:
    handle, name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    os.close(handle)
    return Path(name)


def _require_tool(tool: str) -> None:
    if not shutil.which(tool):
        raise RuntimeError(
            f"{tool} executable was not found. Install it before running "
            "compile.py."
        )


def _run_tool(command: list[str]) -> None:
    _require_tool(command[0])

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{command[0]} failed with exit code {result.returncode}:\n"
            f"{result.stderr.strip()}"
        )


def tool_output(tool: str, *args: str) -> str:
    result = subprocess.run(
        [tool, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{tool} {' '.join(args)} failed with exit code {result.returncode}:\n"
            f"{result.stdout.strip()}"
        )
    return result.stdout.strip()


def tool_paths(tool: str) -> tuple[str, str]:
    invoked = shutil.which(tool)
    if invoked is None:
        raise RuntimeError(f"{tool} executable was not found")
    return invoked, str(Path(invoked).resolve())


def rustc_binary_identity(rustc_tool: str) -> tuple[str, str]:
    sysroot = tool_output(rustc_tool, "--print", "sysroot")
    candidate = Path(sysroot) / "bin" / "rustc"
    compiler_binary = candidate if candidate.is_file() else Path(tool_paths(rustc_tool)[1])
    return sysroot, str(compiler_binary.resolve())


def make_build_manifest(
    *,
    source: str,
    source_sha256: str,
    case: str,
    build: str,
    profile: str,
    gt_binary: str,
    gt_sha256: str,
    fixture_binary: str,
    fixture_sha256: str,
    rustc_tool: str,
    rustc_command: list[str],
    strip_tool: str,
    strip_command: list[str],
) -> dict:
    rustc_invoked, rustc_resolved = tool_paths(rustc_tool)
    rustc_sysroot, rustc_binary = rustc_binary_identity(rustc_tool)
    strip_invoked, strip_resolved = tool_paths(strip_tool)
    return {
        "schema_version": BUILD_MANIFEST_SCHEMA_VERSION,
        "build_id": uuid.uuid4().hex,
        "case": case,
        "build": build,
        "profile": profile,
        "target": RUSTC_TARGET,
        "edition": RUSTC_EDITION,
        "crate_name": case,
        "source": {
            "path": source,
            "sha256": source_sha256,
        },
        "compiler": {
            "invoked_path": rustc_invoked,
            "resolved_path": rustc_resolved,
            "sysroot": rustc_sysroot,
            "compiler_binary_path": rustc_binary,
            "verbose_version": tool_output(rustc_tool, "-vV"),
            "flags": PROFILE_FLAGS[profile],
            "command": rustc_command,
        },
        "strip": {
            "invoked_path": strip_invoked,
            "resolved_path": strip_resolved,
            "version": tool_output(strip_tool, "--version"),
            "flags": STRIP_FLAGS,
            "command": strip_command,
        },
        "artifacts": {
            "non_stripped": {
                "path": gt_binary,
                "sha256": gt_sha256,
            },
            "stripped": {
                "path": fixture_binary,
                "sha256": fixture_sha256,
                "stripped_from_sha256": gt_sha256,
            },
        },
    }


def _publish_file(source: Path, output: str) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = _temporary_path_for(destination)
    try:
        shutil.copyfile(source, temporary)
        shutil.copymode(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def compile_case(args: argparse.Namespace) -> list[str]:
    """Build and publish one matched non-stripped/stripped binary pair."""
    profile = compiled_profile_for_build(args.build)

    # Validate the complete toolchain before replacing either binary.
    _require_tool(args.rustc_tool)
    _require_tool(args.strip_tool)

    source_sha256 = sha256_file(args.source)

    with tempfile.TemporaryDirectory(prefix=f"{args.case}.{args.build}.") as directory:
        staging = Path(directory)
        staged_gt = staging / "non-stripped.bin"
        staged_fixture = staging / "stripped.bin"
        staged_manifest = staging / "build.json"

        rustc_command_used = compile_gt_binary(
            source=args.source,
            case=args.case,
            profile=profile,
            output=str(staged_gt),
            rustc_tool=args.rustc_tool,
        )
        strip_command_used = derive_fixture_binary(
            gt_binary=str(staged_gt),
            output=str(staged_fixture),
            strip_tool=args.strip_tool,
        )

        if sha256_file(args.source) != source_sha256:
            raise RuntimeError("source changed while compilation was in progress")

        gt_sha256 = sha256_file(staged_gt)
        fixture_sha256 = sha256_file(staged_fixture)
        manifest = make_build_manifest(
            source=args.source,
            source_sha256=source_sha256,
            case=args.case,
            build=args.build,
            profile=profile,
            gt_binary=args.gt_binary,
            gt_sha256=gt_sha256,
            fixture_binary=args.fixture_binary,
            fixture_sha256=fixture_sha256,
            rustc_tool=args.rustc_tool,
            rustc_command=rustc_command_used,
            strip_tool=args.strip_tool,
            strip_command=strip_command_used,
        )
        write_manifest(manifest, staged_manifest)

        # The manifest is the completion marker and must be published last.
        _publish_file(staged_gt, args.gt_binary)
        _publish_file(staged_fixture, args.fixture_binary)
        _publish_file(staged_manifest, args.manifest)

    return [args.gt_binary, args.fixture_binary, args.manifest]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compile one Rust example source into this project's non-stripped "
            "gt_bin/ and stripped bin/ evaluation binaries."
        )
    )
    parser.add_argument("source", help="Rust source path, or an example stem")
    parser.add_argument("--case", help="case name and rustc crate name")
    parser.add_argument(
        "--build",
        help=(
            f"evaluation build. O3S compiles the O3 profile, O3KS compiles the "
            f"O3K (--cfg keep) profile. Default: {DEFAULT_BUILD}"
        ),
    )
    parser.add_argument("--gt-binary", help="override non-stripped output path")
    parser.add_argument("--fixture-binary", help="override stripped output path")
    parser.add_argument("--manifest", help="override build manifest output path")
    parser.add_argument(
        "--rustc-tool",
        default="rustc",
        help="rustc-compatible compiler. Default: rustc",
    )
    parser.add_argument(
        "--strip-tool",
        default="strip",
        help="strip-compatible tool. Default: strip",
    )
    return parser


def apply_cli_defaults(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    case, build = split_case_build(args.source, args.build)

    if not Path(args.source).exists():
        args.source = source_rs_for(case)

    if not Path(args.source).exists():
        parser.error(f"source not found: {args.source}")

    args.case = args.case or case
    args.build = build
    args.gt_binary = args.gt_binary or gt_binary_for(args.case, build)
    args.fixture_binary = args.fixture_binary or fixture_binary_for(args.case, build)
    args.manifest = args.manifest or build_manifest_for(args.case, build)


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    apply_cli_defaults(args, parser)

    try:
        outputs = compile_case(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for output in outputs:
        print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
