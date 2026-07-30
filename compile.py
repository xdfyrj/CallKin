from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from build_profiles import (
    BUILD_FLAGS,
    BUILD_TARGET,
    PROFILE_FLAGS,
    RUSTC_EDITION,
    STRIP_FLAGS,
    cargo_profile_config,
    compile_flags,
)
from build_manifest import (
    BUILD_MANIFEST_SCHEMA_VERSION,
    sha256_cargo_inputs,
    sha256_file,
    write_manifest,
)
from paths import (
    BUILD_PROFILES,
    DEFAULT_BUILD,
    DEFAULT_PROFILE,
    build_manifest_for,
    fixture_binary_for,
    gt_binary_for,
    normalize_profile,
    source_rs_for,
    split_case_build,
)

RUSTC_TARGET = BUILD_TARGET


@dataclass(frozen=True)
class CargoSubject:
    path: str
    manifest: str
    lockfile: str
    package: str
    binary: str
    edition: str
    candidate_namespaces: tuple[str, ...]
    root_namespace: str


def cargo_metadata_command(
    *,
    manifest: str,
    cargo_tool: str = "cargo",
) -> list[str]:
    return [
        cargo_tool,
        "metadata",
        "--format-version", "1",
        "--no-deps",
        "--locked",
        "--manifest-path", manifest,
    ]


def inspect_cargo_subject(
    subject_path: str,
    *,
    cargo_tool: str = "cargo",
) -> CargoSubject:
    subject = Path(subject_path)
    manifest = subject / "Cargo.toml"
    lockfile = subject / "Cargo.lock"
    if not manifest.is_file():
        raise ValueError(f"Cargo manifest not found: {manifest}")
    if not lockfile.is_file():
        raise ValueError(
            f"Cargo lockfile not found: {lockfile}. Run cargo generate-lockfile first."
        )

    command = cargo_metadata_command(
        manifest=str(manifest),
        cargo_tool=cargo_tool,
    )
    result = _run_tool_capture(command)
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"cargo metadata returned invalid JSON: {exc}") from exc

    manifest_resolved = manifest.resolve()
    packages = [
        package
        for package in metadata.get("packages", [])
        if Path(package.get("manifest_path", "")).resolve() == manifest_resolved
    ]
    if len(packages) != 1:
        raise ValueError(
            f"expected one Cargo package for {manifest}, found {len(packages)}"
        )
    package = packages[0]
    targets = package.get("targets", [])
    binary_targets = [
        target
        for target in targets
        if "bin" in target.get("kind", [])
    ]
    if len(binary_targets) != 1:
        names = [target.get("name", "?") for target in binary_targets]
        raise ValueError(
            "Cargo subject must currently have exactly one binary target; "
            f"found {names}. Multi-binary selection is not implemented."
        )

    binary = binary_targets[0]["name"]
    library_names = [
        target["name"]
        for target in targets
        if any(kind in {"lib", "rlib", "dylib", "staticlib", "cdylib"}
               for kind in target.get("kind", []))
    ]
    namespaces = tuple(dict.fromkeys([*library_names, binary]))
    return CargoSubject(
        path=str(subject),
        manifest=str(manifest),
        lockfile=str(lockfile),
        package=package["name"],
        binary=binary,
        edition=package["edition"],
        candidate_namespaces=namespaces,
        root_namespace=binary,
    )


def cargo_build_command(
    *,
    subject: CargoSubject,
    target_dir: str,
    config_path: str,
    cargo_tool: str = "cargo",
) -> list[str]:
    return [
        cargo_tool,
        "build",
        "--release",
        "--locked",
        "--manifest-path", subject.manifest,
        "--package", subject.package,
        "--bin", subject.binary,
        "--target", RUSTC_TARGET,
        "--target-dir", target_dir,
        "--message-format=json-render-diagnostics",
        "--config", config_path,
    ]


def rustc_command(
    *,
    source: str,
    case: str,
    profile: str,
    build: str,
    output: str,
    rustc_tool: str = "rustc",
) -> list[str]:
    # rust-loss uses --emit=llvm-ir,asm,link into an --out-dir. Only the
    # linked binary is needed here, and --emit=link -o produces a
    # byte-identical binary under the same rustc.
    return [
        rustc_tool,
        source,
        *compile_flags(profile, build),
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
    build: str,
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
            build=build,
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
    _run_tool_capture(command)


def _run_tool_capture(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    _require_tool(command[0])
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{command[0]} failed with exit code {result.returncode}:\n"
            f"{result.stderr.strip()}"
        )
    return result


def compile_cargo_binary(
    *,
    subject: CargoSubject,
    profile: str,
    build: str,
    output: str,
    staging: Path,
    cargo_tool: str,
    rustc_tool: str,
) -> tuple[list[str], dict[str, str], str]:
    config_path = staging / "callkin-cargo-config.toml"
    config_path.write_text(cargo_profile_config(profile), encoding="utf-8")
    target_dir = staging / "cargo-target"
    command = cargo_build_command(
        subject=subject,
        target_dir=str(target_dir),
        config_path=str(config_path),
        cargo_tool=cargo_tool,
    )

    env = os.environ.copy()
    env["RUSTC"] = rustc_tool
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env["RUSTFLAGS"] = "--cfg keep" if build.upper() == "O3KS" else ""
    result = _run_tool_capture(command, env=env)

    executables: list[str] = []
    for line in result.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target", {})
        executable = message.get("executable")
        if (
            executable
            and target.get("name") == subject.binary
            and "bin" in target.get("kind", [])
        ):
            executables.append(executable)

    unique_executables = tuple(dict.fromkeys(executables))
    if len(unique_executables) != 1:
        raise RuntimeError(
            "Cargo build did not report exactly one selected executable: "
            f"{list(unique_executables)}"
        )
    executable = Path(unique_executables[0])
    if not executable.is_file():
        raise RuntimeError(f"Cargo executable not found: {executable}")

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(executable, destination)
    shutil.copymode(executable, destination)
    recorded_env = {
        "RUSTC": rustc_tool,
        "RUSTFLAGS": env["RUSTFLAGS"],
    }
    return command, recorded_env, cargo_profile_config(profile)


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
    source_kind: str,
    case: str,
    build: str,
    profile: str,
    edition: str,
    crate_name: str,
    gt_binary: str,
    gt_sha256: str,
    fixture_binary: str,
    fixture_sha256: str,
    rustc_tool: str,
    rustc_command: list[str],
    strip_tool: str,
    strip_command: list[str],
    cargo_subject: CargoSubject | None = None,
    cargo_tool: str | None = None,
    cargo_environment: dict[str, str] | None = None,
    cargo_profile: str | None = None,
) -> dict:
    rustc_invoked, rustc_resolved = tool_paths(rustc_tool)
    rustc_sysroot, rustc_binary = rustc_binary_identity(rustc_tool)
    strip_invoked, strip_resolved = tool_paths(strip_tool)
    manifest = {
        "schema_version": BUILD_MANIFEST_SCHEMA_VERSION,
        "build_id": uuid.uuid4().hex,
        "case": case,
        "build": build,
        "profile": profile,
        "target": RUSTC_TARGET,
        "edition": edition,
        "crate_name": crate_name,
        "source": {
            "kind": source_kind,
            "path": source,
            "sha256": source_sha256,
        },
        "compiler": {
            "invoked_path": rustc_invoked,
            "resolved_path": rustc_resolved,
            "sysroot": rustc_sysroot,
            "compiler_binary_path": rustc_binary,
            "verbose_version": tool_output(rustc_tool, "-vV"),
            "flags": compile_flags(profile, build),
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
    if cargo_subject is not None:
        if cargo_tool is None or cargo_environment is None or cargo_profile is None:
            raise ValueError("Cargo manifest data is incomplete")
        cargo_invoked, cargo_resolved = tool_paths(cargo_tool)
        manifest["cargo"] = {
            "invoked_path": cargo_invoked,
            "resolved_path": cargo_resolved,
            "version": tool_output(cargo_tool, "--version", "--verbose"),
            "manifest": {
                "path": cargo_subject.manifest,
                "sha256": sha256_file(cargo_subject.manifest),
            },
            "lockfile": {
                "path": cargo_subject.lockfile,
                "sha256": sha256_file(cargo_subject.lockfile),
            },
            "package": cargo_subject.package,
            "binary": cargo_subject.binary,
            "candidate_namespaces": list(cargo_subject.candidate_namespaces),
            "root_namespace": cargo_subject.root_namespace,
            "command": rustc_command,
            "environment": cargo_environment,
            "profile_config": cargo_profile,
        }
    return manifest


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
    args.profile = normalize_profile(args.profile)
    compile_flags(args.profile, args.build)
    input_kind = getattr(args, "input_kind", "case")

    # Validate the complete toolchain before replacing either binary.
    _require_tool(args.rustc_tool)
    _require_tool(args.strip_tool)
    cargo_subject = None
    if input_kind == "subject":
        _require_tool(args.cargo_tool)
        cargo_subject = inspect_cargo_subject(
            args.source,
            cargo_tool=args.cargo_tool,
        )
        source_sha256 = sha256_cargo_inputs(
            args.source,
            manifest_path=cargo_subject.manifest,
            lockfile_path=cargo_subject.lockfile,
        )
        edition = cargo_subject.edition
        crate_name = cargo_subject.binary
    else:
        source_sha256 = sha256_file(args.source)
        edition = RUSTC_EDITION
        crate_name = args.case

    with tempfile.TemporaryDirectory(
        prefix=f"{args.case}.{args.profile}.{args.build}."
    ) as directory:
        staging = Path(directory)
        staged_gt = staging / "non-stripped.bin"
        staged_fixture = staging / "stripped.bin"
        staged_manifest = staging / "build.json"

        cargo_environment = None
        cargo_profile = None
        if cargo_subject is None:
            compiler_command_used = compile_gt_binary(
                source=args.source,
                case=args.case,
                profile=args.profile,
                build=args.build,
                output=str(staged_gt),
                rustc_tool=args.rustc_tool,
            )
        else:
            (
                compiler_command_used,
                cargo_environment,
                cargo_profile,
            ) = compile_cargo_binary(
                subject=cargo_subject,
                profile=args.profile,
                build=args.build,
                output=str(staged_gt),
                staging=staging,
                cargo_tool=args.cargo_tool,
                rustc_tool=args.rustc_tool,
            )
        strip_command_used = derive_fixture_binary(
            gt_binary=str(staged_gt),
            output=str(staged_fixture),
            strip_tool=args.strip_tool,
        )

        if cargo_subject is None:
            current_source_sha256 = sha256_file(args.source)
        else:
            current_source_sha256 = sha256_cargo_inputs(
                args.source,
                manifest_path=cargo_subject.manifest,
                lockfile_path=cargo_subject.lockfile,
            )
        if current_source_sha256 != source_sha256:
            raise RuntimeError("source changed while compilation was in progress")

        gt_sha256 = sha256_file(staged_gt)
        fixture_sha256 = sha256_file(staged_fixture)
        manifest = make_build_manifest(
            source=args.source,
            source_sha256=source_sha256,
            source_kind=input_kind,
            case=args.case,
            build=args.build,
            profile=args.profile,
            edition=edition,
            crate_name=crate_name,
            gt_binary=args.gt_binary,
            gt_sha256=gt_sha256,
            fixture_binary=args.fixture_binary,
            fixture_sha256=fixture_sha256,
            rustc_tool=args.rustc_tool,
            rustc_command=compiler_command_used,
            strip_tool=args.strip_tool,
            strip_command=strip_command_used,
            cargo_subject=cargo_subject,
            cargo_tool=args.cargo_tool if cargo_subject is not None else None,
            cargo_environment=cargo_environment,
            cargo_profile=cargo_profile,
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
            "Compile one CallKin case or Cargo subject into matched "
            "non-stripped and stripped evaluation binaries."
        )
    )
    parser.add_argument("source", help="case/subject name or explicit path")
    parser.add_argument(
        "input_kind",
        choices=("case", "subject"),
        help="'case' uses src/<name>.rs; 'subject' uses subjects/<name>/Cargo.toml",
    )
    parser.add_argument("--case", help="case name and rustc crate name")
    parser.add_argument(
        "--build",
        help=(
            f"evaluation build. O3KS adds --cfg keep before stripping. "
            f"Default: {DEFAULT_BUILD}"
        ),
    )
    parser.add_argument(
        "--profile",
        choices=BUILD_PROFILES,
        default=DEFAULT_PROFILE,
        help=f"compiler profile. Default: {DEFAULT_PROFILE}",
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
        "--cargo-tool",
        default="cargo",
        help="Cargo-compatible build tool for subjects. Default: cargo",
    )
    parser.add_argument(
        "--strip-tool",
        default="strip",
        help="strip-compatible tool. Default: strip",
    )
    return parser


def apply_cli_defaults(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    requested = Path(args.source)
    if args.input_kind == "case":
        case, build = split_case_build(args.source, args.build)
        if not requested.is_file():
            requested = Path(source_rs_for(case))
        if not requested.is_file():
            parser.error(f"case source not found: {requested}")
    else:
        build = split_case_build(args.source, args.build)[1]
        if not requested.is_dir():
            requested = Path("subjects") / args.source
        if not requested.is_dir():
            parser.error(f"Cargo subject not found: {requested}")
        if not (requested / "Cargo.toml").is_file():
            parser.error(f"Cargo manifest not found: {requested / 'Cargo.toml'}")
        case = requested.name

    args.source = str(requested)
    args.case = args.case or case
    args.build = build
    args.profile = normalize_profile(args.profile)
    args.gt_binary = args.gt_binary or gt_binary_for(args.case, build, args.profile)
    args.fixture_binary = (
        args.fixture_binary or fixture_binary_for(args.case, build, args.profile)
    )
    args.manifest = (
        args.manifest or build_manifest_for(args.case, build, args.profile)
    )


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
