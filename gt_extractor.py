from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from build_manifest import BUILD_TARGET, load_and_verify_manifest
from paths import (
    BUILD_PROFILES,
    DEFAULT_BUILD,
    DEFAULT_PROFILE,
    build_manifest_for,
    gt_json_for,
    normalize_profile,
    resolve_gt_binary,
    split_case_build,
    users_json_for,
)
from provenance import BuildProvenance


GT_SCHEMA_VERSION = 5
USERS_SCHEMA_VERSION = 5
DEFAULT_ID_BIAS = 0x100000


@dataclass(frozen=True)
class Symbol:
    addr: int
    size: int
    kind: str
    name: str


def function_id(addr: int, *, id_bias: int = DEFAULT_ID_BIAS) -> str:
    return f"FUN_{addr + id_bias:08x}"


def parse_int(value: str) -> int:
    return int(value, 0)


def run_nm(binary_path: str, nm_tool: str) -> list[str]:
    result = subprocess.run(
        [nm_tool, "-n", "-S", "-C", binary_path],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.splitlines()


def parse_nm_lines(lines: list[str]) -> list[Symbol]:
    symbols: list[Symbol] = []

    for line in lines:
        parts = line.strip().split(maxsplit=3)
        if len(parts) == 4:
            addr_text, size_text, kind, name = parts
        elif len(parts) == 3:
            # Compatibility with nm output/tests that do not provide -S.
            addr_text, kind, name = parts
            size_text = "0"
        else:
            continue
        if kind not in {"t", "T"}:
            continue

        try:
            addr = int(addr_text, 16)
            size = int(size_text, 16)
        except ValueError:
            continue

        symbols.append(Symbol(addr=addr, size=size, kind=kind, name=name))

    return symbols


def belongs_to_subject(demangled_name: str, namespaces: tuple[str, ...]) -> bool:
    return any(
        demangled_name.startswith(f"{namespace}::")
        or demangled_name.startswith(f"<{namespace}::")
        for namespace in namespaces
    )


def origin_from_symbol(
    demangled_name: str,
    namespaces: tuple[str, ...],
) -> str | None:
    matched_namespace = next(
        (
            namespace
            for namespace in namespaces
            if demangled_name.startswith(f"{namespace}::")
        ),
        None,
    )
    if matched_namespace is not None:
        relative = demangled_name[len(matched_namespace) + 2:]
        if relative == "main" or not relative:
            return None
        origin = (
            demangled_name
            if len(namespaces) > 1
            else relative
        )
    elif any(
        demangled_name.startswith(f"<{namespace}::")
        for namespace in namespaces
    ):
        origin = demangled_name
    else:
        return None

    origin = re.sub(r"::h[0-9a-fA-F]{16}$", "", origin)
    origin = preserve_derived_impl_identity(origin)
    origin = strip_rust_generic_args(origin)

    if not origin:
        return None

    return origin


def preserve_derived_impl_identity(name: str) -> str:
    """Keep the implementation target encoded in rustc's ::<impl ...> paths."""
    marker = "::<"
    start = 0
    while True:
        marker_index = name.find(marker, start)
        if marker_index < 0:
            return name

        content_start = marker_index + len(marker)
        depth = 1
        index = content_start
        while index < len(name) and depth:
            if name[index] == "<":
                depth += 1
            elif name[index] == ">":
                depth -= 1
            index += 1
        if depth:
            return name

        content = name[content_start:index - 1]
        if content.startswith("impl "):
            if " for " in content:
                target_type = content.rsplit(" for ", 1)[1]
                replacement = f"::impl_for={target_type}"
            else:
                target_type = content[len("impl "):]
                replacement = f"::impl={target_type}"
            name = name[:marker_index] + replacement + name[index:]
            start = marker_index + len(replacement)
        else:
            start = index


def strip_rust_generic_args(name: str) -> str:
    # v0 mangling can demangle monomorphized instances as `foo::<T>`.
    # Ground truth origin is the source path with type arguments removed.
    out: list[str] = []
    i = 0

    while i < len(name):
        if name.startswith("::<", i):
            i += 3
            depth = 1
            while i < len(name) and depth:
                if name[i] == "<":
                    depth += 1
                elif name[i] == ">":
                    depth -= 1
                i += 1
            continue

        out.append(name[i])
        i += 1

    return "".join(out)


def make_ground_truth(
    *,
    symbols: list[Symbol],
    case: str,
    build: str,
    profile: str,
    namespaces: tuple[str, ...],
    id_bias: int,
    provenance: BuildProvenance,
) -> dict[str, Any]:
    members_by_origin: dict[str, dict[str, int]] = defaultdict(dict)
    member_addr: dict[str, int] = {}
    symbols_by_member: dict[str, list[str]] = {}
    owner_by_member: dict[str, str] = {}
    alias_notes: list[str] = []

    for symbol in symbols:
        origin = origin_from_symbol(symbol.name, namespaces)
        if origin is None:
            continue

        member_id = function_id(symbol.addr, id_bias=id_bias)
        owner = owner_by_member.get(member_id)

        if owner is not None:
            if owner == origin:
                if symbol.name not in symbols_by_member[member_id]:
                    symbols_by_member[member_id].append(symbol.name)
                alias_notes.append(
                    f"{member_id}: duplicate symbol for origin {origin!r} "
                    f"kept once ({symbol.name})"
                )
                continue

            raise ValueError(
                f"cross-origin address alias at {member_id}: "
                f"first origin {owner!r}, later origin {origin!r} "
                f"({symbol.name}). Rebuild without cross-origin folding or "
                "exclude/handle this case before scoring."
            )

        owner_by_member[member_id] = origin
        member_addr[member_id] = symbol.addr
        symbols_by_member[member_id] = [symbol.name]
        members_by_origin[origin][member_id] = symbol.addr

    origins = []
    for origin, members in sorted(
        members_by_origin.items(),
        key=lambda item: min(item[1].values()),
    ):
        sorted_members = sorted(
            members.items(),
            key=lambda item: item[1],
        )
        origins.append(
            {
                "origin": origin,
                "members": [member_id for member_id, _addr in sorted_members],
            }
        )

    if not origins:
        raise ValueError(f"no text symbols matched namespaces {namespaces!r}")

    gt: dict[str, Any] = {
        "case": case,
        "build": build,
        "profile": profile,
        "schema_version": GT_SCHEMA_VERSION,
        "provenance": provenance.to_dict(),
        "origins": origins,
        "symbols": {
            member_id: symbols_by_member[member_id]
            for member_id, _addr in sorted(
                member_addr.items(),
                key=lambda item: item[1],
            )
        },
    }

    if alias_notes:
        gt["note"] = "address aliases/duplicates: " + "; ".join(alias_notes)

    return gt


def user_addresses(
    *,
    symbols: list[Symbol],
    namespaces: tuple[str, ...],
) -> list[int]:
    addresses = {
        symbol.addr
        for symbol in symbols
        if origin_from_symbol(symbol.name, namespaces) is not None
    }
    return sorted(addresses)


def user_function_bounds(
    *,
    symbols: list[Symbol],
    namespaces: tuple[str, ...],
) -> dict[int, int]:
    """Return symbol extents for namespace functions, including source main."""
    bounds: dict[int, int] = {}

    for symbol in symbols:
        if not belongs_to_subject(symbol.name, namespaces):
            continue
        if symbol.size <= 0:
            raise ValueError(
                f"missing symbol size for {symbol.name!r} at 0x{symbol.addr:x}; "
                "use an nm-compatible tool that supports -S"
            )

        previous = bounds.get(symbol.addr)
        if previous is not None and previous != symbol.size:
            raise ValueError(
                f"conflicting symbol sizes at 0x{symbol.addr:x}: "
                f"0x{previous:x} and 0x{symbol.size:x}"
            )
        bounds[symbol.addr] = symbol.size

    if not bounds:
        raise ValueError(f"no sized text symbols matched namespaces {namespaces!r}")
    return dict(sorted(bounds.items()))


def make_users_json(
    *,
    addresses: list[int],
    function_bounds: dict[int, int],
    case: str,
    build: str,
    profile: str,
    binary_path: str,
    namespaces: tuple[str, ...],
    provenance: BuildProvenance,
) -> dict[str, Any]:
    return {
        "case": case,
        "build": build,
        "profile": profile,
        "schema_version": USERS_SCHEMA_VERSION,
        "provenance": provenance.to_dict(),
        "source": binary_path,
        "namespaces": list(namespaces),
        "addresses": [f"0x{addr:x}" for addr in addresses],
        "function_bounds": [
            {"address": f"0x{addr:x}", "size": size}
            for addr, size in sorted(function_bounds.items())
        ],
    }


def validate_against_fixture(gt: dict[str, Any], fixture_path: str) -> None:
    from loader import load_case

    case = load_case(fixture_path)
    if (case.case, case.build, case.profile) != (
        gt["case"], gt["build"], gt["profile"]
    ):
        raise ValueError(
            "ground truth/fixture identity mismatch: "
            f"fixture={case.case}/{case.build}/{case.profile}, "
            f"ground_truth={gt['case']}/{gt['build']}/{gt['profile']}"
        )
    if case.provenance is None or case.provenance.to_dict() != gt["provenance"]:
        raise ValueError("ground truth/fixture build provenance mismatch")
    scored_ids = {node.id for node in case.nodes if node.scored}
    gt_ids = {
        member
        for origin in gt["origins"]
        for member in origin["members"]
    }

    if scored_ids != gt_ids:
        raise ValueError(
            "generated ground truth does not match fixture scored universe. "
            f"missing in ground truth: {sorted(scored_ids - gt_ids)}; "
            f"present in ground truth but not scored: {sorted(gt_ids - scored_ids)}"
        )


def write_json(data: dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract this project's ground_truth/*.gt.json from a non-stripped "
            "Rust binary's demangled symbols."
        )
    )
    parser.add_argument("binary", help="non-stripped ELF/Rust binary path, or an example stem")
    parser.add_argument(
        "output",
        nargs="?",
        help=(
            "output path. If omitted, writes "
            "ground_truth/<profile>/<case>.<build>.gt.json."
        ),
    )
    parser.add_argument("--case", help="case field written into generated JSON")
    parser.add_argument(
        "--build",
        help=f"build field written into generated JSON. Default: {DEFAULT_BUILD}",
    )
    parser.add_argument(
        "--profile",
        choices=BUILD_PROFILES,
        default=DEFAULT_PROFILE,
        help=f"compiler profile. Default: {DEFAULT_PROFILE}",
    )
    parser.add_argument(
        "--namespace",
        dest="namespaces",
        action="append",
        help=(
            "subject-owned Rust crate namespace. Repeat for multiple crates. "
            "Default: namespaces recorded in the build manifest."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_option",
        help="output path. Kept for compatibility; positional output is preferred.",
    )
    parser.add_argument(
        "--fixture",
        help="optional fixture JSON used to validate the scored node universe",
    )
    parser.add_argument("--users", help="output path for user address JSON")
    parser.add_argument("--manifest", help="override and verify build manifest path")
    parser.add_argument(
        "--id-bias",
        type=parse_int,
        default=DEFAULT_ID_BIAS,
        help="value added to raw symbol addresses when formatting FUN_ ids",
    )
    parser.add_argument(
        "--nm-tool",
        default="nm",
        help="nm-compatible symbol tool. Default: nm",
    )
    return parser


def apply_cli_defaults(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.output and args.output_option and args.output != args.output_option:
        parser.error("use either positional output or --output, not both")

    args.output = args.output_option or args.output
    case, build = split_case_build(args.binary, args.build)
    args.profile = normalize_profile(args.profile)

    if not Path(args.binary).exists():
        args.binary = resolve_gt_binary(case, build, args.profile)
    args.output = args.output or gt_json_for(case, build, args.profile)
    args.users = args.users or users_json_for(case, build, args.profile)
    args.case = args.case or case
    args.build = build
    args.manifest = args.manifest or build_manifest_for(case, build, args.profile)


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    apply_cli_defaults(args, parser)

    try:
        output_path = args.output
        case = args.case
        build = args.build
        verified = load_and_verify_manifest(
            args.manifest,
            expected_case=case,
            expected_build=build,
            expected_profile=args.profile,
            expected_target=BUILD_TARGET,
        )
        if Path(args.binary).resolve() != Path(verified.non_stripped_binary).resolve():
            raise ValueError(
                f"binary does not match build manifest: {args.binary!r} != "
                f"{verified.non_stripped_binary!r}"
            )
        namespaces = tuple(args.namespaces or verified.candidate_namespaces)

        symbols = parse_nm_lines(run_nm(args.binary, args.nm_tool))
        user_addrs = user_addresses(symbols=symbols, namespaces=namespaces)
        function_bounds = user_function_bounds(
            symbols=symbols,
            namespaces=namespaces,
        )
        gt = make_ground_truth(
            symbols=symbols,
            case=case,
            build=build,
            profile=args.profile,
            namespaces=namespaces,
            id_bias=args.id_bias,
            provenance=verified.provenance,
        )

        if args.fixture:
            validate_against_fixture(gt, args.fixture)

        if output_path:
            write_json(gt, output_path)
            print(f"wrote {output_path}")
            print(f"origins={len(gt['origins'])}")
        else:
            print(json.dumps(gt, indent=2))

        if args.users:
            users_json = make_users_json(
                addresses=user_addrs,
                function_bounds=function_bounds,
                case=case,
                build=build,
                profile=args.profile,
                binary_path=args.binary,
                namespaces=namespaces,
                provenance=verified.provenance,
            )
            write_json(users_json, args.users)
            print(f"wrote {args.users}")
            print(f"users={len(user_addrs)}")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
