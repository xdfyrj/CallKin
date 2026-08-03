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
    CANDIDATE_SCOPES,
    DEFAULT_BUILD,
    DEFAULT_CANDIDATE_SCOPE,
    DEFAULT_PROFILE,
    RUST_NONSTD_CANDIDATE_SCOPE,
    SUBJECT_CANDIDATE_SCOPE,
    boundaries_json_for,
    build_manifest_for,
    gt_json_for,
    normalize_profile,
    normalize_candidate_scope,
    resolve_gt_binary,
    split_case_build,
    users_json_for,
)
from provenance import BuildProvenance


GT_SCHEMA_VERSION = 5
USERS_SCHEMA_VERSION = 5
DEFAULT_ID_BIAS = 0x100000
STANDARD_RUST_NAMESPACES = ("core", "alloc", "std")
_RUST_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:])([A-Za-z_][A-Za-z0-9_]*)::")


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


def rust_symbol_owner(demangled_name: str) -> str | None:
    """Return the crate that owns a demangled Rust function when observable."""
    if "::" not in demangled_name:
        return None
    if not demangled_name.startswith("<"):
        match = _RUST_PATH_RE.match(demangled_name)
        return match.group(1) if match else None

    header = _outer_impl_header(demangled_name)
    if header is None:
        return None
    roots = _RUST_PATH_RE.findall(header)
    for root in roots:
        if root not in STANDARD_RUST_NAMESPACES:
            return root
    return roots[0] if roots else None


def is_rust_nonstd_candidate(
    demangled_name: str,
    *,
    root_namespace: str,
) -> bool:
    if demangled_name == f"{root_namespace}::main":
        return False
    owner = rust_symbol_owner(demangled_name)
    return owner is not None and owner not in STANDARD_RUST_NAMESPACES


def _outer_impl_header(name: str) -> str | None:
    depth = 0
    for index, char in enumerate(name):
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
            if depth == 0:
                return name[1:index]
    return None


def origin_from_symbol(
    demangled_name: str,
    namespaces: tuple[str, ...],
    *,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
    root_namespace: str | None = None,
) -> str | None:
    candidate_scope = normalize_candidate_scope(candidate_scope)
    if candidate_scope == RUST_NONSTD_CANDIDATE_SCOPE:
        if root_namespace is None:
            raise ValueError("rust-nonstd origin extraction requires root_namespace")
        if not is_rust_nonstd_candidate(
            demangled_name,
            root_namespace=root_namespace,
        ):
            return None
        origin = demangled_name
    else:
        origin = _subject_origin(demangled_name, namespaces)
        if origin is None:
            return None

    origin = re.sub(r"::h[0-9a-fA-F]{16}$", "", origin)
    origin = preserve_derived_impl_identity(origin)
    origin = strip_rust_generic_args(origin)

    if not origin:
        return None

    return origin


def _subject_origin(
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
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
    root_namespace: str | None = None,
) -> dict[str, Any]:
    members_by_origin: dict[str, dict[str, int]] = defaultdict(dict)
    member_addr: dict[str, int] = {}
    symbols_by_member: dict[str, list[str]] = {}
    owner_by_member: dict[str, str] = {}
    shared_origins_by_member: dict[str, set[str]] = {}
    alias_notes: list[str] = []

    for symbol in symbols:
        origin = origin_from_symbol(
            symbol.name,
            namespaces,
            candidate_scope=candidate_scope,
            root_namespace=root_namespace,
        )
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

            if candidate_scope == RUST_NONSTD_CANDIDATE_SCOPE:
                shared_origins = shared_origins_by_member.setdefault(
                    member_id,
                    {owner},
                )
                shared_origins.add(origin)
                shared_origin = f"shared-address@{member_id}"
                if owner != shared_origin:
                    members_by_origin[owner].pop(member_id, None)
                    members_by_origin[shared_origin][member_id] = symbol.addr
                    owner_by_member[member_id] = shared_origin
                if symbol.name not in symbols_by_member[member_id]:
                    symbols_by_member[member_id].append(symbol.name)
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
        (
            item
            for item in members_by_origin.items()
            if item[1]
        ),
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
        "schema_version": 6 if shared_origins_by_member else GT_SCHEMA_VERSION,
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
    if shared_origins_by_member:
        gt["cross_origin_aliases"] = [
            {
                "member": member_id,
                "origins": sorted(origins),
            }
            for member_id, origins in sorted(shared_origins_by_member.items())
        ]

    return gt


def user_addresses(
    *,
    symbols: list[Symbol],
    namespaces: tuple[str, ...],
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
    root_namespace: str | None = None,
) -> list[int]:
    addresses = {
        symbol.addr
        for symbol in symbols
        if origin_from_symbol(
            symbol.name,
            namespaces,
            candidate_scope=candidate_scope,
            root_namespace=root_namespace,
        ) is not None
    }
    return sorted(addresses)


def user_function_bounds(
    *,
    symbols: list[Symbol],
    namespaces: tuple[str, ...],
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
    root_namespace: str | None = None,
) -> dict[int, int]:
    """Return candidate symbol extents, including the source main boundary."""
    candidate_scope = normalize_candidate_scope(candidate_scope)
    if candidate_scope == RUST_NONSTD_CANDIDATE_SCOPE and root_namespace is None:
        raise ValueError("rust-nonstd bounds require root_namespace")
    bounds: dict[int, int] = {}

    for symbol in symbols:
        belongs = (
            belongs_to_subject(symbol.name, namespaces)
            if candidate_scope == SUBJECT_CANDIDATE_SCOPE
            else is_rust_nonstd_candidate(
                symbol.name,
                root_namespace=root_namespace or "",
            )
            or symbol.name == f"{root_namespace}::main"
        )
        if not belongs:
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


def rust_function_bounds(symbols: list[Symbol]) -> dict[int, int]:
    """Return scope-independent extents for demangled Rust text symbols."""
    bounds: dict[int, int] = {}
    for symbol in symbols:
        if rust_symbol_owner(symbol.name) is None:
            continue
        if symbol.size <= 0:
            raise ValueError(
                f"missing Rust symbol size for {symbol.name!r} at "
                f"0x{symbol.addr:x}"
            )
        previous = bounds.get(symbol.addr)
        if previous is not None and previous != symbol.size:
            raise ValueError(
                f"conflicting Rust symbol sizes at 0x{symbol.addr:x}: "
                f"0x{previous:x} and 0x{symbol.size:x}"
            )
        bounds[symbol.addr] = symbol.size
    if not bounds:
        raise ValueError("no sized demangled Rust text symbols were found")
    return dict(sorted(bounds.items()))


def make_function_boundaries_json(
    *,
    function_bounds: dict[int, int],
    case: str,
    build: str,
    profile: str,
    binary_path: str,
    provenance: BuildProvenance,
) -> dict[str, Any]:
    return {
        "case": case,
        "build": build,
        "profile": profile,
        "schema_version": 1,
        "provenance": provenance.to_dict(),
        "source": binary_path,
        "function_bounds": [
            {"address": f"0x{addr:x}", "size": size}
            for addr, size in sorted(function_bounds.items())
        ],
    }


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
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
    root_namespace: str | None = None,
) -> dict[str, Any]:
    common = {
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
    if root_namespace is None:
        return common

    candidate_scope = normalize_candidate_scope(candidate_scope)
    common["schema_version"] = 6
    common["scope"] = candidate_scope
    common["root_namespace"] = root_namespace
    common["excluded_namespaces"] = (
        list(STANDARD_RUST_NAMESPACES)
        if candidate_scope == RUST_NONSTD_CANDIDATE_SCOPE
        else []
    )
    return common


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
    parser.add_argument(
        "--boundaries",
        help="output path for scope-independent Rust function boundaries",
    )
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
    args.candidate_scope = normalize_candidate_scope(args.candidate_scope)

    if not Path(args.binary).exists():
        args.binary = resolve_gt_binary(case, build, args.profile)
    args.output = args.output or gt_json_for(
        case,
        build,
        args.profile,
        args.candidate_scope,
    )
    args.users = args.users or users_json_for(
        case,
        build,
        args.profile,
        args.candidate_scope,
    )
    args.boundaries = args.boundaries or boundaries_json_for(
        case,
        build,
        args.profile,
    )
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
        root_namespace = verified.root_namespace

        symbols = parse_nm_lines(run_nm(args.binary, args.nm_tool))
        user_addrs = user_addresses(
            symbols=symbols,
            namespaces=namespaces,
            candidate_scope=args.candidate_scope,
            root_namespace=root_namespace,
        )
        function_bounds = user_function_bounds(
            symbols=symbols,
            namespaces=namespaces,
            candidate_scope=args.candidate_scope,
            root_namespace=root_namespace,
        )
        all_boundaries = rust_function_bounds(symbols)
        gt = make_ground_truth(
            symbols=symbols,
            case=case,
            build=build,
            profile=args.profile,
            namespaces=namespaces,
            id_bias=args.id_bias,
            provenance=verified.provenance,
            candidate_scope=args.candidate_scope,
            root_namespace=root_namespace,
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
                candidate_scope=args.candidate_scope,
                root_namespace=root_namespace,
            )
            write_json(users_json, args.users)
            print(f"wrote {args.users}")
            print(f"users={len(user_addrs)}")
        if args.boundaries:
            write_json(
                make_function_boundaries_json(
                    function_bounds=all_boundaries,
                    case=case,
                    build=build,
                    profile=args.profile,
                    binary_path=args.binary,
                    provenance=verified.provenance,
                ),
                args.boundaries,
            )
            print(f"wrote {args.boundaries}")
            print(f"function boundaries={len(all_boundaries)}")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
