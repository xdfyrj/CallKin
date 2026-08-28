"""Audit GT origins for codegen duplicates using raw linkage symbols.

`gt_extractor.py` reads `nm -C`, so the ground truth only keeps demangled
names. Demangling erases the disambiguator hash, which is the one field that
separates two monomorphizations of a generic from the same mono item emitted
into several codegen units. This overlay reads the raw `.symtab` of the
non-stripped binary and classifies every multi-member origin without touching
the existing ground truth.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from build_manifest import sha256_file  # noqa: E402
from gt_extractor import DEFAULT_ID_BIAS  # noqa: E402


AUDIT_SCHEMA_VERSION = 1
AUDIT_ARTIFACT = "v1-gt-mangled-audit"

REPEATED = "repeated_linkage_identity"
DISTINCT = "distinct_linkage_identities"
UNRESOLVED = "unresolved"


def address_from_function_id(
    function_id: str,
    *,
    id_bias: int = DEFAULT_ID_BIAS,
) -> int:
    """Invert `gt_extractor.function_id()`."""
    if not function_id.startswith("FUN_"):
        raise ValueError(f"not a function id: {function_id!r}")
    try:
        biased = int(function_id[4:], 16)
    except ValueError as exc:
        raise ValueError(f"not a function id: {function_id!r}") from exc
    return biased - id_bias


def read_raw_function_symbols(binary_path: str | Path) -> dict[int, frozenset[str]]:
    """Map each text address to the raw (still mangled) symbol names on it."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError("Python package pyelftools is required") from exc

    path = Path(binary_path)
    names: dict[int, set[str]] = {}
    with path.open("rb") as stream:
        try:
            elf = ELFFile(stream)
        except Exception as exc:
            raise ValueError(f"invalid ELF binary: {binary_path}") from exc
        section = elf.get_section_by_name(".symtab")
        if section is None:
            raise ValueError(
                f"{binary_path} has no .symtab; the audit needs a non-stripped binary"
            )
        for symbol in section.iter_symbols():
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            address = int(symbol["st_value"])
            if not address or not symbol.name:
                continue
            names.setdefault(address, set()).add(symbol.name)
    return {address: frozenset(value) for address, value in names.items()}


def raw_symbols_by_member(
    members: Iterable[str],
    raw_symbols: Mapping[int, frozenset[str]],
    *,
    id_bias: int = DEFAULT_ID_BIAS,
) -> dict[str, frozenset[str]]:
    return {
        member: raw_symbols.get(
            address_from_function_id(member, id_bias=id_bias),
            frozenset(),
        )
        for member in members
    }


def classify_members(by_member: Mapping[str, frozenset[str]]) -> str:
    """Classify one origin from its members' raw symbol sets.

    Members are compared as sets rather than single names so that an address
    carrying several aliases stays comparable with another address carrying the
    same aliases.
    """
    sets = list(by_member.values())
    if not sets or any(not names for names in sets):
        return UNRESOLVED
    first = sets[0]
    return REPEATED if all(names == first for names in sets[1:]) else DISTINCT


def build_audit(
    ground_truth: Mapping[str, Any],
    raw_symbols: Mapping[int, frozenset[str]],
    *,
    ground_truth_sha256: str,
    binary_sha256: str,
    id_bias: int = DEFAULT_ID_BIAS,
) -> dict[str, Any]:
    origins = ground_truth.get("origins")
    if not isinstance(origins, list) or not origins:
        raise ValueError("ground truth must contain a non-empty origins list")
    expected_binary_sha256 = (ground_truth.get("provenance") or {}).get(
        "non_stripped_sha256"
    )
    if expected_binary_sha256 and expected_binary_sha256 != binary_sha256:
        raise ValueError(
            "non-stripped binary hash does not match the ground-truth provenance"
        )

    entries: list[dict[str, Any]] = []
    counts = {REPEATED: 0, DISTINCT: 0, UNRESOLVED: 0}
    for group in origins:
        members = list(group["members"])
        if len(members) < 2:
            continue
        by_member = raw_symbols_by_member(members, raw_symbols, id_bias=id_bias)
        classification = classify_members(by_member)
        counts[classification] += 1
        entries.append(
            {
                "classification": classification,
                "origin": group["origin"],
                "members": sorted(members),
                "raw_symbols": sorted(set().union(*by_member.values())),
                "raw_symbols_by_member": {
                    member: sorted(by_member[member]) for member in sorted(by_member)
                },
            }
        )

    entries.sort(key=lambda item: item["origin"])
    member_counts = {name: 0 for name in counts}
    for entry in entries:
        member_counts[entry["classification"]] += len(entry["members"])

    return {
        "artifact": AUDIT_ARTIFACT,
        "schema_version": AUDIT_SCHEMA_VERSION,
        "case": ground_truth.get("case"),
        "build": ground_truth.get("build"),
        "profile": ground_truth.get("profile"),
        "provenance": {
            "ground_truth_sha256": ground_truth_sha256,
            "non_stripped_sha256": binary_sha256,
            "id_bias": id_bias,
        },
        "summary": {
            "multimember_origin_count": len(entries),
            "family_counts": counts,
            "member_counts": member_counts,
        },
        "origins": entries,
    }


def audit_ground_truth_files(
    ground_truth_path: str | Path,
    binary_path: str | Path,
    *,
    id_bias: int = DEFAULT_ID_BIAS,
) -> dict[str, Any]:
    ground_truth = json.loads(Path(ground_truth_path).read_text(encoding="utf-8"))
    return build_audit(
        ground_truth,
        read_raw_function_symbols(binary_path),
        ground_truth_sha256=sha256_file(ground_truth_path),
        binary_sha256=sha256_file(binary_path),
        id_bias=id_bias,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classify GT origins as codegen duplicates or distinct instances."
    )
    parser.add_argument("ground_truth")
    parser.add_argument("non_stripped_binary")
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = audit_ground_truth_files(args.ground_truth, args.non_stripped_binary)
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        else:
            print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        print(f"wrote {args.output}")
    summary = report["summary"]
    for name, count in sorted(summary["family_counts"].items()):
        print(f"{name}={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
