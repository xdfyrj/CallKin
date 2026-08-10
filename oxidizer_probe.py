"""Run Oxidizer in its own environment and snapshot FLIRT evidence stages.

This script intentionally imports Oxidizer's angr fork.  CallKin invokes it
only as a subprocess through oxidizer_adapter.py; do not import it from the
CallKin interpreter.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


LABEL_SCHEMA_VERSION = 1
PROBE_VERSION = "direct-flirt-probe-v1"
_RUST_HASH_RE = re.compile(r"::h[0-9a-fA-F]{16}$")
_OWNER_RE = re.compile(r"(?<![A-Za-z0-9_:])([A-Za-z_][A-Za-z0-9_]*)::")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_files(paths: list[str]) -> str | None:
    if not paths:
        return None
    digest = hashlib.sha256()
    for value in sorted(paths):
        path = Path(value)
        name = path.name.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def linked_address(project: Any, mapped_address: int) -> int:
    """Convert an angr/CLE mapped VA to the ELF link-time VA."""
    main_object = project.loader.main_object
    return mapped_address - main_object.mapped_base + main_object.linked_base


def canonical_origin(name: str) -> str:
    """Drop Rust hash and displayed type arguments from a recovered label."""
    name = _RUST_HASH_RE.sub("", name)
    out: list[str] = []
    depth = 0
    for char in name:
        if char == "<":
            depth += 1
            continue
        if char == ">" and depth:
            depth -= 1
            continue
        if not depth:
            out.append(char)
    return "".join(out).replace("::::", "::").strip(":")


def rust_owner(name: str) -> str | None:
    match = _OWNER_RE.search(name)
    return match.group(1) if match else None


def _demangle(name: str) -> str:
    from angr.rust.utils.demangler import demangle

    try:
        return demangle(name)
    except Exception:
        return name


def snapshot_flirt_matches(project: Any, *, evidence: str) -> dict[int, dict[str, str]]:
    matches: dict[int, dict[str, str]] = {}
    for function in project.kb.functions.values():
        if function.from_signature != "flirt":
            continue
        mapped = int(function.addr)
        linked = linked_address(project, mapped)
        name = _demangle(str(function.name))
        matches[linked] = {
            "address": f"0x{linked:x}",
            "mapped_address": f"0x{mapped:x}",
            "name": name,
            "canonical_origin": canonical_origin(name),
            "owner": rust_owner(name) or "unknown",
            "evidence": evidence,
        }
    return matches


def _git_commit(directory: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def _module_metadata(module: Any, distribution: str) -> dict[str, str | None]:
    try:
        version = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        version = str(getattr(module, "__version__", "unknown"))
    module_file = Path(str(getattr(module, "__file__", ""))).resolve()
    commit = None
    for directory in (module_file, *module_file.parents):
        if (directory / ".git").exists():
            commit = _git_commit(directory)
            break
    return {"version": version, "commit": commit}


def run_probe(binary: str | Path) -> dict[str, Any]:
    """Return direct, propagated, and cleanup labels without conflating them."""
    import angr
    import archinfo
    import cle
    import pyvex

    logging.getLogger().setLevel(logging.WARNING)
    project = angr.Project(str(binary), auto_load_libs=False, is_rust_binary=True)
    project.analyses.CFGFast(normalize=True)

    config = {
        "cfg": "CFGFast(normalize=True)",
        "signature_opt_levels": ["0", "1", "2", "3"],
        "evidence_stages": [
            "direct-flirt",
            "propagated-wrapper",
            "cleanup-heuristic",
        ],
    }
    version = project.analyses.RustcVersionIdentification()
    signature_paths = []
    for opt_level in ("0", "1", "2", "3"):
        path = Path(version.best_sig_dir) / f"{project.rustc_version}-O{opt_level}.sig"
        if path.is_file():
            project.analyses.Flirt(str(path))
            signature_paths.append(str(path))

    direct = snapshot_flirt_matches(project, evidence="direct-flirt")
    project.analyses.FlirtSigPropagation(
        cfg=project.kb.cfgs.get_most_accurate()
    )
    after_propagation = snapshot_flirt_matches(
        project,
        evidence="propagated-wrapper",
    )
    propagated = {
        address: match
        for address, match in after_propagation.items()
        if address not in direct
    }

    project.analyses.CleanupFunctionIdentification()
    after_cleanup = snapshot_flirt_matches(
        project,
        evidence="cleanup-heuristic",
    )
    cleanup = {
        address: match
        for address, match in after_cleanup.items()
        if address not in direct and address not in propagated
    }

    return {
        "tool": {
            "probe_version": PROBE_VERSION,
            "oxidizer_commit": _git_commit(Path.cwd()),
            "uv_lock_sha256": sha256_file(Path.cwd() / "uv.lock"),
            "angr": _module_metadata(angr, "angr"),
            "cle": _module_metadata(cle, "cle"),
            "pyvex": _module_metadata(pyvex, "pyvex"),
            "archinfo": _module_metadata(archinfo, "archinfo"),
            "detected_rustc_version": project.rustc_version,
            "version_match_count": version.matched_count,
            "signature_directory": str(version.best_sig_dir),
            "signature_paths": signature_paths,
            "signature_database_sha256": sha256_files(signature_paths),
            "type_database_sha256": None,
            "config_sha256": sha256_json(config),
        },
        "matches": [direct[address] for address in sorted(direct)],
        "propagated_wrappers": [
            propagated[address] for address in sorted(propagated)
        ],
        "cleanup_heuristics": [cleanup[address] for address in sorted(cleanup)],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Oxidizer FLIRT and preserve evidence-stage provenance."
    )
    parser.add_argument("--binary", required=True, help="stripped ELF binary")
    parser.add_argument("--output", required=True, help="label JSON output path")
    parser.add_argument("--case", required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--profile", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    binary = Path(args.binary)
    if not binary.is_file():
        print(f"error: stripped binary not found: {binary}", file=sys.stderr)
        return 1

    try:
        result = run_probe(binary)
    except Exception as exc:
        print(f"error: Oxidizer probe failed: {exc}", file=sys.stderr)
        return 1

    output = {
        "schema_version": LABEL_SCHEMA_VERSION,
        "case": args.case,
        "build": args.build,
        "profile": args.profile,
        "stripped_sha256": sha256_file(binary),
        "analysis": {
            "input": "stripped-only",
            "cfg": "CFGFast(normalize=True)",
        },
        **result,
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
