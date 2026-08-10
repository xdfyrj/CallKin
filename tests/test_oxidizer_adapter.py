from __future__ import annotations

import os
import sys
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_evidence import make_raw_graph
from oxidizer_adapter import (
    build_label_artifact,
    probe_from_label_cache,
    run_oxidizer_probe,
    validate_label_artifact,
)
from provenance import BuildProvenance


PROVENANCE = BuildProvenance(
    build_id="oxidizer-test",
    source_sha256="1" * 64,
    non_stripped_sha256="2" * 64,
    stripped_sha256="3" * 64,
)


def _function(address: int) -> dict[str, object]:
    return {
        "address": f"0x{address:x}",
        "name": f"function_{address:x}",
        "size": 0x20,
        "boundary_source": "symbol-oracle",
        "discovered_by_radare2": True,
    }


def _match(address: int, name: str, evidence: str) -> dict[str, str]:
    return {
        "address": f"0x{address:x}",
        "mapped_address": f"0x{address + 0x400000:x}",
        "name": name,
        "canonical_origin": "probe-only",
        "owner": "probe-only",
        "evidence": evidence,
    }


def main() -> int:
    raw = make_raw_graph(
        case="oxidizer-test",
        build="O3S",
        profile="plain",
        binary_path="bin/plain/oxidizer-test.O3S.fixture.bin",
        provenance=PROVENANCE,
        boundary_input_sha256="4" * 64,
        root_address=0x1000,
        functions=[_function(address) for address in (0x1000, 0x2000, 0x3000)],
        transfers=[],
        boundary_mode="symbol-extent",
        boundary_mismatches=[],
    )
    probe = {
        "schema_version": 1,
        "case": "oxidizer-test",
        "build": "O3S",
        "profile": "plain",
        "stripped_sha256": PROVENANCE.stripped_sha256,
        "analysis": {"input": "stripped-only", "cfg": "CFGFast(normalize=True)"},
        "tool": {"oxidizer_commit": "test"},
        "matches": [
            _match(
                0x2000,
                "core::ptr::drop_in_place<alloc::string::String>",
                "direct-flirt",
            ),
            _match(0x4000, "std::mem::replace", "direct-flirt"),
        ],
        "propagated_wrappers": [
            _match(0x3000, "core::ptr::drop_in_place", "propagated-wrapper"),
        ],
        "cleanup_heuristics": [
            _match(0x5000, "core::ptr::drop_in_place", "cleanup-heuristic"),
        ],
    }

    artifact = build_label_artifact(raw=raw, probe=probe)
    validate_label_artifact(artifact)
    if artifact["matches"] != [{
        "address": "0x2000",
        "mapped_address": "0x402000",
        "name": "core::ptr::drop_in_place<alloc::string::String>",
        "canonical_origin": "core::ptr::drop_in_place",
        "owner": "core",
        "evidence": "direct-flirt",
    }]:
        print(f"FAIL direct FLIRT evidence: {artifact['matches']}")
        return 1
    if len(artifact["propagated_wrappers"]) != 1:
        print("FAIL propagated wrapper was not preserved separately")
        return 1
    unmatched = {
        (entry["address"], entry["evidence"])
        for entry in artifact["unmatched_addresses"]
    }
    if unmatched != {
        ("0x4000", "direct-flirt"),
        ("0x5000", "cleanup-heuristic"),
    }:
        print(f"FAIL unmatched labels were dropped or changed: {unmatched}")
        return 1
    if artifact["analysis"]["seed_policy"] != "direct-flirt-only":
        print("FAIL adapter did not enforce direct-FLIRT-only seed policy")
        return 1
    rebuilt = build_label_artifact(
        raw=raw,
        probe=probe_from_label_cache(artifact),
    )
    if rebuilt != artifact:
        print("FAIL cached label evidence did not reproduce the same artifact")
        return 1

    with tempfile.TemporaryDirectory() as temp_dir:
        oxidizer_dir = Path(temp_dir) / "oxidizer"
        oxidizer_dir.mkdir()
        (oxidizer_dir / "pyproject.toml").write_text("[project]\nname='test'\n")
        (oxidizer_dir / "uv.lock").write_text("version = 1\n")
        seen = {}

        def fake_run(command, **kwargs):
            seen["command"] = command
            seen["cwd"] = kwargs["cwd"]
            output = Path(command[command.index("--output") + 1])
            output.write_text(json.dumps(probe), encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("oxidizer_adapter.shutil.which", return_value="/usr/bin/uv"), patch(
            "oxidizer_adapter.subprocess.run", side_effect=fake_run
        ):
            rerun_probe = run_oxidizer_probe(
                oxidizer_dir=oxidizer_dir,
                binary_path="bin/plain/oxidizer-test.O3S.fixture.bin",
                case="oxidizer-test",
                build="O3S",
                profile="plain",
                timeout_seconds=1,
            )
        if rerun_probe != probe:
            print("FAIL isolated probe output changed")
            return 1
        if seen["command"][:4] != ["uv", "run", "--frozen", "python"]:
            print(f"FAIL adapter did not use Oxidizer uv environment: {seen['command']}")
            return 1
        if seen["cwd"] != oxidizer_dir:
            print("FAIL adapter did not run from Oxidizer checkout")
            return 1

    print("Oxidizer direct-FLIRT adapter PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
