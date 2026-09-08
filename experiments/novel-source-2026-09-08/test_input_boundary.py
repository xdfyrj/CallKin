"""Regression guard: observation may retain labels without consuming them."""

from __future__ import annotations

import tempfile
from pathlib import Path

import infer_novel_source as infer
from novel_common import sha256_file, source_record


class _MustNotOpen(str):
    def __new__(cls):
        return super().__new__(cls, "/must-not-open/label.json")

    def __fspath__(self):
        raise AssertionError("GT/linkage was consumed by observation")


def test_observation_inputs_exclude_gt_and_linkage():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config_path, protocol_path = root / "config.json", root / "protocol.md"
        config_path.write_text("{}", encoding="utf-8")
        protocol_path.write_text("protocol", encoding="utf-8")
        consumed = {}
        for name, content in (("body", '{"functions": []}'), ("fixture", "{}"), ("raw", "{}")):
            path = root / f"{name}.json"
            path.write_text(content, encoding="utf-8")
            consumed[name] = source_record(path)
        metadata_path = root / "metadata.json"
        metadata_path.write_text("metadata", encoding="utf-8")
        config = {"case": "case"}
        identity = {"case": "case", "build": "O3S", "profile": "plain", "track": "angr", "anchor_policy": "role", "candidate_scope": "rust-nonstd", "mode": "out-in", "k": 16}
        metadata = {**identity, "status": "completed", "config_sha256": sha256_file(config_path), "protocol_sha256": sha256_file(protocol_path), "base_commit": "base", "implementation_sha256": {"code": "hash"}, "outputs": {"body": consumed["body"], "fixture": consumed["fixture"], "raw_graph": consumed["raw"], "ground_truth": {"path": _MustNotOpen(), "sha256": "never"}, "linkage": {"path": _MustNotOpen(), "sha256": "never"}}}
        paths = {"observation_metadata": metadata_path, "body": root / "body.json", "fixture": root / "fixture.json", "raw_graph": root / "raw.json"}
        old = (infer.case_paths, infer.case_identity, infer.core_base_commit, infer.frozen_implementation_hashes, infer._config_path, infer._protocol_path, infer.read_json)
        seen = []
        try:
            infer.case_paths = lambda _config, _case: paths
            infer.case_identity = lambda _config, _case: identity
            infer.core_base_commit = lambda _config: "base"
            infer.frozen_implementation_hashes = lambda _config: {"code": "hash"}
            infer._config_path = lambda: config_path
            infer._protocol_path = lambda: protocol_path
            infer.read_json = lambda path: metadata if Path(path) == metadata_path else ({"functions": []} if Path(path) == paths["body"] else {})
            original = infer.verify_output_hashes
            def checked(records):
                if {"ground_truth", "linkage"} & set(records):
                    raise AssertionError("observation consumed deferred labels")
                seen.append(set(records))
                return original(records)
            infer.verify_output_hashes = checked
            observed, body, _ = infer._observation_inputs(config, "case")
        finally:
            (infer.case_paths, infer.case_identity, infer.core_base_commit, infer.frozen_implementation_hashes, infer._config_path, infer._protocol_path, infer.read_json) = old
            infer.verify_output_hashes = original
        assert body == {"functions": []}
        assert seen == [{"body", "fixture", "raw_graph"}]
        assert observed["status"] == "completed"


if __name__ == "__main__":
    test_observation_inputs_exclude_gt_and_linkage()
    print("PASS: observation input boundary")
