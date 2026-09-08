"""Small checks for the novel-source orchestration guards."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from infer_novel_source import (
    ARM_B2,
    ARM_BODY_SCORE,
    ARM_C3,
    ARM_EXACT,
    ARM_RESCUE,
    ARM_V0,
    _simple_prediction,
)
from novel_common import case_paths, write_json_once
from score_novel_source import _clip_prediction


def test_arm_order_is_frozen():
    assert (ARM_V0, ARM_EXACT, ARM_B2, ARM_C3, ARM_BODY_SCORE, ARM_RESCUE) == (
        "V0-relation",
        "exact-token-hash",
        "B2-token-cfg",
        "C3-token-cfg-relation",
        "B2-body-score",
        "C3-rescue",
    )


def test_simple_prediction_canonicalizes_and_drops_singletons():
    identity = {
        "build": "O3S",
        "profile": "plain",
        "candidate_scope": "rust-nonstd",
    }
    prediction = _simple_prediction(
        "hexyl-v0170",
        identity,
        ARM_V0,
        ["FUN_2", "FUN_1"],
        [["FUN_2", "FUN_1", "FUN_2"], ["FUN_3"]],
    )
    assert prediction["universe"] == {"target_ids": ["FUN_1", "FUN_2"]}
    assert prediction["clusters"] == [
        {"members": ["FUN_1", "FUN_2"], "status": "accepted"}
    ]


def test_clip_prediction_reports_out_of_mask_members():
    prediction = {
        "universe": {"target_ids": ["a", "b", "c"]},
        "clusters": [
            {"members": ["a", "b", "c"], "status": "accepted"},
            {"members": ["b", "c"], "status": "accepted"},
        ],
    }
    clipped, contamination = _clip_prediction(prediction, {"a", "b"})
    assert clipped["universe"] == {"target_ids": ["a", "b"]}
    assert clipped["clusters"] == [
        {"members": ["a", "b"], "status": "accepted"},
    ]
    assert contamination == {
        "out_of_mask_member_count": 2,
        "out_of_mask_members": ["c"],
    }


def test_write_json_once_is_idempotent_and_refuses_drift():
    state = {"bytes": None}

    class FakePath:
        def __init__(self, value):
            self.value = str(value)
            self.parent = self

        def exists(self):
            return state["bytes"] is not None

        def read_bytes(self):
            return state["bytes"]

        def write_bytes(self, value):
            state["bytes"] = value

        def mkdir(self, **_kwargs):
            return None

        def __str__(self):
            return self.value

    with patch("novel_common.Path", FakePath):
        path = FakePath("value.json")
        first = write_json_once(path, {"b": 2, "a": 1})
        assert first == write_json_once(path, {"a": 1, "b": 2})
        try:
            write_json_once(path, {"a": 9})
        except ValueError as exc:
            assert "refusing to overwrite" in str(exc)
        else:
            raise AssertionError("drifted retained output was accepted")


def test_default_paths_follow_frozen_output_templates():
    config = {
        "build": {"build": "O3S", "profile": "plain"},
        "track": "angr",
        "anchor_policy": "role",
        "candidate_scope": "rust-nonstd",
        "mode": "out-in",
        "k": 16,
        "cases": ["hexyl-v0170"],
        "sources": [{
            "id": "hexyl-v0170",
            "source": "workspace/sources/hexyl",
            "namespaces": ["hexyl"],
        }],
        "outputs": {
            "observation": "observations/<case>/",
            "candidates": "candidates/<case>/<arm>.candidates.json",
            "predictions": "predictions/<case>/<arm>/prediction.json",
            "scores": "scores/<case>/<arm>/<label-view>.json",
        },
    }
    paths = case_paths(config, "hexyl-v0170")
    assert paths["ground_truth"].name == "hexyl-v0170.O3S.gt.json"
    assert paths["prediction_dir"].name == "hexyl-v0170"
    assert paths["score_dir"].name == "hexyl-v0170"


def test_observe_imports_core_from_outside_repo_without_pythonpath():
    study = Path(__file__).resolve().parent
    code = f"""
import sys
sys.path.insert(0, {str(study)!r})
import observe_novel_source as observe
import os
os.chdir(observe.REPO_ROOT)
from build_manifest import BUILD_TARGET, load_and_verify_manifest
from novel_common import case_paths

config = observe.read_json(observe._config_path())
paths = case_paths(config, "hexyl-v0170")
manifest = observe._manifest_path(config, "hexyl-v0170", paths)
verified = load_and_verify_manifest(
    manifest,
    expected_case="hexyl-v0170",
    expected_build="O3S",
    expected_profile="plain",
    expected_target=BUILD_TARGET,
)
observe._verify_build_pins(config, "hexyl-v0170", manifest, verified)
assert str(observe.REPO_ROOT) in __import__("sys").path
print("core import/build pin PASS")
"""
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-B", "-c", code],
        cwd="/tmp",
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "core import/build pin PASS" in result.stdout


def main() -> int:
    test_arm_order_is_frozen()
    test_simple_prediction_canonicalizes_and_drops_singletons()
    test_clip_prediction_reports_out_of_mask_members()
    test_write_json_once_is_idempotent_and_refuses_drift()
    test_default_paths_follow_frozen_output_templates()
    test_observe_imports_core_from_outside_repo_without_pythonpath()
    print("novel-source orchestration PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
