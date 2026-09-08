"""Small shared guards for the prospective novel-source study.

The module only handles deterministic file identity and study-local paths.  It
does not import the CallKin extraction or inference stack, which keeps the
Sage observation process separate from the Python 3.12 inference process.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DEFAULT_CASES = ("hexyl-v0170", "hyperfine-v1200", "tokei-v1500")
DEFAULT_BUILD = "O3S"
DEFAULT_PROFILE = "plain"
DEFAULT_TRACK = "angr"
DEFAULT_ANCHOR_POLICY = "role"
DEFAULT_SCOPE = "rust-nonstd"
DEFAULT_MODE = "out-in"
DEFAULT_K = 16


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_once(path: str | Path, value: Any) -> str:
    """Write canonical JSON once; equal retained output is reusable."""

    destination = Path(path)
    encoded = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    if destination.exists():
        if destination.read_bytes() != encoded:
            raise ValueError(f"refusing to overwrite retained output: {destination}")
        return digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoded)
    return digest


def write_text_once(path: str | Path, text: str) -> str:
    destination = Path(path)
    encoded = text.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    if destination.exists():
        if destination.read_bytes() != encoded:
            raise ValueError(f"refusing to overwrite retained output: {destination}")
        return digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoded)
    return digest


def source_record(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    return {"path": str(target), "sha256": sha256_file(target), "bytes": target.stat().st_size}


def config_cases(config: Mapping[str, Any]) -> tuple[str, ...]:
    cases = config.get("cases")
    if not isinstance(cases, list):
        raise ValueError("config.cases must be a list")
    names = tuple(str(case) for case in cases)
    if not names or len(set(names)) != len(names):
        raise ValueError("config.cases must contain unique case names")
    return names


def case_config(config: Mapping[str, Any], case: str) -> Mapping[str, Any]:
    sources = config.get("sources")
    if not isinstance(sources, list):
        raise ValueError("config.sources must be a list")
    matches = [item for item in sources if isinstance(item, Mapping) and item.get("id") == case]
    if len(matches) != 1:
        raise ValueError(f"config.sources must contain exactly one entry for {case!r}")
    return matches[0]


def case_identity(config: Mapping[str, Any], case: str) -> dict[str, Any]:
    if case not in config_cases(config):
        raise ValueError(f"case is outside frozen config: {case}")
    build_config = config.get("build")
    if not isinstance(build_config, Mapping):
        raise ValueError("config.build must be an object")
    build = str(build_config.get("build", DEFAULT_BUILD))
    profile = str(build_config.get("profile", DEFAULT_PROFILE))
    return {
        "case": case,
        "build": build,
        "profile": profile,
        "track": str(config.get("track", DEFAULT_TRACK)),
        "anchor_policy": str(config.get("anchor_policy", DEFAULT_ANCHOR_POLICY)),
        "candidate_scope": str(config.get("candidate_scope", DEFAULT_SCOPE)),
        "mode": str(config.get("mode", DEFAULT_MODE)),
        "k": int(config.get("k", DEFAULT_K)),
    }


def resolve_study_path(value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    # Paths in this study's config are relative to the study directory.
    return (HERE / path).resolve()


def case_paths(config: Mapping[str, Any], case: str) -> dict[str, Path]:
    identity = case_identity(config, case)
    build = identity["build"]
    stem = f"{case}.{build}"
    source = case_config(config, case)
    prebuilt = source.get("prebuilt")
    manifest_value = (
        prebuilt.get("manifest")
        if isinstance(prebuilt, Mapping) and prebuilt.get("manifest")
        else f"build/{case}/{case}.{build}.build.json"
    )
    outputs = config.get("outputs")
    if not isinstance(outputs, Mapping):
        raise ValueError("config.outputs must be an object")

    def template(name: str, **values: str) -> Path:
        value = outputs.get(name)
        if not isinstance(value, str):
            raise ValueError(f"config.outputs.{name} must be a string")
        rendered = value.replace("<case>", case).replace("<build>", build)
        for key, replacement in values.items():
            rendered = rendered.replace(f"<{key}>", replacement)
        return resolve_study_path(rendered)

    observation_dir = template("observation")
    candidates_template = template("candidates", arm="__arm__")
    predictions_template = template("predictions", arm="__arm__")
    scores_template = template(
        "scores", arm="__arm__", **{"label-view": "__label__"}
    )
    candidates_dir = candidates_template.parent
    prediction_dir = predictions_template.parent.parent
    score_dir = scores_template.parent.parent
    defaults = {
        "build_manifest": resolve_study_path(manifest_value),
        "ground_truth": observation_dir / f"{stem}.gt.json",
        "users": observation_dir / f"{stem}.users.json",
        "boundaries": observation_dir / f"{stem}.boundaries.json",
        "fixture": observation_dir / f"{stem}.fixture.json",
        "raw_graph": observation_dir / f"{stem}.raw.json",
        "body": observation_dir / f"{stem}.body.json",
        "linkage": observation_dir / f"{stem}.linkage.json",
        "observation_metadata": observation_dir / "metadata.json",
        "multi_candidates": candidates_dir / f"{stem}.multi.k{identity['k']}.json",
        "body2_candidates": candidates_dir / "B2-token-cfg.candidates.json",
        "c3_candidates": candidates_dir / "C3-token-cfg-relation.candidates.json",
        "rescue_candidates": candidates_dir / "C3-rescue-input.candidates.json",
        "body_score_candidates": candidates_dir / "B2-body-score.candidates.json",
        "candidate_metadata": candidates_dir / "metadata.json",
        "prediction_dir": prediction_dir,
        "score_dir": score_dir,
    }
    return defaults


def implementation_paths() -> dict[str, Path]:
    return {
        "observe": HERE / "observe_novel_source.py",
        "infer": HERE / "infer_novel_source.py",
        "common": HERE / "novel_common.py",
        "derive_helper": REPO_ROOT / "experiments" / "followup-2026-09-08" / "run_followup.py",
        "selector_helper": REPO_ROOT / "experiments" / "relation-control-2026-09-08" / "relation_control.py",
    }


def implementation_hashes(*, include: tuple[str, ...] | None = None) -> dict[str, str]:
    paths = implementation_paths()
    names = include or tuple(paths)
    result = {}
    for name in names:
        path = paths[name]
        if not path.is_file():
            raise ValueError(f"implementation file is missing: {path}")
        result[name] = sha256_file(path)
    return result


def core_base_commit(config: Mapping[str, Any]) -> str:
    reference = config.get("reference")
    if not isinstance(reference, Mapping):
        raise ValueError("config.reference must be an object")
    value = reference.get("core_base_commit")
    if not isinstance(value, str) or not value:
        raise ValueError("config.reference.core_base_commit is required")
    return value


def runtime_config(config: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    runtime = config.get("runtime")
    if not isinstance(runtime, Mapping):
        raise ValueError("config.runtime must be an object")
    value = runtime.get(kind)
    if not isinstance(value, Mapping):
        raise ValueError(f"config.runtime.{kind} must be an object")
    return value


def frozen_implementation_hashes(config: Mapping[str, Any]) -> Mapping[str, str]:
    """Read the implementation pin that Root freezes before execution."""

    manifest_value = config.get("hash_manifest")
    if not isinstance(manifest_value, str) or not manifest_value:
        raise ValueError("config.hash_manifest is required")
    manifest = read_json(resolve_study_path(manifest_value))
    value = manifest.get("implementation_sha256") if isinstance(manifest, Mapping) else None
    if not isinstance(value, Mapping) or not value:
        raise ValueError("hash manifest implementation_sha256 is not frozen")
    result = {}
    for name, digest in value.items():
        if not isinstance(name, str) or not isinstance(digest, str):
            raise ValueError("hash manifest implementation_sha256 is invalid")
        result[name] = digest
    return result


def ensure_no_partial_outputs(paths: Mapping[str, Path], metadata: Path) -> None:
    if metadata.exists():
        return
    existing = [path for path in paths.values() if path.is_file()]
    if existing:
        joined = ", ".join(str(path) for path in existing)
        raise ValueError(f"partial retained output exists; refusing resume: {joined}")


def verify_output_hashes(records: Mapping[str, Any]) -> None:
    for name, record in records.items():
        if not isinstance(record, Mapping) or not isinstance(record.get("path"), str):
            raise ValueError(f"output hash record is invalid: {name}")
        path = Path(record["path"])
        if not path.is_file() or sha256_file(path) != record.get("sha256"):
            raise ValueError(f"retained output hash mismatch: {name}: {path}")


__all__ = [
    "DEFAULT_ANCHOR_POLICY",
    "DEFAULT_BUILD",
    "DEFAULT_CASES",
    "DEFAULT_K",
    "DEFAULT_MODE",
    "DEFAULT_PROFILE",
    "DEFAULT_SCOPE",
    "DEFAULT_TRACK",
    "HERE",
    "REPO_ROOT",
    "case_config",
    "case_identity",
    "case_paths",
    "config_cases",
    "core_base_commit",
    "frozen_implementation_hashes",
    "ensure_no_partial_outputs",
    "implementation_hashes",
    "implementation_paths",
    "read_json",
    "runtime_config",
    "sha256_file",
    "source_record",
    "verify_output_hashes",
    "write_json_once",
    "write_text_once",
]
