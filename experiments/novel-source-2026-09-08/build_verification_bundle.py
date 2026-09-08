"""Build a bounded retained-output rescore bundle.

The package contains frozen labels, predictions, metadata, scores, and a
standalone checker. It deliberately omits bodies, candidates, builds, and
source trees, so it is a retained-output verification package rather than a
fresh inference reproduction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CASES = ("hexyl-v0170", "hyperfine-v1200", "tokei-v1500")
ARMS = (
    "V0-relation",
    "exact-token-hash",
    "B2-token-cfg",
    "C3-token-cfg-relation",
    "B2-body-score",
    "C3-rescue",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def encoded(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def add(files: dict[str, bytes], name: str, data: bytes) -> None:
    if name in files and files[name] != data:
        raise ValueError(f"bundle path collision: {name}")
    files[name] = data


def source(files: dict[str, bytes], name: str, path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"required retained input is missing: {path}")
    add(files, name, path.read_bytes())


def label_paths(config: dict[str, Any], case: str) -> tuple[Path, Path]:
    build = config.get("build", {})
    build_name = build.get("build", "O3S") if isinstance(build, dict) else str(build)
    defaults = (
        HERE / "observations" / case / f"{case}.{build_name}.gt.json",
        HERE / "observations" / case / f"{case}.{build_name}.linkage.json",
    )
    primary = config.get("labels", {}).get("primary", {})
    if not isinstance(primary, dict):
        return defaults
    paths = []
    for key, fallback in zip(("ground_truth", "linkage"), defaults):
        value = primary.get(key)
        if not isinstance(value, str):
            paths.append(fallback)
            continue
        value = value.replace("<case>", case).replace("<build>", str(build_name))
        path = Path(value)
        paths.append(path if path.is_absolute() else HERE / path)
    return paths[0], paths[1]


def verify_freeze(config: dict[str, Any], manifest: dict[str, Any]) -> None:
    if str(config.get("status", "")).upper() not in {"FROZEN", "FROZEN-DESIGN", "APPROVED"}:
        raise ValueError("novel config is not frozen")
    protocol = HERE / str(config.get("protocol", "protocol.md"))
    if not protocol.is_file() or config.get("protocol_sha256") != sha(protocol.read_bytes()):
        raise ValueError("novel protocol hash does not match config")
    if manifest.get("protocol_sha256") not in (None, sha(protocol.read_bytes())):
        raise ValueError("hash manifest protocol hash mismatch")
    expected_config = manifest.get("config_sha256")
    if expected_config and expected_config != sha((HERE / "config.json").read_bytes()):
        raise ValueError("hash manifest config hash mismatch")
    if tuple(config.get("cases", ())) != CASES:
        raise ValueError("novel case order is not the frozen three-case order")


def build(*, output: Path = HERE / "verification-bundle.zip", staging: Path = HERE / "verification-bundle") -> dict[str, Any]:
    config_path = HERE / "config.json"
    hash_manifest_path = HERE / "hash-manifest.json"
    config, hash_manifest = read(config_path), read(hash_manifest_path)
    verify_freeze(config, hash_manifest)
    files: dict[str, bytes] = {}

    for name, path in (
        ("study/config.json", config_path),
        ("study/protocol.md", HERE / "protocol.md"),
        ("study/hash-manifest.json", hash_manifest_path),
        ("study/exposed-origins.json", HERE / "exposed-origins.json"),
        ("study/evaluator.py", HERE / "score_novel_source.py"),
        ("README.md", HERE / "verification-bundle-README.md"),
        ("verify_retained_bundle.py", HERE / "verify_retained_bundle.py"),
        ("linkage_overlay.py", REPO / "linkage_overlay.py"),
        ("LICENSE", REPO / "LICENSE"),
    ):
        source(files, name, path)

    for case in CASES:
        gt_path, linkage_path = label_paths(config, case)
        source(files, f"labels/{case}/ground_truth.json", gt_path)
        source(files, f"labels/{case}/linkage.json", linkage_path)
        for arm in ARMS:
            directory = HERE / "predictions" / case / arm
            metadata_path, prediction_path = directory / "metadata.json", directory / "prediction.json"
            metadata = read(metadata_path)
            if metadata.get("status") != "completed":
                raise ValueError(f"bundle expects completed arm: {case}/{arm}")
            if metadata.get("prediction_sha256") != sha(prediction_path.read_bytes()):
                raise ValueError(f"prediction hash mismatch: {case}/{arm}")
            source(files, f"predictions/{case}/{arm}/metadata.json", metadata_path)
            source(files, f"predictions/{case}/{arm}/prediction.json", prediction_path)
        source(files, f"scores/{case}/scores.json", HERE / "scores" / case / "scores.json")
        source(files, f"scores/{case}/summary.csv", HERE / "scores" / case / "summary.csv")

    # Real is a separate condition. Keep compact reports/evaluations/hashes,
    # while omitting raw stdout/stderr, scripts, resource dumps, and binaries.
    for name in (
        "real-config.json",
        "real-environment-lock.txt",
        "real-freeze-hashes.json",
        "real-preflight.md",
        "real-protocol.md",
    ):
        source(files, f"real/{name}", HERE / name)
    real_dir = HERE / "real" / "hexyl-v0170"
    for name in (
        "evaluation.json",
        "real-run-report.md",
        "real-run-validation.json",
        "real-run-supplementary.json",
        "real-run-output-hashes.txt",
        "real-run-postrun-hashes.txt",
        "real-run-invocation.txt",
        "real-run.status.txt",
        "real-score.status.txt",
    ):
        source(files, f"real/hexyl-v0170/{name}", real_dir / name)

    summary = {
        "artifact": "callkin-novel-source-retained-rescore",
        "schema_version": 1,
        "kind": "retained-output-rescoring",
        "cases": list(CASES),
        "arms": list(ARMS),
        "prediction_count": len(CASES) * len(ARMS),
        "quality_view_count": len(CASES) * len(ARMS) * 3,
        "scoring_python": "3.12.3",
        "evaluator_sha256": sha(files["study/evaluator.py"]),
        "includes": ["original GT/linkage", "pinned exposure labels", "retained predictions and metadata", "retained score JSON/CSV", "standalone arithmetic checker"],
        "excludes": ["body evidence", "candidate caches", "build artifacts", "source checkouts", "raw inference logs"],
        "limitations": ["candidate SHA pins are checked against retained metadata but candidate files are omitted", "the package verifies retained predictions and score arithmetic; it does not rebuild observations or rerun inference", "Real artifacts cover the separately frozen hexyl Real condition; no Real output is asserted for hyperfine or tokei"],
    }
    add(files, "bundle-summary.json", encoded(summary))
    member_hashes = {name: sha(data) for name, data in sorted(files.items())}
    manifest = {**summary, "members": member_hashes, "member_count": len(member_hashes), "uncompressed_bytes": sum(len(data) for data in files.values())}
    add(files, "manifest.json", encoded(manifest))

    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.json").write_bytes(files["manifest.json"])
    external_manifest = HERE / "verification-bundle-manifest.json"
    external_manifest.write_bytes(files["manifest.json"])
    if output.exists():
        raise ValueError(f"refusing to overwrite existing bundle: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return {"path": str(output), "manifest": str(external_manifest), "files": len(files), "bytes": output.stat().st_size, "uncompressed_bytes": manifest["uncompressed_bytes"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "verification-bundle.zip")
    parser.add_argument("--staging", type=Path, default=HERE / "verification-bundle")
    args = parser.parse_args()
    print(json.dumps(build(output=args.output, staging=args.staging), indent=2))
