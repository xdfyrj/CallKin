"""Bundle retained relation-control predictions for standalone rescore checks.

The bundle contains no body observations, candidate caches, disassembly, or
source checkout.  It is a retained-prediction rescore package, not a fresh
prediction or human/full-source reproduction.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REFERENCE = HERE.parent / "followup-2026-09-08"
TERMINAL = {"completed", "budget-refused", "resource-incomplete"}
METRICS = ("TP", "FP", "FN", "TN", "precision", "recall", "f1")


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def source_bytes(path: Path, expected: str | None = None) -> bytes:
    data = path.read_bytes()
    actual = sha(data)
    if expected and actual != expected:
        raise ValueError(f"hash mismatch: {path}")
    return data


def label_paths(config, inputs, case, role, base=HERE):
    spec = config["labels"][role][case]
    if spec.get("same_as_primary"):
        return label_paths(config, inputs, case, "primary", base)
    result = {}
    for name in ("ground_truth", "linkage"):
        direct = spec.get(name)
        if direct is not None:
            path = (base / str(direct)).resolve()
            expected = spec.get(name + "_sha256")
        else:
            source = spec[name + "_from_source_manifest"]
            path = (Path(inputs["input_root"]) / source).resolve()
            expected = inputs["cases"][case][name]["sha256"]
        data = source_bytes(path, expected)
        result[name] = {
            "path": path,
            "sha256": sha(data),
            "expected_sha256": expected,
            "bytes": len(data),
        }
    return result


def build(output: Path = HERE, reference: Path = REFERENCE, include_selection: bool = False):
    output, reference = Path(output), Path(reference)
    config_path, protocol_path, snapshot_path = output / "config.json", output / "protocol.md", output / "snapshot.json"
    config, snapshot = read(config_path), read(snapshot_path)
    if snapshot.get("status") != "controls-hashed":
        raise ValueError("snapshot is not a frozen control snapshot")
    if snapshot.get("config_sha256") != sha(source_bytes(config_path)) or snapshot.get("protocol_sha256") != sha(source_bytes(protocol_path)):
        raise ValueError("snapshot/config/protocol identity mismatch")
    inputs = read(reference / "inputs.json")
    arms = (config["arms"]["treatment"], *config["arms"]["controls"])
    files: dict[str, bytes] = {}

    def add(name, data):
        if name in files and files[name] != data:
            raise ValueError(f"bundle path collision: {name}")
        files[name] = data
    for name in ("config.json", "protocol.md", "snapshot.json"):
        add(name, source_bytes(output / name))
    add("reference-inputs.json", source_bytes(reference / "inputs.json", snapshot["reference"]["reference_inputs"]["sha256"]))
    add("results-summary.csv", source_bytes(output / "results-summary.csv"))
    add("source-corrected-sensitivity.json", source_bytes(output / "source-corrected-sensitivity.json"))
    for name in ("random5-summary.json", "primary-deltas.json"):
        if (output / name).is_file():
            add(name, source_bytes(output / name))
    add("README.md", source_bytes(output / "verification" / "README.md"))
    add("verification/recheck.py", source_bytes(output / "verification" / "recheck.py"))
    add("linkage_overlay.py", source_bytes(ROOT / "linkage_overlay.py"))
    add("LICENSE", source_bytes(ROOT / "LICENSE"))

    labels = {}
    for case in config["cases"]:
        labels[case] = {}
        for role, package_role in (("primary", "primary"), ("secondary_original", "original")):
            paths = label_paths(config, inputs, case, role, output)
            labels[case][package_role] = {}
            for name, record in paths.items():
                package_name = f"labels/{package_role}/{case}/{name}.json"
                add(package_name, source_bytes(Path(record["path"]), record["sha256"]))
                labels[case][package_role][name] = {
                    "path": package_name,
                    "sha256": record["sha256"],
                    "expected_sha256": record["expected_sha256"],
                    "bytes": record["bytes"],
                }
    add("labels-manifest.json", encoded(labels))

    expected = []
    for case in config["cases"]:
        for arm in arms:
            directory = output / "runs" / case / arm
            metadata_path, prediction_path = directory / "metadata.json", directory / "prediction.json"
            metadata = read(metadata_path)
            status = metadata.get("status")
            if status not in TERMINAL or metadata.get("case") != case or metadata.get("arm") != arm:
                raise ValueError(f"arm is not terminal or identity is wrong: {case}/{arm}")
            expected_candidate = (
                snapshot["reference"]["cases"][case]["combined3_candidates"]["sha256"]
                if arm == config["arms"]["treatment"]
                else snapshot["controls"][case][arm]
            )
            expected_identity = {
                "body_evidence_sha256": snapshot["reference"]["cases"][case]["body"]["sha256"],
                "candidate_sha256": expected_candidate,
                "config_sha256": sha(source_bytes(config_path)),
                "protocol_sha256": sha(source_bytes(protocol_path)),
                "base_commit": config["base_commit"],
            }
            if any(metadata.get(key) != value for key, value in expected_identity.items()):
                raise ValueError(f"arm metadata identity mismatch: {case}/{arm}")
            expected_impl = {name: record["sha256"] for name, record in snapshot.get("implementation", {}).items()}
            if metadata.get("implementation_sha256") != expected_impl:
                raise ValueError(f"arm implementation identity mismatch: {case}/{arm}")
            if config.get("runtime", {}).get("python") and metadata.get("python") != config["runtime"]["python"]:
                raise ValueError(f"arm Python identity mismatch: {case}/{arm}")
            add(f"runs/{case}/{arm}/metadata.json", source_bytes(metadata_path))
            row = {"case": case, "arm": arm, "status": status, "metadata_sha256": sha(files[f"runs/{case}/{arm}/metadata.json"]), "prediction_sha256": metadata.get("prediction_sha256"), "primary": None, "original": None}
            if status == "completed":
                if not metadata.get("prediction_sha256"):
                    raise ValueError(f"completed prediction hash is missing: {case}/{arm}")
                data = source_bytes(prediction_path, metadata.get("prediction_sha256"))
                add(f"runs/{case}/{arm}/prediction.json", data)
                evaluation_path = directory / "evaluation.json"
                evaluation = read(evaluation_path)
                if evaluation.get("status") != status or not isinstance(evaluation.get("metrics"), dict) or not isinstance(evaluation.get("secondary_metrics"), dict):
                    raise ValueError(f"completed evaluation is missing quality: {case}/{arm}")
                row["primary"] = {key: evaluation["metrics"].get(key) for key in METRICS}
                row["original"] = {key: evaluation["secondary_metrics"].get(key) for key in METRICS}
            elif prediction_path.exists():
                raise ValueError(f"noncompleted arm has a prediction: {case}/{arm}")
            expected.append(row)
    add("expected-results.json", encoded(expected))
    if include_selection:
        for path in sorted((output / "selection").glob("*.json.gz")):
            add(f"selection/{path.name}", source_bytes(path))
    manifest = {name: sha(data) for name, data in sorted(files.items())}
    add("manifest.json", encoded(manifest))
    destination = output / "verification-bundle.zip"
    if destination.exists():
        raise ValueError(f"refusing to overwrite existing bundle: {destination}")
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return {"path": str(destination), "files": len(files), "rows": len(expected)}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE)
    parser.add_argument("--reference", type=Path, default=REFERENCE)
    parser.add_argument("--include-selection", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.reference, args.include_selection), indent=2))
