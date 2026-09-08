"""Prepare and hash GT-blind relation-control candidate artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from relation_control import (
    BODY2_VIEWS,
    load_bodies,
    make_control_artifact,
    pair_from_record,
    select_control_pairs,
    strata_counts,
    stratum_label,
)


HERE = Path(__file__).resolve().parent
DEFAULT_REFERENCE = HERE.parent / "followup-2026-09-08"


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json_once(path: Path, value: Any) -> str:
    encoded = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    if path.exists():
        if sha256_file(path) != digest:
            raise ValueError(f"refusing to overwrite retained output: {path}")
        return digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8")
    return digest


def _source_record(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _reference_inputs(reference: Path) -> dict[str, Any]:
    return read_json(reference / "inputs.json")


def _case_body_path(reference_inputs: Mapping[str, Any], case: str) -> Path:
    root = Path(reference_inputs["input_root"])
    return root / reference_inputs["cases"][case]["body"]["path"]


def _validate_candidate_source(
    *,
    case: str,
    artifact: Mapping[str, Any],
    artifact_path: Path,
    reference_inputs: Mapping[str, Any],
    reference: Path,
    method: str,
    expected_sha256: str,
) -> None:
    pinned = reference_inputs["cases"][case]
    provenance = artifact.get("provenance", {})
    if provenance.get("body_evidence_sha256") != pinned["body"]["sha256"]:
        raise ValueError(f"{case}/{method}: body provenance differs from pinned input")
    if provenance.get("fixture_sha256") != pinned["fixture"]["sha256"]:
        raise ValueError(f"{case}/{method}: fixture provenance differs from pinned input")
    for key in (
        "raw_graph_sha256",
        "stripped_sha256",
        "candidate_selection_sha256",
    ):
        if key not in provenance:
            raise ValueError(f"{case}/{method}: candidate provenance lacks {key}")
    metadata_path = reference / "runs" / case / f"{method}-k16" / "metadata.json"
    if not metadata_path.is_file():
        raise ValueError(f"{case}/{method}: retained metadata is missing")
    actual_sha256 = sha256_file(artifact_path)
    if actual_sha256 != expected_sha256:
        raise ValueError(f"{case}/{method}: candidate hash differs from frozen config")
    metadata = read_json(metadata_path)
    expected_sha = metadata.get("candidate_sha256")
    if expected_sha and expected_sha != actual_sha256:
        raise ValueError(f"{case}/{method}: candidate hash differs from metadata")


def _selection_json(
    selection: Mapping[str, Any],
    *,
    source_pool_sha256: str | None = None,
    treatment_sha256: str | None = None,
    arm: str | None = None,
) -> dict[str, Any]:
    result = {
        "seed": selection["seed"],
        "seed_or_body_score_rule": (
            "body-score:min(token,cfg),mean,IDs"
            if arm == "B2-body-score"
            else "sha256"
        ),
        "quotas": {
            stratum_label(key): int(value)
            for key, value in sorted(
                selection["quotas"].items(),
                key=lambda item: stratum_label(item[0]),
            )
        },
        "random_stats": selection["random_stats"],
        "body_score_stats": selection["body_score_stats"],
        "random_pairs": [
            list(pair_from_record(record).to_list())
            for record in selection["random"]
        ],
        "body_score_pairs": [
            list(pair_from_record(record).to_list())
            for record in selection["body-score"]
        ],
    }
    if source_pool_sha256 is not None:
        result["source_pool_sha256"] = source_pool_sha256
    if treatment_sha256 is not None:
        result["treatment_sha256"] = treatment_sha256
    if arm is not None:
        result["arm"] = arm
    return result


def prepare(
    *,
    reference: Path = DEFAULT_REFERENCE,
    output: Path = HERE,
) -> dict[str, Any]:
    config = read_json(output / "config.json")
    reference_config = read_json(reference / "config.json")
    reference_inputs = _reference_inputs(reference)
    if tuple(config["cases"]) != tuple(reference_config["cases"]):
        raise ValueError("control and reference case sets differ")
    if tuple(config["seeds"]) != tuple(
        f"relation-control-2026-09-08/{index}" for index in range(5)
    ):
        raise ValueError("control seed list is not frozen")
    reference_protocol_sha = sha256_file(reference / "protocol.md")
    expected_reference_protocol = reference_config.get("protocol_sha256")
    if expected_reference_protocol and reference_protocol_sha != expected_reference_protocol:
        raise ValueError("reference protocol hash differs from pinned config")
    pinned_reference_protocol = config.get("reference_protocol_sha256")
    if pinned_reference_protocol and reference_protocol_sha != pinned_reference_protocol:
        raise ValueError("reference protocol hash differs from control config")
    expected_protocol = config.get("protocol_sha256")
    if expected_protocol and expected_protocol != sha256_file(output / "protocol.md"):
        raise ValueError("control protocol hash differs from pinned config")
    controls_config = config["arms"]["controls"]
    expected_arms = ("B2-body-score",) + tuple(f"random-{index}" for index in range(5))
    if set(controls_config) != set(expected_arms):
        raise ValueError("control arm list is not frozen")
    source_snapshot = {
        "reference_config": _source_record(reference / "config.json"),
        "reference_inputs": _source_record(reference / "inputs.json"),
        "reference_protocol": _source_record(reference / "protocol.md"),
    }
    selections: dict[str, Any] = {}
    controls: dict[str, dict[str, str]] = {}
    for case in config["cases"]:
        body_path = _case_body_path(reference_inputs, case)
        body2_path = reference / "cache" / case / "body2-k16.candidates.json"
        treatment_path = reference / "cache" / case / "combined3-k16.candidates.json"
        for path in (body_path, body2_path, treatment_path):
            if not path.is_file():
                raise ValueError(f"required source artifact is missing: {path}")
        bodies = load_bodies(body_path)
        body2 = read_json(body2_path)
        treatment = read_json(treatment_path)
        if sha256_file(body_path) != reference_inputs["cases"][case]["body"]["sha256"]:
            raise ValueError(f"{case}: body hash differs from pinned input")
        _validate_candidate_source(
            case=case,
            artifact=body2,
            artifact_path=body2_path,
            reference_inputs=reference_inputs,
            reference=reference,
            method="body2",
            expected_sha256=config["candidate_sha256"][case]["body2"],
        )
        _validate_candidate_source(
            case=case,
            artifact=treatment,
            artifact_path=treatment_path,
            reference_inputs=reference_inputs,
            reference=reference,
            method="combined3",
            expected_sha256=config["candidate_sha256"][case]["c3"],
        )
        common_keys = set(body2["provenance"]) | set(treatment["provenance"])
        common_keys.discard("candidate_derivation")
        for key in sorted(common_keys):
            if body2["provenance"].get(key) != treatment["provenance"].get(key):
                raise ValueError(f"{case}: body2/C3 provenance differs at {key}")
        if tuple(body2["config"].get("views", ())) != BODY2_VIEWS:
            raise ValueError(f"{case}: body2 is not the named token+CFG artifact")
        source_snapshot.setdefault("cases", {})[case] = {
            "body": _source_record(body_path),
            "body2_candidates": _source_record(body2_path),
            "combined3_candidates": _source_record(treatment_path),
        }
        case_selections = []
        case_controls: dict[str, str] = {}
        for seed_index, seed in enumerate(config["seeds"]):
            selection = select_control_pairs(
                body2,
                treatment,
                bodies,
                seed=seed,
            )
            arm = f"random-{seed_index}"
            stats = selection["random_stats"]
            artifact = make_control_artifact(
                body2,
                selection["random"],
                arm,
                {
                    "case": case,
                    "seed": seed,
                    "selection": stats,
                    "body2_source_sha256": sha256_file(body2_path),
                    "treatment_source_sha256": sha256_file(treatment_path),
                },
            )
            path = output / "candidates" / case / f"{arm}.candidates.json"
            case_controls[arm] = write_json_once(path, artifact)
            case_selections.append(
                _selection_json(
                    selection,
                    source_pool_sha256=sha256_file(body2_path),
                    treatment_sha256=sha256_file(treatment_path),
                    arm=arm,
                )
            )
        score_selection = select_control_pairs(
            body2,
            treatment,
            bodies,
            seed=config["seeds"][0],
        )
        score_arm = "B2-body-score"
        score_artifact = make_control_artifact(
            body2,
            score_selection["body-score"],
            score_arm,
            {
                "case": case,
                "selection": score_selection["body_score_stats"],
                "body2_source_sha256": sha256_file(body2_path),
                "treatment_source_sha256": sha256_file(treatment_path),
            },
        )
        score_path = output / "candidates" / case / "B2-body-score.candidates.json"
        case_controls[score_arm] = write_json_once(score_path, score_artifact)
        selections[case] = {
            "treatment_candidate_count": len(treatment["pairs"]),
            "body2_candidate_count": len(body2["pairs"]),
            "strata": {
                stratum_label(key): count
                for key, count in sorted(
                    strata_counts(treatment["pairs"], bodies).items(),
                    key=lambda item: stratum_label(item[0]),
                )
            },
            "random": case_selections,
            "body_score": _selection_json(
                score_selection,
                source_pool_sha256=sha256_file(body2_path),
                treatment_sha256=sha256_file(treatment_path),
                arm=score_arm,
            ),
            "selection_frozen_before_f4_cache": True,
            "gt_used_for_selection": False,
            "relation_flags_used_for_selection": False,
            "source_pool_sha256": sha256_file(body2_path),
            "treatment_sha256": sha256_file(treatment_path),
            "controls": case_controls,
        }
        controls[case] = case_controls
        selection_path = output / "selection" / f"{case}.json"
        write_json_once(selection_path, selections[case])
    implementation_names = (
        "relation_control.py",
        "prepare_relation_control.py",
        "run_relation_control.py",
    )
    if any(not (output / name).is_file() for name in implementation_names):
        raise ValueError("implementation files must exist before snapshot freeze")
    snapshot = {
        "study": config["study"],
        "status": "controls-hashed",
        "config_sha256": sha256_file(output / "config.json"),
        "protocol_sha256": sha256_file(output / "protocol.md"),
        "base_commit": config["base_commit"],
        "reference": source_snapshot,
        "selection_sha256": {
            case: sha256_file(output / "selection" / f"{case}.json")
            for case in selections
        },
        "controls": controls,
        "implementation": {
            name: _source_record(output / name)
            for name in implementation_names
        },
    }
    write_json_once(output / "snapshot.json", snapshot)
    return snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument("--output", type=Path, default=HERE)
    args = parser.parse_args()
    result = prepare(reference=args.reference, output=args.output)
    print(
        json.dumps(
            {"status": result["status"], "cases": sorted(result["controls"])},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
