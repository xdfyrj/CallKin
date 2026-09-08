"""Score retained novel-source predictions after the inference freeze."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import io
import json
import platform
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from novel_common import (  # noqa: E402
    HERE,
    REPO_ROOT,
    case_config,
    case_identity,
    case_paths,
    config_cases,
    core_base_commit,
    frozen_implementation_hashes,
    implementation_hashes,
    read_json,
    runtime_config,
    sha256_file,
    source_record,
    verify_output_hashes,
    write_json_once,
)


ARM_V0 = "V0-relation"
ARM_EXACT = "exact-token-hash"
ARM_B2 = "B2-token-cfg"
ARM_C3 = "C3-token-cfg-relation"
ARM_BODY_SCORE = "B2-body-score"
ARM_RESCUE = "C3-rescue"
ARMS = (ARM_V0, ARM_EXACT, ARM_B2, ARM_C3, ARM_BODY_SCORE, ARM_RESCUE)
F6_CANDIDATE_KEYS = {
    ARM_B2: "body2",
    ARM_C3: "c3",
    ARM_BODY_SCORE: "body_score",
    ARM_RESCUE: "rescue",
}
TERMINAL = {
    "completed",
    "budget-refused",
    "resource-incomplete",
    "dependency-unavailable",
    # Kept while older retained inference metadata is migrated to the frozen
    # dependency-unavailable spelling.
    "blocked-prerequisite",
}

# Only the two pure label functions are reused.  Importing this module defines
# helpers but does not call the old runner's environment verifier.
_OLD_STUDY = REPO_ROOT / "experiments" / "followup-2026-09-08"
for _path in (REPO_ROOT, _OLD_STUDY):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))
from score_followup import metrics, truth_index  # noqa: E402


def _write_text_once(path: Path, text: str) -> str:
    encoded = text.encode("utf-8")
    if path.exists() and path.read_bytes() != encoded:
        raise ValueError(f"refusing to overwrite retained output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def _config_path() -> Path:
    return HERE / "config.json"


def _protocol_path() -> Path:
    return HERE / "protocol.md"


def _load_frozen_config() -> dict[str, Any]:
    config = read_json(_config_path())
    if not isinstance(config, dict):
        raise ValueError("config root must be an object")
    protocol_sha = sha256_file(_protocol_path())
    if config.get("protocol_sha256") != protocol_sha:
        raise ValueError("protocol hash is not frozen in config; refusing scoring")
    if str(config.get("status", "")).upper() not in {"FROZEN", "FROZEN-DESIGN", "APPROVED"}:
        raise ValueError("config status is not frozen; refusing scoring")
    return config


def _verify_core(config: Mapping[str, Any]) -> None:
    base = core_base_commit(config)
    if subprocess.run(
        ["git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor", base, "HEAD"],
        check=False,
    ).returncode:
        raise ValueError(f"frozen core commit is not an ancestor: {base}")
    prefix = HERE.relative_to(REPO_ROOT).as_posix().rstrip("/") + "/"
    changed = [
        path
        for path in subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "diff", "--name-only", base, "--"],
            text=True,
        ).splitlines()
        if path and not path.startswith(prefix)
    ]
    if changed:
        raise ValueError("tracked core files differ from frozen base: " + ", ".join(changed))


def _verify_runtime(config: Mapping[str, Any]) -> str:
    expected = runtime_config(config, "inference").get("python")
    actual = platform.python_version()
    if not isinstance(expected, str) or actual != expected:
        raise ValueError(f"scoring requires inference Python {expected!r}; running {actual!r}")
    return actual


def _observation_body(config: Mapping[str, Any], case: str) -> tuple[dict[str, Any], dict[str, Any]]:
    paths = case_paths(config, case)
    metadata = read_json(paths["observation_metadata"])
    if not isinstance(metadata, Mapping) or metadata.get("status") != "completed":
        raise ValueError(f"completed observation is required: {paths['observation_metadata']}")
    expected = {
        "case": case,
        **case_identity(config, case),
        "config_sha256": sha256_file(_config_path()),
        "protocol_sha256": sha256_file(_protocol_path()),
        "base_commit": core_base_commit(config),
        "implementation_sha256": dict(frozen_implementation_hashes(config)),
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"observation {case} {key} identity mismatch")
    outputs = metadata.get("outputs")
    if not isinstance(outputs, Mapping):
        raise ValueError("observation output manifest is missing")
    verify_output_hashes({name: outputs[name] for name in ("body", "fixture", "raw_graph")})
    body = read_json(paths["body"])
    body_record = outputs.get("body")
    if not isinstance(body_record, Mapping):
        raise ValueError("observation body provenance is missing")
    return dict(metadata), body


def _candidate_paths(paths: Mapping[str, Path]) -> dict[str, Path]:
    return {
        "body2": paths["body2_candidates"],
        "c3": paths["c3_candidates"],
        "rescue": paths["rescue_candidates"],
        "body_score": paths["body_score_candidates"],
    }


def _prediction_metadata(
    config: Mapping[str, Any],
    case: str,
    arm: str,
    candidate_sha: str | None,
) -> tuple[dict[str, Any], Path, Path]:
    paths = case_paths(config, case)
    destination = paths["prediction_dir"] / arm
    metadata_path = destination / "metadata.json"
    prediction_path = destination / "prediction.json"
    if not metadata_path.is_file():
        raise ValueError(f"prediction metadata is missing: {metadata_path}")
    metadata = read_json(metadata_path)
    if not isinstance(metadata, Mapping):
        raise ValueError(f"prediction metadata is invalid: {metadata_path}")
    expected = {
        "case": case,
        "arm": arm,
        "config_sha256": sha256_file(_config_path()),
        "protocol_sha256": sha256_file(_protocol_path()),
        "base_commit": core_base_commit(config),
        "implementation_sha256": dict(frozen_implementation_hashes(config)),
        "candidate_sha256": candidate_sha,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"prediction {case}/{arm} {key} identity mismatch")
    status = metadata.get("status")
    if status not in TERMINAL:
        raise ValueError(f"prediction {case}/{arm} is not terminal: {status!r}")
    if status == "completed":
        expected_prediction = metadata.get("prediction_sha256")
        if not prediction_path.is_file() or sha256_file(prediction_path) != expected_prediction:
            raise ValueError(f"prediction hash mismatch: {prediction_path}")
    elif prediction_path.exists():
        raise ValueError(f"non-completed prediction has an output: {prediction_path}")
    return dict(metadata), metadata_path, prediction_path


def _validate_prediction(
    prediction: Mapping[str, Any], config: Mapping[str, Any], case: str, arm: str,
    body_sha256: str | None, candidate_sha256: str | None = None,
) -> tuple[str, ...]:
    identity = case_identity(config, case)
    for key, expected in (("case", case), ("build", identity["build"]),
                          ("profile", identity["profile"]), ("scope", identity["candidate_scope"])):
        if prediction.get(key) != expected:
            raise ValueError(f"prediction {case}/{arm} {key} mismatch")
    if prediction.get("artifact") == "novel-source-prediction":
        if prediction.get("arm") != arm:
            raise ValueError(f"prediction {case}/{arm} arm mismatch")
    elif "arm" in prediction and prediction.get("arm") != arm:
        raise ValueError(f"prediction {case}/{arm} arm mismatch")
    target = _target_ids(prediction)
    if body_sha256:
        provenance = prediction.get("provenance", {})
        for record in (provenance, prediction):
            if isinstance(record, Mapping) and record.get("body_evidence_sha256") not in (None, body_sha256):
                raise ValueError(f"prediction {case}/{arm} body provenance mismatch")
        if candidate_sha256 and prediction.get("artifact") != "novel-source-prediction":
            if not isinstance(provenance, Mapping) or provenance.get("candidate_artifact_sha256") != candidate_sha256:
                raise ValueError(f"prediction {case}/{arm} candidate provenance mismatch")
    elif candidate_sha256:
        provenance = prediction.get("provenance", {})
        if isinstance(provenance, Mapping) and provenance.get("candidate_artifact_sha256") not in (None, candidate_sha256):
            raise ValueError(f"prediction {case}/{arm} candidate provenance mismatch")
    return target


def _label_pair_inputs(
    config: Mapping[str, Any],
    case: str,
    target_ids: Iterable[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    paths = case_paths(config, case)
    gt_path, linkage_path = paths["ground_truth"], paths["linkage"]
    labels = config.get("labels", {})
    primary = labels.get("primary", {}) if isinstance(labels, Mapping) else {}
    if isinstance(primary, Mapping):
        for name, fallback in (("ground_truth", gt_path), ("linkage", linkage_path)):
            value = primary.get(name)
            if isinstance(value, str):
                rendered = value.replace("<case>", case).replace("<build>", str(case_identity(config, case)["build"]))
                candidate = Path(rendered)
                if not candidate.is_absolute():
                    candidate = HERE / candidate
                if name == "ground_truth":
                    gt_path = candidate
                else:
                    linkage_path = candidate
        if primary.get("kind") not in (None, "original-symbol-normalization"):
            raise ValueError("primary label must use original symbol normalization")
        if any(token in str(primary.get(name, "")).lower() for name in ("ground_truth", "linkage") for token in ("audit-correction", "audit_correction", "corrected")):
            raise ValueError("primary labels cannot use audit corrections")
    expected_gt = primary.get("ground_truth_sha256") if isinstance(primary, Mapping) else None
    expected_linkage = primary.get("linkage_sha256") if isinstance(primary, Mapping) else None
    if expected_gt and sha256_file(gt_path) != expected_gt:
        raise ValueError("primary ground-truth hash mismatch")
    if expected_linkage and sha256_file(linkage_path) != expected_linkage:
        raise ValueError("primary linkage hash mismatch")
    gt = read_json(gt_path)
    linkage = read_json(linkage_path)
    if not isinstance(gt, Mapping) or not isinstance(linkage, Mapping):
        raise ValueError("primary labels must be JSON objects")
    for key, expected in (
        ("case", case),
        ("build", case_identity(config, case)["build"]),
        ("profile", case_identity(config, case)["profile"]),
    ):
        if gt.get(key) != expected or linkage.get(key) != expected:
            raise ValueError(f"primary label {key} mismatch for {case}")
    gt_provenance = gt.get("provenance")
    audit_provenance = linkage.get("provenance")
    if not isinstance(gt_provenance, Mapping) or not isinstance(audit_provenance, Mapping):
        raise ValueError("primary labels lack provenance")
    if audit_provenance.get("ground_truth_sha256") != sha256_file(gt_path):
        raise ValueError("linkage does not name the retained ground truth hash")
    if audit_provenance.get("non_stripped_sha256") != gt_provenance.get("non_stripped_sha256"):
        raise ValueError("linkage/non-stripped provenance mismatch")
    if "parent_ground_truth_sha256" in gt:
        raise ValueError("corrected GT cannot replace primary original GT")
    if target_ids is not None:
        _validate_label_universe(gt, linkage, target_ids)
    return dict(gt), dict(linkage), {
        "ground_truth": source_record(gt_path),
        "linkage": source_record(linkage_path),
    }


def _validate_label_universe(
    gt: Mapping[str, Any], linkage: Mapping[str, Any], target_ids: Iterable[str]
) -> None:
    expected = set(target_ids)
    groups = gt.get("origins")
    members = [member for group in groups if isinstance(group, Mapping) for member in group.get("members", ())] if isinstance(groups, list) else []
    addresses = linkage.get("addresses")
    if any(not isinstance(member, str) for member in members) or len(members) != len(set(members)) or set(members) != expected:
        raise ValueError("primary GT target universe mismatch")
    if not isinstance(addresses, Mapping) or set(addresses) != expected:
        raise ValueError("primary linkage target universe mismatch")
    if isinstance(gt.get("symbols"), Mapping) and set(gt["symbols"]) != expected:
        raise ValueError("primary symbol target universe mismatch")


def _target_ids(prediction: Mapping[str, Any]) -> tuple[str, ...]:
    universe = prediction.get("universe")
    values = universe.get("target_ids") if isinstance(universe, Mapping) else None
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values) or len(set(values)) != len(values):
        raise ValueError("prediction universe is invalid")
    return tuple(sorted(values))


def _primary_metrics(
    prediction: Mapping[str, Any],
    gt: Mapping[str, Any],
    linkage: Mapping[str, Any],
    bodies: Mapping[str, Any],
    candidate_pairs: Iterable[tuple[str, str]] | None,
) -> dict[str, Any]:
    eligible = {
        function_id
        for function_id, body in bodies.items()
        if body.complete and not body.quality.get("opaque_indirect_jumps", 0)
    }
    return metrics(
        prediction,
        gt,
        linkage,
        eligible=eligible,
        candidate_pairs=set(candidate_pairs) if candidate_pairs is not None else None,
    )


def _origin_map(linkage: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    result = {}
    for member, record in (linkage.get("addresses") or {}).items():
        origins = record.get("origins") if isinstance(record, Mapping) else None
        if isinstance(origins, list):
            result[str(member)] = tuple(str(origin) for origin in origins)
    return result


def _clip_prediction(
    prediction: Mapping[str, Any],
    mask: set[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    clipped = copy.deepcopy(dict(prediction))
    clipped["universe"] = {"target_ids": sorted(mask)}
    contamination: list[str] = []
    clusters = []
    for cluster in prediction.get("clusters", ()):
        members = set(cluster.get("members", ()))
        if cluster.get("status") == "accepted":
            contamination.extend(sorted(members - mask))
        kept = sorted(members & mask)
        if len(kept) >= 2:
            clusters.append({"members": kept, "status": cluster.get("status", "accepted")})
    clipped["clusters"] = clusters
    return clipped, {
        "out_of_mask_member_count": len(contamination),
        "out_of_mask_members": sorted(set(contamination)),
    }


def clip_prediction(prediction: Mapping[str, Any], mask: set[str]) -> dict[str, Any]:
    """Public clipping helper used by the small scorer regression checks."""

    return _clip_prediction(prediction, mask)[0]


def _validate_join(
    ground_truth: Mapping[str, Any],
    linkage: Mapping[str, Any],
    target_ids: Iterable[str],
    case: str,
) -> None:
    expected = set(target_ids)
    gt_member_list = [
        member
        for group in ground_truth.get("origins", ())
        if isinstance(group, Mapping)
        for member in group.get("members", ())
    ]
    gt_members = set(gt_member_list)
    addresses = linkage.get("addresses", {})
    linkage_members = set(addresses) if isinstance(addresses, Mapping) else set()
    if len(gt_member_list) != len(gt_members) or gt_members != expected or linkage_members != expected:
        raise ValueError(f"{case} universe mismatch between labels and targets")


def _view(
    prediction: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
    linkage: Mapping[str, Any],
    universe: set[str],
    eligible: set[str],
    view_name: str,
    spec: Mapping[str, Any],
    known_origins: set[str],
) -> dict[str, Any]:
    """Score a masked view without regrouping predicted clusters."""

    origins = _origin_map(linkage)
    if view_name == "project_owned":
        from gt_extractor import belongs_to_subject

        namespaces = tuple(spec.get("namespaces", ()))
        mask = {
            member
            for member in universe
            if len(origins.get(member, ())) == 1
            and belongs_to_subject(origins[member][0], namespaces)
        }
    elif view_name in {"previously_unobserved", "previously_unobserved_normalized_origin", "previously-unobserved-normalized-origin"}:
        mask = {
            member
            for member in universe
            if len(origins.get(member, ())) == 1
            and origins[member][0] not in known_origins
        }
    else:
        raise ValueError(f"unknown secondary view: {view_name}")
    clipped, contamination = _clip_prediction(prediction, mask)
    result = metrics(clipped, ground_truth, linkage, eligible & mask)
    if result["positive_pairs"] == 0:
        result["recall"] = None
        result["macro_origin_recall"] = None
        result["exact_group_rate"] = None
    result.update({
        "mask_size": len(mask),
        "mask_positive_pairs": result["positive_pairs"],
        "cross_boundary_cluster_count": 0,
        "mask_members_in_mixed_clusters": 0,
        "outside_members_in_mixed_clusters": 0,
        "contamination": contamination,
    })
    for cluster in prediction.get("clusters", ()):
        if cluster.get("status") != "accepted":
            continue
        members = set(cluster.get("members", ()))
        inside, outside = members & mask, members - mask
        if inside and outside:
            result["cross_boundary_cluster_count"] += 1
            result["mask_members_in_mixed_clusters"] += len(inside)
            result["outside_members_in_mixed_clusters"] += len(outside)
    return result


def _unobserved_origins(config: Mapping[str, Any]) -> set[str]:
    manifest_value = config.get("hash_manifest")
    if not isinstance(manifest_value, str):
        raise ValueError("config.hash_manifest is required")
    manifest_path = HERE / manifest_value
    manifest = read_json(manifest_path)
    inventory = manifest.get("exposure_inventory") if isinstance(manifest, Mapping) else None
    if not isinstance(inventory, Mapping) or not isinstance(inventory.get("files"), list):
        raise ValueError("exposure inventory is missing")
    listed = [item.get("path") for item in inventory["files"] if isinstance(item, Mapping)]
    if len(listed) != len(inventory["files"]):
        raise ValueError("exposure inventory record is invalid")
    listed_sha = inventory.get("file_list_sha256")
    if listed_sha and hashlib.sha256(json.dumps(listed, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest() != listed_sha:
        raise ValueError("exposure file-list hash mismatch")
    # The 13 source files remain provenance, while this compact pinned list is
    # the only exposure data consumed by scoring.
    descriptor = inventory.get("normalized_origin_label_set")
    if not isinstance(descriptor, Mapping):
        raise ValueError("normalized origin label-set artifact is not pinned")
    value = descriptor.get("path") or descriptor.get("file")
    if not isinstance(value, str):
        raise ValueError("normalized origin label-set path is missing")
    path = Path(value)
    if not path.is_absolute():
        path = HERE / path
    expected = descriptor.get("sha256")
    if not path.is_file() or not expected or sha256_file(path) != expected:
        raise ValueError("normalized origin label-set hash mismatch")
    data = read_json(path)
    labels = data.get("origins") if isinstance(data, Mapping) else data
    if not isinstance(labels, list) or any(not isinstance(origin, str) for origin in labels) or labels != sorted(set(labels)):
        raise ValueError("normalized origin label-set is not sorted and unique")
    if inventory.get("normalized_origin_label_set", {}).get("label_count") not in (None, len(labels)):
        raise ValueError("normalized origin label-set count mismatch")
    canonical = json.dumps(labels, ensure_ascii=True, separators=(",", ":")).encode()
    if hashlib.sha256(canonical).hexdigest() != expected:
        raise ValueError("normalized origin label-set canonical hash mismatch")
    return set(labels)


def _secondary_masks(
    config: Mapping[str, Any],
    case: str,
    gt: Mapping[str, Any],
    linkage: Mapping[str, Any],
    target_ids: Iterable[str] | None = None,
) -> dict[str, set[str]]:
    from gt_extractor import belongs_to_subject

    source = case_config(config, case)
    namespaces = source.get("namespaces")
    if not isinstance(namespaces, list):
        raise ValueError(f"source namespaces are missing for {case}")
    origins = _origin_map(linkage)
    target = set(target_ids) if target_ids is not None else set(origins)
    project_owned = {
        member
        for member, names in origins.items()
        if member in target and len(names) == 1 and belongs_to_subject(names[0], tuple(namespaces))
    }
    known = _unobserved_origins(config)
    previously_unobserved = {
        member for member, names in origins.items() if member in target and len(names) == 1 and names[0] not in known
    }
    return {
        "project_owned": project_owned,
        "previously_unobserved_normalized_origin": previously_unobserved,
    }


def _candidate_pairs_for_arm(
    config: Mapping[str, Any],
    case: str,
    arm: str,
) -> set[tuple[str, str]] | None:
    key = F6_CANDIDATE_KEYS.get(arm)
    if key is None:
        return None
    path = _candidate_paths(case_paths(config, case))[key]
    artifact = read_json(path)
    return {tuple(sorted(item["pair"])) for item in artifact["pairs"]}


def _candidate_summary(
    artifact: Mapping[str, Any] | None, bodies: Mapping[str, Any]
) -> dict[str, Any] | None:
    if artifact is None:
        return None
    pairs = artifact.get("pairs", ())
    counts: defaultdict[str, int] = defaultdict(int)
    eligible = 0
    for record in pairs:
        pair = record.get("pair") if isinstance(record, Mapping) else None
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError("candidate pair record is invalid")
        reasons = set()
        for member in pair:
            body = bodies.get(member)
            if body is None:
                reasons.add("missing")
            elif not body.complete:
                reasons.add("incomplete")
            elif body.quality.get("opaque_indirect_jumps", 0):
                reasons.add("opaque")
        if reasons:
            for reason in sorted(reasons):
                counts[reason] += 1
        else:
            eligible += 1
    return {
        "candidate_pair_count": len(pairs),
        "eligible_pair_count": eligible,
        "ineligible_pair_count": len(pairs) - eligible,
        "ineligible_count_by_reason": dict(sorted(counts.items())),
    }


def _mask_diagnostics(prediction: Mapping[str, Any], mask: set[str]) -> dict[str, Any]:
    crossed = mask_members = outside_members = 0
    for cluster in prediction.get("clusters", ()):
        if not isinstance(cluster, Mapping) or cluster.get("status") != "accepted":
            continue
        members = set(cluster.get("members", ()))
        inside, outside = members & mask, members - mask
        if inside and outside:
            crossed += 1
            mask_members += len(inside)
            outside_members += len(outside)
    return {
        "cross_boundary_cluster_count": crossed,
        "mask_members_in_mixed_clusters": mask_members,
        "outside_members_in_mixed_clusters": outside_members,
    }


def _logical_cost(metadata: Mapping[str, Any], prediction: Mapping[str, Any] | None) -> dict[str, Any]:
    source = prediction.get("metrics", {}) if isinstance(prediction, Mapping) else metadata.get("comparison_cost", {})
    if not isinstance(source, Mapping):
        source = {}
    demand = metadata.get("demand", {}) if isinstance(metadata.get("demand", {}), Mapping) else {}
    def get(*keys: str) -> Any:
        for container in (source, demand, metadata):
            for key in keys:
                if key in container:
                    return container[key]
        return None
    rescue = metadata.get("rescue_summary", {})
    if not isinstance(rescue, Mapping):
        rescue = {}
    return {
        "candidate_comparisons": get("candidate_detailed_comparison_count", "candidate_comparisons", "comparisons"),
        "candidate_alignment_cells": get("candidate_alignment_cells", "alignment_cells"),
        "on_demand_comparisons": get("on_demand_comparison_count", "on_demand_comparisons"),
        "on_demand_alignment_cells": get("on_demand_alignment_cells"),
        "total_comparisons": get("total_detailed_comparisons", "total_comparisons"),
        "total_alignment_cells": get("total_alignment_cells"),
        "rescue_comparisons": rescue.get("reserved_comparisons"),
        "rescue_alignment_cells": rescue.get("reserved_alignment_cells"),
        "physical_cache": metadata.get("physical_cache"),
        "wall_seconds": metadata.get("elapsed_seconds"),
        "max_rss": (metadata.get("resource") or {}).get("max_rss") if isinstance(metadata.get("resource"), Mapping) else None,
        "basis": "logical n*m proxy; physical cache cost reported separately",
        "rescue_scope": "additional-to-strict-f6",
        "rescue_budget": metadata.get("rescue_budget"),
    }


def _refusal_counts(metadata: Mapping[str, Any]) -> Mapping[str, Any]:
    value = metadata.get("refusal_counts", metadata.get("refusal_count"))
    if isinstance(value, Mapping):
        return dict(value)
    if metadata.get("status") == "budget-refused":
        return {"budget_refused": 1}
    if metadata.get("status") in {"resource-incomplete", "dependency-unavailable", "blocked-prerequisite"}:
        return {str(metadata["status"]): 1}
    return {}


def score_case(config: Mapping[str, Any], case: str) -> dict[str, Any]:
    scoring_python = _verify_runtime(config)
    if str(config.get("status", "")).upper() not in {"FROZEN", "FROZEN-DESIGN", "APPROVED"}:
        raise ValueError("config status is not frozen; refusing scoring")
    if config.get("protocol_sha256") != sha256_file(_protocol_path()):
        raise ValueError("protocol hash is not frozen; refusing scoring")
    observation, body_artifact = _observation_body(config, case)
    old_core = REPO_ROOT / "experiments" / "followup-2026-09-08"
    for path in (REPO_ROOT, old_core):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from body_similarity import load_body_evidence

    bodies = load_body_evidence(body_artifact)
    paths = case_paths(config, case)
    candidate_paths = _candidate_paths(paths)
    candidate_hashes = {
        key: sha256_file(path) for key, path in candidate_paths.items()
    }
    prediction_meta: dict[str, dict[str, Any]] = {}
    prediction_data: dict[str, dict[str, Any]] = {}
    candidate_artifacts: dict[str, dict[str, Any]] = {}
    target_sets: list[tuple[str, ...]] = []
    body_sha = (observation.get("outputs", {}).get("body", {}) or {}).get("sha256")
    if not body_sha:
        raise ValueError("observation body provenance is missing")
    for key, path in candidate_paths.items():
        artifact = read_json(path)
        if not isinstance(artifact, Mapping):
            raise ValueError(f"candidate artifact is invalid: {path}")
        candidate_artifacts[key] = dict(artifact)
        universe = artifact.get("universe", {})
        values = universe.get("target_ids") if isinstance(universe, Mapping) else None
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values) or len(set(values)) != len(values):
            raise ValueError(f"candidate target universe is invalid: {path}")
        target_sets.append(tuple(sorted(values)))
    for arm in ARMS:
        candidate_key = F6_CANDIDATE_KEYS.get(arm)
        candidate_sha = candidate_hashes[candidate_key] if candidate_key else None
        metadata, _metadata_path, prediction_path = _prediction_metadata(
            config, case, arm, candidate_sha
        )
        prediction_meta[arm] = metadata
        if metadata["status"] == "completed":
            prediction = read_json(prediction_path)
            if not isinstance(prediction, Mapping):
                raise ValueError(f"prediction is invalid: {prediction_path}")
            target_sets.append(_validate_prediction(prediction, config, case, arm, body_sha, candidate_sha))
            prediction_data[arm] = dict(prediction)

    if target_sets and any(target != target_sets[0] for target in target_sets[1:]):
        raise ValueError("prediction/candidate target universe mismatch")
    body_records = body_artifact.get("functions", ()) if isinstance(body_artifact, Mapping) else ()
    body_ids = {item.get("id") for item in body_records if isinstance(item, Mapping) and isinstance(item.get("id"), str)}
    target = target_sets[0] if target_sets else tuple(sorted(body_ids))
    if not target:
        raise ValueError("validated target universe is empty")
    if body_ids and body_ids != set(target):
        raise ValueError("observation body target universe mismatch")

    # This is the first point at which label files are opened.  Every arm's
    # terminal state and completed prediction hash was checked above.
    gt, linkage, label_records = _label_pair_inputs(config, case, target)
    masks = _secondary_masks(config, case, gt, linkage, target)
    outputs: dict[str, Any] = {}
    eligible = {
        function_id
        for function_id, body in bodies.items()
        if body.complete and not body.quality.get("opaque_indirect_jumps", 0)
    }
    for arm in ARMS:
        metadata = prediction_meta[arm]
        record: dict[str, Any] = {
            "case": case,
            "arm": arm,
            "status": metadata["status"],
            "config_sha256": sha256_file(_config_path()),
            "protocol_sha256": sha256_file(_protocol_path()),
            "prediction_metadata_sha256": sha256_file(
                paths["prediction_dir"] / arm / "metadata.json"
            ),
            "cost": _logical_cost(metadata, prediction_data.get(arm)),
            "refusal_counts": _refusal_counts(metadata),
            "scoring_python": scoring_python,
            "candidate": _candidate_summary(
                candidate_artifacts.get(F6_CANDIDATE_KEYS.get(arm, "")), bodies
            ),
        }
        if metadata["status"] == "completed":
            candidate_pairs = _candidate_pairs_for_arm(config, case, arm)
            prediction = prediction_data[arm]
            record["prediction"] = source_record(paths["prediction_dir"] / arm / "prediction.json")
            record["metrics"] = _primary_metrics(
                prediction,
                gt,
                linkage,
                bodies,
                candidate_pairs,
            )
            for view, mask in masks.items():
                clipped, contamination = _clip_prediction(prediction, mask)
                secondary_metrics = metrics(clipped, gt, linkage, eligible=eligible & mask)
                if secondary_metrics["positive_pairs"] == 0:
                    secondary_metrics["recall"] = None
                    secondary_metrics["macro_origin_recall"] = None
                    secondary_metrics["exact_group_rate"] = None
                diagnostics = _mask_diagnostics(prediction, mask)
                contamination.update(diagnostics)
                secondary_metrics["mask_size"] = len(mask)
                secondary_metrics["mask_positive_pairs"] = secondary_metrics["positive_pairs"]
                secondary_metrics.update(diagnostics)
                secondary_metrics["exact_group_interpretation"] = "subset-completeness only under clipped target universe"
                secondary_metrics["precision_interpretation"] = "masked-target precision; not full-target discovery precision"
                record.setdefault("secondary", {})[view] = {
                    "target_count": len(mask),
                    "metrics": secondary_metrics,
                    "contamination": contamination,
                }
        else:
            record["metrics"] = None
            record["secondary"] = {
                view: {"target_count": None, "metrics": None, "contamination": None}
                for view in masks
            }
        if arm == ARM_RESCUE and ARM_C3 in outputs:
            record["cost"]["strict_input_cost"] = outputs[ARM_C3]["cost"]
        outputs[arm] = record
    summary = {
        "case": case,
        "status": "completed",
        "config_sha256": sha256_file(_config_path()),
        "protocol_sha256": sha256_file(_protocol_path()),
        "arms": {arm: {"status": outputs[arm]["status"], "metrics": outputs[arm].get("metrics"), "secondary": outputs[arm].get("secondary"), "cost": outputs[arm]["cost"], "refusal_counts": outputs[arm]["refusal_counts"]} for arm in ARMS},
    }
    write_json_once(paths["score_dir"] / "scores.json", {"case": case, "status": "scored", "provenance": {"config_sha256": sha256_file(_config_path()), "protocol_sha256": sha256_file(_protocol_path()), "observation_metadata_sha256": sha256_file(paths["observation_metadata"]), "ground_truth_sha256": label_records["ground_truth"]["sha256"], "linkage_sha256": label_records["linkage"]["sha256"], "scoring_python": scoring_python}, "arms": outputs})
    rows = []
    for arm in ARMS:
        for view, value in [("primary", outputs[arm].get("metrics")), *outputs[arm].get("secondary", {}).items()]:
            quality = value.get("metrics", value) if isinstance(value, Mapping) else None
            if isinstance(value, Mapping) and isinstance(value.get("contamination"), Mapping):
                quality = {**quality, **value["contamination"]}
            cost = outputs[arm]["cost"]
            rows.append({"case": case, "arm": arm, "status": outputs[arm]["status"], "label_view": view, "target_count": quality.get("target_count") if quality else None, "mask_size": quality.get("mask_size") if quality else None, **{key: quality.get(key) if quality else None for key in ("TP", "FP", "FN", "TN", "precision", "recall", "f1", "macro_origin_recall", "exact_group_rate", "positive_pairs")}, "macro_R": quality.get("macro_origin_recall") if quality else None, "candidate_comparisons": cost.get("candidate_comparisons"), "on_demand_comparisons": cost.get("on_demand_comparisons"), "total_comparisons": cost.get("total_comparisons"), "rescue_comparisons": cost.get("rescue_comparisons"), "cross_boundary_cluster_count": quality.get("cross_boundary_cluster_count") if quality else None, "mask_members_in_mixed_clusters": quality.get("mask_members_in_mixed_clusters") if quality else None, "outside_members_in_mixed_clusters": quality.get("outside_members_in_mixed_clusters") if quality else None})
    fields = tuple(rows[0]) if rows else ("case", "arm", "status", "label_view")
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: "NA" if row.get(field) is None else row.get(field) for field in fields})
    _write_text_once(paths["score_dir"] / "summary.csv", stream.getvalue())
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    args = parser.parse_args(argv)
    try:
        config = _load_frozen_config()
        _verify_core(config)
        _verify_runtime(config)
        expected = dict(frozen_implementation_hashes(config))
        actual = implementation_hashes()
        if expected != actual:
            raise ValueError(f"frozen implementation hashes do not match: {expected} != {actual}")
        cases = config_cases(config)
        if args.case not in cases:
            raise ValueError(f"case is outside frozen config: {args.case}")
        score_case(config, args.case)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
