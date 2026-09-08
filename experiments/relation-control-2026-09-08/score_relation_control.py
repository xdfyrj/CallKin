"""Score frozen relation-control predictions after all arms have run.

Selection and inference are upstream of this module.  This evaluator only
reads their retained artifacts, applies the existing linkage scorer, and
writes evaluation summaries.  It never changes a candidate or prediction.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REFERENCE = HERE.parent / "followup-2026-09-08"

# The old evaluator is intentionally reused.  Importing it does not run the
# old environment verifier; only its pure truth_index/metrics functions are
# used here.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(REFERENCE) not in sys.path:
    sys.path.insert(0, str(REFERENCE))
from relation_control import (  # noqa: E402
    ELIGIBLE,
    endpoint_reasons,
    graph_summary,
    load_bodies,
    pair_cost,
    pair_from_record,
    pair_stratum,
    stratum_label,
)
from score_followup import metrics as legacy_metrics  # noqa: E402
from score_followup import truth_index  # noqa: E402

# Public aliases keep callers on the exact prior scorer implementation.
metrics = legacy_metrics


ARM_TERMINAL_STATES = ("completed", "budget-refused", "resource-incomplete")
QUALITY_FIELDS = (
    "TP",
    "FP",
    "FN",
    "TN",
    "precision",
    "recall",
    "f1",
    "macro_origin_recall",
    "exact_group_rate",
    "positive_pairs",
    "scored_pairs",
    "neutral_pairs",
    "per_origin",
    "positive_first_outcome",
    "on_demand_positive_compared",
    "comparison_cost",
)
SUMMARY_FIELDS = (
    "case",
    "arm",
    "status",
    "candidate_pair_count",
    "eligible_pair_count",
    "ineligible_pair_count",
    "candidate_comparisons",
    "candidate_alignment_cells",
    "on_demand_comparisons",
    "on_demand_alignment_cells",
    "total_comparisons",
    "total_alignment_cells",
    "TP",
    "FP",
    "FN",
    "TN",
    "precision",
    "recall",
    "f1",
    "macro_R",
    "exact_group_rate",
)
DELTA_METRICS = (
    "precision",
    "recall",
    "f1",
    "macro_R",
    "exact_group_rate",
    "candidate_positive_recall",
    "candidate_comparisons",
    "candidate_alignment_cells",
    "on_demand_comparisons",
    "on_demand_alignment_cells",
    "total_comparisons",
    "total_alignment_cells",
)
SENSITIVITY_FIELDS = (
    "TP",
    "FP",
    "FN",
    "TN",
    "precision",
    "recall",
    "f1",
    "macro_R",
    "exact_group_rate",
)


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json_once(path: Path, value: Any) -> str:
    """Write deterministic JSON while refusing to replace retained output."""

    encoded = json.dumps(
        value, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    if path.exists():
        if sha256_file(path) != digest:
            raise ValueError(f"refusing to overwrite retained output: {path}")
        return digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8")
    return digest


def score_prediction(
    prediction: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
    linkage: Mapping[str, Any],
    *,
    eligible: Iterable[str] | None = None,
    candidate_pairs: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Score one prediction with the unchanged follow-up scorer."""

    result = legacy_metrics(
        prediction,
        ground_truth,
        linkage,
        set(eligible) if eligible is not None else None,
        set(candidate_pairs) if candidate_pairs is not None else None,
    )
    _quality_conservation(result)
    return result


def _target_ids(universe: Mapping[str, Any], label: str) -> tuple[str, ...]:
    values = universe.get("target_ids")
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"{label} has no valid target_ids")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} target_ids contain duplicates")
    return tuple(sorted(values))


def _pair_key(record: Mapping[str, Any]) -> tuple[str, str]:
    pair = pair_from_record(record)
    return pair.left, pair.right


def _pair_set(records: Iterable[Mapping[str, Any]]) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for record in records:
        key = _pair_key(record)
        if key in result:
            raise ValueError(f"duplicate candidate pair: {key}")
        result.add(key)
    return result


def _source_record(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}


def _reference_record(
    reference_inputs: Mapping[str, Any], case: str, name: str
) -> Mapping[str, Any]:
    try:
        record = reference_inputs["cases"][case][name]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"old input manifest lacks {case}/{name}") from exc
    if not isinstance(record, Mapping) or "path" not in record or "sha256" not in record:
        raise ValueError(f"old input manifest record is invalid: {case}/{name}")
    return record


def _resolve_label_path(
    spec: Mapping[str, Any],
    name: str,
    *,
    reference_inputs: Mapping[str, Any],
    case: str,
) -> tuple[Path, str | None]:
    direct = spec.get(name)
    if direct is not None:
        path = Path(str(direct))
        return (path if path.is_absolute() else (HERE / path).resolve()), None
    manifest_name = f"{name}_from_source_manifest"
    source = spec.get(manifest_name)
    if source is not None:
        root = Path(str(reference_inputs["input_root"]))
        return (root / str(source)).resolve(), manifest_name
    raise ValueError(f"label plan lacks {name} path for {case}")


def _load_label_plan(
    config: Mapping[str, Any],
    reference_inputs: Mapping[str, Any],
    case: str,
    role: str,
) -> dict[str, Any]:
    plans = config.get("labels", {})
    if role == "secondary_original":
        plans = plans.get("secondary_original", {})
    else:
        plans = plans.get(role, {})
    spec = plans.get(case)
    if not isinstance(spec, Mapping):
        raise ValueError(f"label plan lacks {role}/{case}")
    if spec.get("same_as_primary"):
        return {"role": role, "same_as_primary": True, "spec": dict(spec)}

    descriptor: dict[str, Any] = {"role": role, "spec": dict(spec)}
    try:
        gt_path, gt_source_key = _resolve_label_path(
            spec, "ground_truth", reference_inputs=reference_inputs, case=case
        )
        linkage_path, linkage_source_key = _resolve_label_path(
            spec, "linkage", reference_inputs=reference_inputs, case=case
        )
        descriptor.update(
            {
                "ground_truth": _source_record(gt_path),
                "linkage": _source_record(linkage_path),
                "ground_truth_source": gt_source_key or "config",
                "linkage_source": linkage_source_key or "config",
            }
        )
        expected_gt = spec.get("ground_truth_sha256")
        expected_linkage = spec.get("linkage_sha256")
        if gt_source_key:
            expected_gt = _reference_record(reference_inputs, case, "ground_truth")["sha256"]
        if linkage_source_key:
            expected_linkage = _reference_record(reference_inputs, case, "linkage")["sha256"]
        descriptor["expected_ground_truth_sha256"] = expected_gt
        descriptor["expected_linkage_sha256"] = expected_linkage
        errors = []
        if expected_gt and descriptor["ground_truth"]["sha256"] != expected_gt:
            errors.append("ground_truth_file_hash_mismatch")
        if expected_linkage and descriptor["linkage"]["sha256"] != expected_linkage:
            errors.append("linkage_file_hash_mismatch")
        descriptor["load_error"] = None
        descriptor["load_errors"] = errors
        descriptor["ground_truth_data"] = read_json(gt_path)
        descriptor["linkage_data"] = read_json(linkage_path)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        descriptor["load_error"] = repr(exc)
        descriptor["load_errors"] = ["label_file_load_failure"]
        descriptor["ground_truth_data"] = None
        descriptor["linkage_data"] = None
    return descriptor


def _label_descriptor(label: Mapping[str, Any]) -> dict[str, Any]:
    """Return label identity metadata without embedding raw label files."""

    keep = {
        "role",
        "same_as_primary",
        "spec",
        "ground_truth",
        "linkage",
        "ground_truth_source",
        "linkage_source",
        "expected_ground_truth_sha256",
        "expected_linkage_sha256",
        "load_error",
        "load_errors",
    }
    return {key: value for key, value in label.items() if key in keep}


def _label_join(
    label: Mapping[str, Any],
    *,
    case: str,
    candidate: Mapping[str, Any],
    target_ids: Iterable[str],
    reference_inputs: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate exact GT/linkage joins before allowing a score."""

    expected = set(target_ids)
    errors = list(label.get("load_errors", ()))
    gt = label.get("ground_truth_data")
    audit = label.get("linkage_data")
    if not isinstance(gt, Mapping) or not isinstance(audit, Mapping):
        errors.append("label_data_missing")
        return {
            "status": "join-failure",
            "errors": sorted(set(errors)),
            "target_count": len(expected),
        }

    for key in ("case", "build", "profile"):
        expected_value = candidate.get(key)
        if expected_value is not None and gt.get(key) != expected_value:
            errors.append(f"gt_{key}_mismatch")

    origins = gt.get("origins")
    addresses = audit.get("addresses")
    if not isinstance(origins, list):
        errors.append("gt_origins_missing")
        origins = []
    if not isinstance(addresses, Mapping):
        errors.append("linkage_addresses_missing")
        addresses = {}

    gt_members = [
        member
        for group in origins
        if isinstance(group, Mapping) and isinstance(group.get("members"), list)
        for member in group["members"]
    ]
    gt_member_set = set(gt_members)
    linkage_set = set(addresses)
    if len(gt_member_set) != len(gt_members):
        errors.append("gt_member_duplicates")

    # Compare identities, not just counts or typed labels.  A same-sized but
    # shifted label universe must be rejected as a failed join.
    if gt_member_set != expected:
        if expected - gt_member_set:
            errors.append("gt_missing_target_ids")
        if gt_member_set - expected:
            errors.append("gt_extra_target_ids")
    if linkage_set != expected:
        if expected - linkage_set:
            errors.append("linkage_missing_target_ids")
        if linkage_set - expected:
            errors.append("linkage_extra_target_ids")

    symbols = gt.get("symbols")
    if isinstance(symbols, Mapping) and set(symbols) != expected:
        errors.append("gt_symbols_target_join_mismatch")

    candidate_provenance = candidate.get("provenance", {})
    gt_provenance = gt.get("provenance", {})
    if isinstance(candidate_provenance, Mapping) and isinstance(gt_provenance, Mapping):
        for key in ("build_id", "source_sha256", "non_stripped_sha256", "stripped_sha256"):
            if (
                key in candidate_provenance
                and key in gt_provenance
                and candidate_provenance[key] != gt_provenance[key]
            ):
                errors.append(f"gt_provenance_{key}_mismatch")

    case_input = _reference_record(reference_inputs, case, "ground_truth")
    linkage_input = _reference_record(reference_inputs, case, "linkage")
    spec = label.get("spec", {})
    if spec.get("ground_truth") is not None:
        if gt.get("parent_ground_truth_sha256") != case_input["sha256"]:
            errors.append("corrected_gt_parent_hash_mismatch")
    linkage_provenance = audit.get("provenance", {})
    if not isinstance(linkage_provenance, Mapping):
        linkage_provenance = {}
    if spec.get("linkage") is not None:
        if linkage_provenance.get("parent_sha256") != linkage_input["sha256"]:
            errors.append("corrected_linkage_parent_hash_mismatch")
    if linkage_provenance.get("ground_truth_sha256"):
        if linkage_provenance["ground_truth_sha256"] != label.get(
            "ground_truth", {}
        ).get("sha256"):
            errors.append("linkage_gt_hash_mismatch")
    if (
        linkage_provenance.get("non_stripped_sha256")
        and isinstance(gt_provenance, Mapping)
        and gt_provenance.get("non_stripped_sha256")
        != linkage_provenance["non_stripped_sha256"]
    ):
        errors.append("linkage_provenance_non_stripped_mismatch")

    for address, record in addresses.items():
        if not isinstance(record, Mapping):
            errors.append(f"linkage_record_invalid:{address}")
            continue
        if not isinstance(record.get("origins"), list):
            errors.append(f"linkage_origins_invalid:{address}")
        if not isinstance(record.get("identities"), list):
            errors.append(f"linkage_identities_invalid:{address}")

    return {
        "status": "ok" if not errors else "join-failure",
        "errors": sorted(set(errors)),
        "target_count": len(expected),
        "gt_member_count": len(gt_member_set),
        "linkage_address_count": len(linkage_set),
        "gt_target_ids": sorted(gt_member_set),
        "linkage_target_ids": sorted(linkage_set),
    }


def _snapshot_errors(
    output: Path, reference: Path, config: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> list[str]:
    errors: list[str] = []
    if snapshot.get("status") != "controls-hashed":
        errors.append("snapshot_not_controls_hashed")
    config_path = output / "config.json"
    protocol_path = output / "protocol.md"
    if config.get("protocol_sha256") is None:
        errors.append("protocol_hash_not_frozen")
    config_sha = sha256_file(config_path)
    protocol_sha = sha256_file(protocol_path)
    if config.get("protocol_sha256") != protocol_sha:
        errors.append("config_protocol_hash_mismatch")
    if snapshot.get("config_sha256") != config_sha:
        errors.append("snapshot_config_hash_mismatch")
    if snapshot.get("protocol_sha256") != protocol_sha:
        errors.append("snapshot_protocol_hash_mismatch")
    if snapshot.get("base_commit") != config.get("base_commit"):
        errors.append("snapshot_base_commit_mismatch")
    for name, record in snapshot.get("implementation", {}).items():
        path = output / name
        if (
            not isinstance(record, Mapping)
            or not path.is_file()
            or sha256_file(path) != record.get("sha256")
        ):
            errors.append(f"snapshot_implementation_hash_mismatch:{name}")

    for name in ("reference_config", "reference_inputs", "reference_protocol"):
        record = snapshot.get("reference", {}).get(name)
        if not isinstance(record, Mapping) or not Path(str(record.get("path", ""))).is_file():
            errors.append(f"snapshot_{name}_missing")
        elif sha256_file(record["path"]) != record.get("sha256"):
            errors.append(f"snapshot_{name}_hash_mismatch")
    selections = snapshot.get("selection_sha256", {})
    for case in config.get("cases", ()):
        selection_path = output / "selection" / f"{case}.json"
        if not selection_path.is_file() or selections.get(case) != sha256_file(selection_path):
            errors.append(f"selection_hash_mismatch:{case}")
        case_records = snapshot.get("reference", {}).get("cases", {}).get(case, {})
        if not isinstance(case_records, Mapping):
            errors.append(f"snapshot_case_missing:{case}")
            continue
        for name, record in case_records.items():
            if not isinstance(record, Mapping) or not Path(str(record.get("path", ""))).is_file():
                errors.append(f"snapshot_case_input_missing:{case}/{name}")
            elif sha256_file(record["path"]) != record.get("sha256"):
                errors.append(f"snapshot_case_input_hash_mismatch:{case}/{name}")
        arms = snapshot.get("controls", {}).get(case, {})
        controls = tuple(config.get("arms", {}).get("controls", ()))
        if set(arms) != set(controls):
            errors.append(f"snapshot_control_arm_set_mismatch:{case}")
        for arm, expected_sha in arms.items():
            path = output / "candidates" / case / f"{arm}.candidates.json"
            if not path.is_file() or sha256_file(path) != expected_sha:
                errors.append(f"control_hash_mismatch:{case}/{arm}")
    return errors


def validate_snapshot(
    *, output: Path = HERE, reference: Path = REFERENCE, config: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Validate the preparation freeze without invoking the old verifier."""

    config = read_json(output / "config.json") if config is None else config
    snapshot = read_json(output / "snapshot.json")
    errors = _snapshot_errors(output, reference, config, snapshot)
    if errors:
        raise ValueError("relation-control freeze validation failed: " + "; ".join(errors))
    return snapshot


def _candidate_path(
    *, output: Path, reference: Path, snapshot: Mapping[str, Any], case: str, arm: str, treatment: str
) -> Path:
    if arm == treatment:
        record = snapshot["reference"]["cases"][case].get("combined3_candidates")
        if isinstance(record, Mapping):
            return Path(str(record["path"]))
        return reference / "cache" / case / "combined3-k16.candidates.json"
    return output / "candidates" / case / f"{arm}.candidates.json"


def _run_identity_errors(
    metadata: Mapping[str, Any],
    *,
    case: str,
    arm: str,
    candidate_path: Path,
    candidate_sha: str,
    prediction_path: Path | None,
    output: Path,
    snapshot: Mapping[str, Any],
    config: Mapping[str, Any],
) -> list[str]:
    expected_body = snapshot["reference"]["cases"][case]["body"]["sha256"]
    expected_input = snapshot["reference"]["reference_inputs"]["sha256"]
    expected = {
        "case": case,
        "arm": arm,
        "candidate_sha256": candidate_sha,
        "body_evidence_sha256": expected_body,
        "config_sha256": sha256_file(output / "config.json"),
        "protocol_sha256": sha256_file(output / "protocol.md"),
        "base_commit": config["base_commit"],
    }
    expected_python = config.get("runtime", {}).get("python")
    if expected_python is not None:
        expected["python"] = expected_python
    errors = [
        f"metadata_{key}_mismatch"
        for key, value in expected.items()
        if metadata.get(key) != value
    ]
    # The snapshot already authenticates the old input manifest.  Newer
    # runners may repeat that identity in metadata; validate it when present
    # while remaining compatible with the retained runner schema.
    if (
        "input_manifest_sha256" in metadata
        and metadata.get("input_manifest_sha256") != expected_input
    ):
        errors.append("metadata_input_manifest_sha256_mismatch")
    expected_implementation = {
        name: record.get("sha256")
        for name, record in snapshot.get("implementation", {}).items()
        if isinstance(record, Mapping)
    }
    if metadata.get("implementation_sha256") != expected_implementation:
        errors.append("metadata_implementation_sha256_mismatch")
    status = metadata.get("status")
    if status == "completed":
        if prediction_path is None or not prediction_path.is_file():
            errors.append("completed_prediction_missing")
        elif metadata.get("prediction_sha256") != sha256_file(prediction_path):
            errors.append("prediction_hash_mismatch")
    elif status in ("budget-refused", "resource-incomplete"):
        if prediction_path is not None and prediction_path.exists():
            errors.append("noncompleted_prediction_present")
    else:
        errors.append("nonterminal_arm_status")
    if not candidate_path.is_file():
        errors.append("candidate_artifact_missing")
    return errors


def _candidate_identity_errors(
    candidate: Mapping[str, Any],
    *,
    case: str,
    arm: str,
    treatment: str,
    target_ids: tuple[str, ...],
    expected_body_sha: str,
    expected_fixture_sha: str | None,
) -> list[str]:
    errors: list[str] = []
    target_set = set(target_ids)
    if candidate.get("case") != case:
        errors.append("candidate_case_mismatch")
    if _target_ids(candidate.get("universe", {}), "candidate") != target_ids:
        errors.append("candidate_target_universe_mismatch")
    records = candidate.get("pairs")
    if not isinstance(records, list):
        errors.append("candidate_pairs_missing")
        records = []
    try:
        pairs = _pair_set(records)
    except ValueError as exc:
        errors.append(str(exc))
        pairs = set()
    if any(member not in target_set for pair in pairs for member in pair):
        errors.append("candidate_pair_outside_target_universe")
    expected_views = ["token", "cfg", "relation"] if arm == treatment else ["token", "cfg"]
    if tuple(candidate.get("config", {}).get("views", ())) != tuple(expected_views):
        errors.append("candidate_views_mismatch")
    provenance = candidate.get("provenance", {})
    if isinstance(provenance, Mapping):
        if provenance.get("body_evidence_sha256") != expected_body_sha:
            errors.append("candidate_body_provenance_mismatch")
        if expected_fixture_sha is not None and provenance.get("fixture_sha256") != expected_fixture_sha:
            errors.append("candidate_fixture_provenance_mismatch")
    return errors


def _prediction_identity_errors(
    prediction: Mapping[str, Any],
    *,
    candidate: Mapping[str, Any],
    candidate_sha: str,
    body_sha: str,
    expected_policy: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    for key in ("case", "build", "profile", "scope"):
        if key in candidate and prediction.get(key) != candidate.get(key):
            errors.append(f"prediction_{key}_mismatch")
    if _target_ids(prediction.get("universe", {}), "prediction") != _target_ids(
        candidate.get("universe", {}), "candidate"
    ):
        errors.append("prediction_target_universe_mismatch")
    provenance = prediction.get("provenance", {})
    if not isinstance(provenance, Mapping):
        errors.append("prediction_provenance_missing")
    else:
        if provenance.get("body_evidence_sha256") != body_sha:
            errors.append("prediction_body_provenance_mismatch")
        if provenance.get("candidate_artifact_sha256") != candidate_sha:
            errors.append("prediction_candidate_provenance_mismatch")
    actual_policy = prediction.get("config", {})
    if not isinstance(actual_policy, Mapping):
        errors.append("prediction_policy_missing")
    else:
        for key, value in expected_policy.items():
            # `rescue` is a protocol declaration; PairPolicyConfig does not
            # serialize it (or other prose-only declarations) into the
            # unchanged F6 prediction config.
            if key in ("rescue", "align_decide_complete_link"):
                continue
            if actual_policy.get(key) != value:
                errors.append(f"prediction_policy_{key}_mismatch")
    return errors


def _candidate_stats(
    candidate: Mapping[str, Any], bodies: Mapping[str, Any], *, c3_nominal: Mapping[str, int] | None = None
) -> dict[str, Any]:
    records = candidate.get("pairs", ())
    target_ids = _target_ids(candidate.get("universe", {}), "candidate")
    strata: dict[str, dict[str, Any]] = {}
    reasons = Counter()
    eligible_count = 0
    nominal_by_stratum: Counter[str] = Counter()
    for record in records:
        pair = pair_from_record(record)
        stratum = pair_stratum(pair, bodies)
        label = stratum_label(stratum)
        entry = strata.setdefault(label, {"stratum": label, "pair_count": 0, "nominal_alignment_cells": 0})
        entry["pair_count"] += 1
        if stratum[0] == ELIGIBLE:
            eligible_count += 1
            nominal = pair_cost(pair, bodies)
            entry["nominal_alignment_cells"] += nominal
            nominal_by_stratum[label] += nominal
        else:
            for reason in stratum[1]:
                reasons[reason] += 1
    for label, entry in strata.items():
        nominal_by_stratum.setdefault(label, 0)
        baseline = (c3_nominal or {}).get(label)
        entry["nominal_cost_deviation"] = (
            (entry["nominal_alignment_cells"] - baseline) / baseline
            if baseline
            else None
        )
    result = {
        "target_count": len(target_ids),
        "candidate_pair_count": len(records),
        "eligible_pair_count": eligible_count,
        "ineligible_pair_count": len(records) - eligible_count,
        "ineligible_count_by_reason": dict(sorted(reasons.items())),
        "eligibility_reason_counts": dict(sorted(reasons.items())),
        "nominal_alignment_cells_by_stratum": dict(sorted(nominal_by_stratum.items())),
        "nominal_cost_by_stratum": dict(sorted(nominal_by_stratum.items())),
        "nominal_cost_deviation_by_stratum": {
            label: strata[label]["nominal_cost_deviation"] for label in sorted(strata)
        },
        "strata": [strata[label] for label in sorted(strata)],
        "candidate_graph_summary": graph_summary(records, target_ids),
    }
    return result


def _selection_match_errors(
    treatment_stats: Mapping[str, Any], control_stats: Mapping[str, Any]
) -> list[str]:
    """Check the frozen non-label quota and eligibility inheritance."""

    errors: list[str] = []
    for field in (
        "candidate_pair_count",
        "eligible_pair_count",
        "ineligible_pair_count",
        "ineligible_count_by_reason",
    ):
        if treatment_stats.get(field) != control_stats.get(field):
            errors.append(f"control_{field}_differs_from_C3")
    treatment_strata = {
        item["stratum"]: item["pair_count"] for item in treatment_stats.get("strata", ())
    }
    control_strata = {
        item["stratum"]: item["pair_count"] for item in control_stats.get("strata", ())
    }
    if treatment_strata != control_strata:
        errors.append("control_stratum_counts_differ_from_C3")
    return errors


def _selection_stats(
    selection: Mapping[str, Any],
    arm: str,
    treatment: str,
    candidate_pair_set: set[tuple[str, str]],
    c3_pairs: set[tuple[str, str]],
) -> dict[str, Any]:
    selected_stats: Mapping[str, Any] | None = None
    if arm == treatment:
        selected_stats = None
    elif arm == "B2-body-score":
        selected_stats = selection.get("body_score", {}).get("body_score_stats")
    else:
        try:
            index = int(arm.rsplit("-", 1)[1])
            selected_stats = selection.get("random", [])[index].get("random_stats")
        except (ValueError, IndexError, AttributeError):
            selected_stats = None
    result: dict[str, Any] = {
        "selection_frozen_before_f4_cache": True,
        "gt_used_for_selection": False,
        "relation_flags_used_for_selection": False,
        "c3_overlap_count": None,
        "c3_overlap_fraction": None,
    }
    for key in (
        "selection_frozen_before_f4_cache",
        "gt_used_for_selection",
        "relation_flags_used_for_selection",
    ):
        if key in selection:
            result[key] = selection[key]
    if selected_stats is not None:
        result.update(dict(selected_stats))
        selected = int(selected_stats.get("selected_count", len(candidate_pair_set)))
        overlap = sum(int(pair in c3_pairs) for pair in candidate_pair_set)
        result["c3_overlap_count"] = overlap
        result["c3_overlap_fraction"] = overlap / selected if selected else None
        forced_pairs = int(result.get("forced_selection_pair_count", 0))
        result["forced_selection_pair_fraction"] = forced_pairs / selected if selected else None
    return result


def _compact_metrics(metrics: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if metrics is None:
        return None
    return {
        key: metrics.get("macro_origin_recall") if key == "macro_R" else metrics.get(key)
        for key in SENSITIVITY_FIELDS
    }


def _quality_conservation(result: Mapping[str, Any]) -> None:
    if result["TP"] + result["FP"] + result["FN"] + result["TN"] != result["scored_pairs"]:
        raise ValueError("TP/FP/FN/TN do not conserve scored pairs")
    if result["TP"] + result["FN"] != result["positive_pairs"]:
        raise ValueError("TP/FN do not conserve positive pairs")
    stages = result.get("positive_first_outcome")
    if stages is not None and sum(stages.values()) != result["positive_pairs"]:
        raise ValueError("positive outcome stages do not conserve positive pairs")
    if stages is not None and stages.get("recovered", result["TP"]) != result["TP"]:
        raise ValueError("recovered stage does not equal TP")


def _label_quality(
    prediction: Mapping[str, Any],
    candidate: Mapping[str, Any],
    gt: Mapping[str, Any],
    audit: Mapping[str, Any],
    *,
    eligible: set[str],
) -> dict[str, Any]:
    result = legacy_metrics(
        prediction,
        gt,
        audit,
        eligible,
        _pair_set(candidate.get("pairs", ())),
    )
    _quality_conservation(result)
    return result


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def _delta(left: Any, right: Any) -> float | int | None:
    return left - right if _number(left) and _number(right) else None


def _metric_for_delta(evaluation: Mapping[str, Any], name: str) -> Any:
    metrics = evaluation.get("metrics")
    if not isinstance(metrics, Mapping):
        return None
    if name == "macro_R":
        return metrics.get("macro_origin_recall")
    if name == "candidate_positive_recall":
        return evaluation.get("candidate_positive_recall")
    if name in ("candidate_comparisons", "candidate_alignment_cells"):
        return evaluation.get(name)
    cost = metrics.get("comparison_cost")
    cost_keys = {
        "on_demand_comparisons": "on_demand_comparison_count",
        "on_demand_alignment_cells": "on_demand_alignment_cells",
        "total_comparisons": "total_detailed_comparisons",
        "total_alignment_cells": "total_alignment_cells",
    }
    if name in cost_keys:
        return cost.get(cost_keys[name]) if isinstance(cost, Mapping) else None
    return metrics.get(name)


def _primary_delta(treatment: Mapping[str, Any], control: Mapping[str, Any]) -> dict[str, Any]:
    return {name: _delta(_metric_for_delta(control, name), _metric_for_delta(treatment, name)) for name in DELTA_METRICS}


def _primary_sidecar(
    evaluations: Mapping[str, Mapping[str, Mapping[str, Any]]], config: Mapping[str, Any]
) -> dict[str, Any]:
    treatment = config["arms"]["treatment"]
    body_score_arm = next(
        (arm for arm in config["arms"]["controls"] if arm == "B2-body-score"),
        next(
            (arm for arm in config["arms"]["controls"] if "body-score" in arm),
            "B2-body-score",
        ),
    )
    result: dict[str, Any] = {
        "study": config.get("study"),
        "primary_endpoint": "f1",
        "direction": "control_minus_C3",
        "inferential_tests": False,
        "generalization_claim": False,
        "cases": {},
    }
    for case in config["cases"]:
        case_rows = evaluations.get(case, {})
        treatment_eval = case_rows.get(treatment, {})
        control_eval = case_rows.get(body_score_arm, {})
        row = {
            "case": case,
            "treatment_arm": treatment,
            "control_arm": body_score_arm,
            "treatment_status": treatment_eval.get("status"),
            "control_status": control_eval.get("status"),
            "deltas": _primary_delta(treatment_eval, control_eval),
        }
        result["cases"][case] = row
    return result


def _random5_sidecar(
    evaluations: Mapping[str, Mapping[str, Mapping[str, Any]]], config: Mapping[str, Any]
) -> dict[str, Any]:
    arms = tuple(
        arm
        for arm in config["arms"]["controls"]
        if arm != "B2-body-score" and arm.rsplit("-", 1)[-1].isdigit()
    )
    seeds = tuple(config.get("seeds", ()))
    metrics = ("precision", "recall", "f1", "macro_R", "exact_group_rate", "candidate_positive_recall")
    result: dict[str, Any] = {
        "study": config.get("study"),
        "descriptive_only": True,
        "inferential_tests": False,
        "generalization_claim": False,
        "cases": {},
    }
    for case in config["cases"]:
        case_evals = evaluations.get(case, {})
        case_result: dict[str, Any] = {"seeds": [], "metrics": {}}
        for arm in arms:
            index = int(arm.rsplit("-", 1)[1])
            evaluation = case_evals.get(arm, {})
            case_result["seeds"].append(
                {
                    "arm": arm,
                    "seed": seeds[index] if index < len(seeds) else str(index),
                    "status": evaluation.get("status"),
                }
            )
        for metric in metrics:
            values = [
                {
                    "arm": arm,
                    "seed": seeds[int(arm.rsplit("-", 1)[1])]
                    if int(arm.rsplit("-", 1)[1]) < len(seeds)
                    else str(int(arm.rsplit("-", 1)[1])),
                    "value": _metric_for_delta(case_evals.get(arm, {}), metric),
                }
                for arm in arms
            ]
            numbers = [item["value"] for item in values if _number(item["value"])]
            case_result["metrics"][metric] = {
                "per_seed_values": values,
                "available_count": len(numbers),
                "mean": sum(numbers) / len(numbers) if numbers else None,
                "min": min(numbers) if numbers else None,
                "max": max(numbers) if numbers else None,
            }
        result["cases"][case] = case_result
    return result


def _summary_rows(
    evaluations: Mapping[str, Mapping[str, Mapping[str, Any]]], config: Mapping[str, Any]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in config["cases"]:
        for arm in (config["arms"]["treatment"], *config["arms"]["controls"]):
            evaluation = evaluations[case][arm]
            metrics = evaluation.get("metrics") or {}
            cost = metrics.get("comparison_cost") or {}
            candidate = evaluation.get("candidate", {})
            row = {
                "case": case,
                "arm": arm,
                "status": evaluation.get("status"),
                "candidate_pair_count": candidate.get("candidate_pair_count"),
                "eligible_pair_count": candidate.get("eligible_pair_count"),
                "ineligible_pair_count": candidate.get("ineligible_pair_count"),
                "candidate_comparisons": evaluation.get("candidate_comparisons"),
                "candidate_alignment_cells": evaluation.get("candidate_alignment_cells"),
                "on_demand_comparisons": cost.get("on_demand_comparison_count"),
                "on_demand_alignment_cells": cost.get("on_demand_alignment_cells"),
                "total_comparisons": cost.get("total_detailed_comparisons"),
                "total_alignment_cells": cost.get("total_alignment_cells"),
                "TP": metrics.get("TP"),
                "FP": metrics.get("FP"),
                "FN": metrics.get("FN"),
                "TN": metrics.get("TN"),
                "precision": metrics.get("precision"),
                "recall": metrics.get("recall"),
                "f1": metrics.get("f1"),
                "macro_R": metrics.get("macro_origin_recall"),
                "exact_group_rate": metrics.get("exact_group_rate"),
            }
            rows.append(row)
    return rows


def _csv_value(value: Any) -> Any:
    return "NA" if value is None else value


def _write_summary_csv(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    rows = list(rows)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(SUMMARY_FIELDS), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in SUMMARY_FIELDS})


def _sensitivity_sidecar(
    evaluations: Mapping[str, Mapping[str, Mapping[str, Any]]],
    labels: Mapping[str, Mapping[str, Mapping[str, Any]]],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "study": config.get("study"),
        "same_prediction_for_both_labels": True,
        "original_is_secondary": True,
    }
    for case in config.get("quality_metrics", {}).get("source_corrected_sensitivity", {}).get("cases", ("fd", "zoxide")):
        if case not in evaluations:
            continue
        case_rows = []
        for arm, evaluation in evaluations[case].items():
            if evaluation.get("status") not in ARM_TERMINAL_STATES:
                continue
            primary_join = evaluation.get("label", {}).get("join", {})
            secondary_join = evaluation.get("secondary_label", {}).get("join", {})
            primary_metrics = evaluation.get("metrics")
            secondary_metrics = evaluation.get("secondary_metrics")
            case_rows.append(
                {
                    "arm": arm,
                    "status": evaluation.get("status"),
                    "prediction_sha256": evaluation.get("metadata", {}).get("prediction_sha256"),
                    "primary_label_join": primary_join,
                    "secondary_label_join": secondary_join,
                    "primary": _compact_metrics(primary_metrics),
                    "secondary": _compact_metrics(secondary_metrics),
                    "primary_minus_secondary": {
                        field: _delta(
                            (primary_metrics or {}).get("macro_origin_recall") if field == "macro_R" else (primary_metrics or {}).get(field),
                            (secondary_metrics or {}).get("macro_origin_recall") if field == "macro_R" else (secondary_metrics or {}).get(field),
                        )
                        for field in SENSITIVITY_FIELDS
                    },
                    "same_prediction": bool(
                        evaluation.get("status") == "completed"
                        and evaluation.get("metadata", {}).get("prediction_sha256")
                    ),
                }
            )
        result[case] = {
            "primary": _label_descriptor(labels[case].get("primary", {})),
            "secondary": _label_descriptor(labels[case].get("secondary_original", {})),
            "rows": case_rows,
        }
    return result


def _provenance_sidecar(
    *, output: Path, snapshot: Mapping[str, Any], config: Mapping[str, Any], labels: Mapping[str, Any], evaluations: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "study": config.get("study"),
        "evaluator_sha256": sha256_file(Path(__file__)),
        "config": _source_record(output / "config.json"),
        "protocol": _source_record(output / "protocol.md"),
        "snapshot": _source_record(output / "snapshot.json"),
        "reference_inputs": snapshot.get("reference", {}).get("reference_inputs"),
        "labels": {
            case: {role: _label_descriptor(label) for role, label in case_labels.items()}
            for case, case_labels in labels.items()
        },
        "runs": {
            case: {
                arm: {
                    "status": evaluation.get("status"),
                    "candidate_sha256": evaluation.get("metadata", {}).get("candidate_sha256"),
                    "prediction_sha256": evaluation.get("metadata", {}).get("prediction_sha256"),
                }
                for arm, evaluation in case_evals.items()
            }
            for case, case_evals in evaluations.items()
        },
    }


def score_all(
    *,
    output: Path = HERE,
    reference: Path = REFERENCE,
    cases: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Score all terminal arm outputs and write relation-control sidecars."""

    output, reference = Path(output), Path(reference)
    config = read_json(output / "config.json")
    snapshot = validate_snapshot(output=output, reference=reference, config=config)
    reference_inputs_path = Path(
        str(snapshot["reference"]["reference_inputs"]["path"])
    )
    reference_inputs = read_json(reference_inputs_path)
    selected_cases = tuple(cases) if cases is not None else tuple(config["cases"])
    unknown = sorted(set(selected_cases) - set(config["cases"]))
    if unknown:
        raise ValueError(f"unknown relation-control case(s): {unknown}")

    treatment = config["arms"]["treatment"]
    arm_names = (treatment, *config["arms"]["controls"])
    # Verify every run and read every prediction before loading any label.
    runs: dict[str, dict[str, dict[str, Any]]] = {}
    for case in selected_cases:
        case_runs: dict[str, dict[str, Any]] = {}
        for arm in arm_names:
            run_dir = output / "runs" / case / arm
            metadata_path = run_dir / "metadata.json"
            if not metadata_path.is_file():
                raise ValueError(f"missing terminal metadata: {case}/{arm}")
            metadata = read_json(metadata_path)
            candidate_path = _candidate_path(
                output=output,
                reference=reference,
                snapshot=snapshot,
                case=case,
                arm=arm,
                treatment=treatment,
            )
            if not candidate_path.is_file():
                raise ValueError(f"missing candidate artifact: {case}/{arm}")
            candidate_sha = sha256_file(candidate_path)
            prediction_path = run_dir / "prediction.json" if metadata.get("status") == "completed" else None
            errors = _run_identity_errors(
                metadata,
                case=case,
                arm=arm,
                candidate_path=candidate_path,
                candidate_sha=candidate_sha,
                prediction_path=prediction_path,
                output=output,
                snapshot=snapshot,
                config=config,
            )
            if errors:
                raise ValueError(f"run identity validation failed for {case}/{arm}: {'; '.join(errors)}")
            prediction = read_json(prediction_path) if prediction_path is not None else None
            candidate = read_json(candidate_path)
            case_runs[arm] = {
                "metadata": metadata,
                "candidate": candidate,
                "candidate_path": candidate_path,
                "candidate_sha": candidate_sha,
                "prediction": prediction,
                "prediction_path": prediction_path,
            }
        runs[case] = case_runs

    labels: dict[str, dict[str, dict[str, Any]]] = {}
    evaluations: dict[str, dict[str, dict[str, Any]]] = {}
    for case in selected_cases:
        case_snapshot = snapshot["reference"]["cases"][case]
        body_path = Path(str(case_snapshot["body"]["path"]))
        bodies = load_bodies(body_path)
        label_case: dict[str, dict[str, Any]] = {}
        primary = _load_label_plan(config, reference_inputs, case, "primary")
        secondary = _load_label_plan(config, reference_inputs, case, "secondary_original")
        if secondary.get("same_as_primary"):
            secondary = dict(primary)
            secondary["role"] = "secondary_original"
            secondary["same_as_primary"] = True
        label_case["primary"] = primary
        label_case["secondary_original"] = secondary
        labels[case] = label_case
        target_ids = _target_ids(runs[case][treatment]["candidate"]["universe"], "treatment candidate")
        body_ids = tuple(sorted(bodies))
        if body_ids != target_ids:
            raise ValueError(f"{case}: body and candidate target universes differ")
        primary_join = _label_join(
            primary,
            case=case,
            candidate=runs[case][treatment]["candidate"],
            target_ids=target_ids,
            reference_inputs=reference_inputs,
        )
        secondary_join = (
            primary_join
            if secondary.get("same_as_primary")
            else _label_join(
                secondary,
                case=case,
                candidate=runs[case][treatment]["candidate"],
                target_ids=target_ids,
                reference_inputs=reference_inputs,
            )
        )
        primary["join"] = primary_join
        secondary["join"] = secondary_join
        eligible = {
            member
            for member, body in bodies.items()
            if not endpoint_reasons(body)
        }
        c3_records = runs[case][treatment]["candidate"].get("pairs", ())
        c3_pairs = _pair_set(c3_records)
        c3_stats = _candidate_stats(runs[case][treatment]["candidate"], bodies)
        c3_nominal = c3_stats["nominal_alignment_cells_by_stratum"]
        selection = read_json(output / "selection" / f"{case}.json")
        case_evaluations: dict[str, dict[str, Any]] = {}
        for arm, run in runs[case].items():
            candidate = run["candidate"]
            candidate_error_list = _candidate_identity_errors(
                candidate,
                case=case,
                arm=arm,
                treatment=treatment,
                target_ids=target_ids,
                expected_body_sha=case_snapshot["body"]["sha256"],
                expected_fixture_sha=reference_inputs["cases"][case]["fixture"]["sha256"],
            )
            expected_candidate_hash = None
            if arm == treatment:
                expected_candidate_hash = config.get("candidate_sha256", {}).get(case, {}).get("c3")
            else:
                expected_candidate_hash = snapshot.get("controls", {}).get(case, {}).get(arm)
            if expected_candidate_hash and run["candidate_sha"] != expected_candidate_hash:
                candidate_error_list.append("candidate_file_hash_mismatch")
            if candidate_error_list:
                raise ValueError(f"candidate validation failed for {case}/{arm}: {'; '.join(candidate_error_list)}")

            candidate_stat = _candidate_stats(candidate, bodies, c3_nominal=c3_nominal)
            if arm != treatment:
                selection_errors = _selection_match_errors(c3_stats, candidate_stat)
                if selection_errors:
                    raise ValueError(
                        f"selection quota validation failed for {case}/{arm}: "
                        + "; ".join(selection_errors)
                    )
            candidate_pair_set = _pair_set(candidate.get("pairs", ()))
            run_metadata = run["metadata"]
            demand = run_metadata.get("demand", {})
            selection_stat = _selection_stats(
                selection, arm, treatment, candidate_pair_set, c3_pairs
            )
            evaluation: dict[str, Any] = {
                "case": case,
                "arm": arm,
                "status": run_metadata["status"],
                "metadata": run_metadata,
                "evaluator_sha256": sha256_file(Path(__file__)),
                "candidate": candidate_stat,
                "candidate_comparisons": demand.get("comparisons"),
                "candidate_alignment_cells": demand.get("alignment_cells"),
                "selection": selection_stat,
                "label": {
                    "role": "primary",
                    "descriptor": _label_descriptor(primary),
                    "join": primary_join,
                },
                "secondary_label": {"join": secondary_join},
                "metrics": None,
                "candidate_positive_pairs": None,
                "candidate_positive_recall": None,
            }
            prediction = run["prediction"]
            if prediction is not None:
                prediction_errors = _prediction_identity_errors(
                    prediction,
                    candidate=candidate,
                    candidate_sha=run["candidate_sha"],
                    body_sha=case_snapshot["body"]["sha256"],
                    expected_policy=config.get("policy", {}),
                )
                if prediction_errors:
                    raise ValueError(f"prediction validation failed for {case}/{arm}: {'; '.join(prediction_errors)}")
            if primary_join["status"] == "ok":
                gt = primary["ground_truth_data"]
                audit = primary["linkage_data"]
                positive = truth_index(target_ids, audit)[2]
                candidate_positive = len(positive & candidate_pair_set)
                evaluation["candidate_positive_pairs"] = candidate_positive
                evaluation["candidate_positive_recall"] = candidate_positive / len(positive) if positive else None
                if prediction is not None:
                    evaluation["metrics"] = _label_quality(
                        prediction, candidate, gt, audit, eligible=eligible
                    )
            if prediction is not None and secondary_join["status"] == "ok":
                evaluation["secondary_metrics"] = _label_quality(
                    prediction,
                    candidate,
                    secondary["ground_truth_data"],
                    secondary["linkage_data"],
                    eligible=eligible,
                )
            else:
                evaluation["secondary_metrics"] = None
            case_evaluations[arm] = evaluation
        evaluations[case] = case_evaluations

    selected_config = {**config, "cases": list(selected_cases)}
    primary_sidecar = _primary_sidecar(evaluations, selected_config)
    for case in selected_cases:
        row = primary_sidecar["cases"][case]
        for arm, evaluation in evaluations[case].items():
            if arm == row["control_arm"]:
                evaluation["primary_delta_vs_C3"] = row["deltas"]
            else:
                evaluation["primary_delta_vs_C3"] = None

    summary_rows = _summary_rows(evaluations, {**config, "cases": list(selected_cases)})
    for case in selected_cases:
        results = [evaluations[case][arm] for arm in arm_names]
        write_json_once(output / f"{case}-results.json", results)
        for evaluation in results:
            write_json_once(
                output / "runs" / case / evaluation["arm"] / "evaluation.json", evaluation
            )
    _write_summary_csv(output / "results-summary.csv", summary_rows)
    write_json_once(output / "random5-summary.json", _random5_sidecar(evaluations, selected_config))
    write_json_once(output / "primary-deltas.json", primary_sidecar)
    write_json_once(output / "source-corrected-sensitivity.json", _sensitivity_sidecar(evaluations, labels, selected_config))
    write_json_once(output / "candidate-diagnostics.json", {
        "study": config.get("study"),
        "cases": {
            case: {arm: evaluation["candidate"] for arm, evaluation in evaluations[case].items()}
            for case in selected_cases
        },
    })
    write_json_once(output / "provenance.json", _provenance_sidecar(output=output, snapshot=snapshot, config=config, labels=labels, evaluations=evaluations))
    return {
        "status": "scored",
        "cases": list(selected_cases),
        "rows": len(summary_rows),
        "summary_csv": str(output / "results-summary.csv"),
    }


def score(case: str, *, output: Path = HERE, reference: Path = REFERENCE) -> dict[str, Any]:
    """Compatibility wrapper for scoring one frozen case."""

    return score_all(output=output, reference=reference, cases=(case,))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE)
    parser.add_argument("--reference", type=Path, default=REFERENCE)
    parser.add_argument("--case", action="append", dest="cases")
    args = parser.parse_args()
    print(json.dumps(score_all(output=args.output, reference=args.reference, cases=args.cases), indent=2))


if __name__ == "__main__":
    main()
