"""F4.5: diagnose whether body evidence can split one V0 collision cluster.

This module deliberately keeps the V0 partition and the GT separate:

* V0 (fixture + CG-WL) chooses the cluster and its member IDs.
* body evidence scores every pair in that cluster.
* ground truth is read only after the pair universe has been fixed, and is
  used only to label pairs for the diagnostic counts.

The output is a diagnostic, not F5.  It does not change the CallKin
partition and it does not use origin labels to select or merge a cluster.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from body_similarity import (  # noqa: E402
    FunctionBody,
    body_evidence_sha256,
    compare_bodies,
    load_body_evidence,
)
from engine import CG_WL_MODES, run_cg_wl  # noqa: E402
from loader import load_case  # noqa: E402
from paths import (  # noqa: E402
    ANALYSIS_TRACKS,
    ANCHOR_POLICIES,
    CANDIDATE_SCOPES,
    DEFAULT_BUILD,
    DEFAULT_PROFILE,
    f45_partition_for,
    f45_result_for,
    normalize_build,
    normalize_profile,
    resolve_fixture_json,
)


PARTITION_SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 1
PARTITION_ID_PREFIX = "cluster_"
DEFAULT_CLUSTER_SIZE = 325
DEFAULT_THRESHOLD = 0.80
DEFAULT_EXPECTED_SAME_PAIRS = 318
DEFAULT_EXPECTED_DIFFERENT_PAIRS = 52332
F45_DEFAULT_MODE = "out-in"
F45_DEFAULT_TRACK = "angr"
F45_DEFAULT_CANDIDATE_SCOPE = "rust-nonstd"
F45_DEFAULT_ANCHOR_POLICY = "role"

# These definitions are intentionally pre-registered and visible in every
# report.  ``compare_bodies`` already removes concrete call identities from
# normalized instructions, so these are local body features only.  The
# structure condition is deliberately split into three layers:
# instruction evidence, block alignment, and CFG evidence.  Slot evidence is
# kept separate so the ablation cannot silently re-introduce opcode/sequence
# features into ``slot_only``.
STRUCTURE_COMPONENTS = (
    # Instruction layer.
    "instruction_count_ratio",
    "mnemonic_multiset_jaccard",
    "mnemonic_ngram_jaccard",
    "sequence_ratio",
    # Block layer.
    "aligned_block_ratio",
    "aligned_instruction_ratio",
    # CFG layer.
    "edge_consistency",
    "cfg_block_count_ratio",
    "cfg_edge_count_ratio",
    "cfg_color_multiset_jaccard",
)
SLOT_COMPONENTS = (
    "constant_slot_consistency",
    "call_slot_shape_consistency",
    "data_reference_consistency",
)


def _canonical_members(members: Iterable[str]) -> tuple[str, ...]:
    values = list(members)
    if not values:
        raise ValueError("cluster must contain at least one member")
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("cluster members must be non-empty strings")
    if len(set(values)) != len(values):
        duplicates = sorted(
            item for item, count in Counter(values).items() if count > 1
        )
        raise ValueError(f"duplicate cluster member(s): {duplicates}")
    return tuple(sorted(values))


def _member_list_digest(members: Sequence[str]) -> str:
    canonical = json.dumps(
        list(members),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def cluster_id_for_members(members: Iterable[str]) -> str:
    """Return the stable identity of a cluster, independent of list order."""

    canonical = _canonical_members(members)
    return f"{PARTITION_ID_PREFIX}{_member_list_digest(canonical)}"


def build_partition_artifact(
    *,
    case: str,
    build: str,
    profile: str,
    mode: str,
    clusters: Mapping[str, Iterable[str]] | Iterable[Iterable[str]],
    source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Canonicalize V0 clusters and discard temporary numeric names.

    ``clusters`` accepts either the engine's list of member lists or a
    mapping such as ``{"C212": [...]}``.  Mapping keys are deliberately not
    copied into the artifact; only the member-list hash is an identity.
    """

    if mode not in CG_WL_MODES:
        raise ValueError(f"unknown CG-WL mode: {mode!r}")
    if not isinstance(case, str) or not case:
        raise ValueError("case must be a non-empty string")
    build = normalize_build(build)
    profile = normalize_profile(profile)

    raw_clusters = (
        list(clusters.values())
        if isinstance(clusters, Mapping)
        else list(clusters)
    )
    records = []
    seen_members: set[str] = set()
    seen_ids: set[str] = set()
    for raw_members in raw_clusters:
        members = _canonical_members(raw_members)
        overlap = seen_members.intersection(members)
        if overlap:
            raise ValueError(f"partition clusters overlap: {sorted(overlap)}")
        seen_members.update(members)
        digest = _member_list_digest(members)
        cluster_id = f"{PARTITION_ID_PREFIX}{digest}"
        if cluster_id in seen_ids:
            raise ValueError(f"duplicate partition cluster id: {cluster_id}")
        seen_ids.add(cluster_id)
        records.append({
            "id": cluster_id,
            "members": list(members),
            "member_count": len(members),
            "member_list_sha256": digest,
        })

    records.sort(key=lambda item: item["id"])
    artifact: dict[str, Any] = {
        "schema_version": PARTITION_SCHEMA_VERSION,
        "case": case,
        "build": build,
        "profile": profile,
        "mode": mode,
        "identity": "sha256(canonical sorted member list)",
        "clusters": records,
    }
    if source is not None:
        artifact["source"] = dict(source)
    return artifact


def validate_partition_artifact(artifact: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "case",
        "build",
        "profile",
        "mode",
        "identity",
        "clusters",
    }
    allowed = required | {"source"}
    if not isinstance(artifact, Mapping):
        raise ValueError("partition artifact must be an object")
    missing = required - set(artifact)
    unknown = set(artifact) - allowed
    if missing:
        raise ValueError(f"partition artifact missing field(s): {sorted(missing)}")
    if unknown:
        raise ValueError(f"partition artifact has unknown field(s): {sorted(unknown)}")
    if artifact["schema_version"] != PARTITION_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported partition schema_version: {artifact['schema_version']}"
        )
    if not isinstance(artifact["case"], str) or not artifact["case"]:
        raise ValueError("partition case must be a non-empty string")
    normalize_build(artifact["build"])
    normalize_profile(artifact["profile"])
    if artifact["mode"] not in CG_WL_MODES:
        raise ValueError(f"invalid partition mode: {artifact['mode']!r}")
    if artifact["identity"] != "sha256(canonical sorted member list)":
        raise ValueError("unsupported partition identity definition")
    clusters = artifact["clusters"]
    if not isinstance(clusters, list) or not clusters:
        raise ValueError("partition clusters must be a non-empty list")

    seen_ids: set[str] = set()
    seen_members: set[str] = set()
    for index, record in enumerate(clusters):
        where = f"clusters[{index}]"
        if not isinstance(record, Mapping) or set(record) != {
            "id", "members", "member_count", "member_list_sha256"
        }:
            raise ValueError(
                f"{where} must contain id/members/member_count/member_list_sha256"
            )
        members = _canonical_members(record["members"])
        expected_digest = _member_list_digest(members)
        expected_id = f"{PARTITION_ID_PREFIX}{expected_digest}"
        if record["id"] != expected_id:
            raise ValueError(f"{where}.id does not match its member-list hash")
        if record["member_count"] != len(members):
            raise ValueError(f"{where}.member_count does not match members")
        if record["member_list_sha256"] != expected_digest:
            raise ValueError(f"{where}.member_list_sha256 does not match members")
        if record["id"] in seen_ids:
            raise ValueError(f"duplicate partition cluster id: {record['id']}")
        overlap = seen_members.intersection(members)
        if overlap:
            raise ValueError(f"partition clusters overlap: {sorted(overlap)}")
        seen_ids.add(record["id"])
        seen_members.update(members)


def load_partition_artifact(path: str | Path) -> dict[str, Any]:
    artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_partition_artifact(artifact)
    return dict(artifact)


def write_partition_artifact(path: str | Path, artifact: Mapping[str, Any]) -> None:
    validate_partition_artifact(artifact)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def partition_from_fixture(fixture_path: str | Path, *, mode: str) -> dict[str, Any]:
    """Run V0 once and persist exactly the scored member partition."""

    fixture = Path(fixture_path)
    case = load_case(str(fixture))
    result = run_cg_wl(case, mode=mode)
    return build_partition_artifact(
        case=case.case,
        build=case.build,
        profile=case.profile,
        mode=mode,
        clusters=result.clusters,
        source={
            "kind": "v0-cg-wl",
            "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
            "fixture_schema_version": case.schema_version,
            "v0_rounds": result.rounds,
            "analysis": (
                case.analysis.to_dict() if case.analysis is not None else None
            ),
        },
    )


def select_cluster(
    partition: Mapping[str, Any],
    *,
    cluster_id: str | None = None,
    cluster_size: int | None = DEFAULT_CLUSTER_SIZE,
) -> dict[str, Any]:
    validate_partition_artifact(partition)
    clusters = partition["clusters"]
    if cluster_id is not None:
        matches = [item for item in clusters if item["id"] == cluster_id]
        if not matches:
            raise ValueError(f"cluster id not present in partition: {cluster_id}")
        return dict(matches[0])
    if cluster_size is None:
        raise ValueError("provide --cluster-id or --cluster-size")
    if cluster_size < 1:
        raise ValueError("cluster size must be positive")
    matches = [item for item in clusters if item["member_count"] == cluster_size]
    if not matches:
        sizes = sorted(item["member_count"] for item in clusters)
        raise ValueError(
            f"no cluster has {cluster_size} members; available sizes: {sizes}"
        )
    if len(matches) > 1:
        raise ValueError(
            f"{len(matches)} clusters have {cluster_size} members; use --cluster-id"
        )
    return dict(matches[0])


def _ground_truth_index(ground_truth: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(ground_truth, Mapping):
        raise ValueError("ground truth must be an object")
    origins = ground_truth.get("origins")
    if not isinstance(origins, list) or not origins:
        raise ValueError("ground truth origins must be a non-empty list")
    origin_by_member: dict[str, str] = {}
    seen_origins: set[str] = set()
    for index, group in enumerate(origins):
        if not isinstance(group, Mapping) or set(group) != {"origin", "members"}:
            raise ValueError(f"ground_truth.origins[{index}] has an invalid schema")
        origin = group["origin"]
        if not isinstance(origin, str) or not origin:
            raise ValueError(f"ground_truth.origins[{index}].origin is invalid")
        if origin in seen_origins:
            raise ValueError(f"duplicate ground-truth origin: {origin}")
        seen_origins.add(origin)
        members = group["members"]
        if not isinstance(members, list):
            raise ValueError(f"ground_truth.origins[{index}].members must be a list")
        for member in members:
            if not isinstance(member, str) or not member:
                raise ValueError("ground-truth member IDs must be non-empty strings")
            if member in origin_by_member:
                raise ValueError(f"ground-truth member appears twice: {member}")
            origin_by_member[member] = origin
    return origin_by_member


def _validate_join_metadata(
    partition: Mapping[str, Any],
    body_artifact: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
) -> None:
    for label, data in (("body evidence", body_artifact), ("ground truth", ground_truth)):
        for key in ("case", "build", "profile"):
            if key in data and data[key] != partition[key]:
                raise ValueError(
                    f"{label}/{key} mismatch: {data[key]!r} != {partition[key]!r}"
                )
    if "scope" in body_artifact and "scope" in ground_truth:
        if body_artifact["scope"] != ground_truth["scope"]:
            raise ValueError("body evidence/ground truth scope mismatch")
    partition_source = partition.get("source")
    partition_analysis = (
        partition_source.get("analysis")
        if isinstance(partition_source, Mapping)
        else None
    )
    body_provenance = body_artifact.get("provenance", {})
    gt_provenance = ground_truth.get("provenance", {})
    if (
        isinstance(partition_source, Mapping)
        and isinstance(body_provenance, Mapping)
        and partition_source.get("fixture_sha256")
        and body_provenance.get("fixture_sha256")
        and partition_source["fixture_sha256"] != body_provenance["fixture_sha256"]
    ):
        raise ValueError("partition/body fixture provenance mismatch")
    if (
        isinstance(body_provenance, Mapping)
        and isinstance(gt_provenance, Mapping)
        and body_provenance.get("stripped_sha256")
        and gt_provenance.get("stripped_sha256")
        and body_provenance["stripped_sha256"] != gt_provenance["stripped_sha256"]
    ):
        raise ValueError("body evidence/ground truth stripped binary mismatch")
    if isinstance(partition_analysis, Mapping):
        if "candidate_scope" in partition_analysis and "scope" in body_artifact:
            if partition_analysis["candidate_scope"] != body_artifact["scope"]:
                raise ValueError(
                    "partition/body candidate scope provenance mismatch"
                )
        if not isinstance(body_provenance, Mapping):
            raise ValueError("body evidence is missing provenance")
        for key in ("raw_graph_sha256", "candidate_selection_sha256"):
            expected = partition_analysis.get(key)
            actual = body_provenance.get(key)
            if not expected:
                raise ValueError(f"partition analysis is missing {key}")
            if not actual:
                raise ValueError(f"body evidence provenance is missing {key}")
            if actual != expected:
                raise ValueError(f"partition/body {key} mismatch")


def _validate_requested_partition_config(
    partition: Mapping[str, Any],
    *,
    track: str,
    candidate_scope: str,
    anchor_policy: str,
    mode: str,
) -> None:
    if partition["mode"] != mode:
        raise ValueError(
            f"partition/mode mismatch: {partition['mode']!r} != {mode!r}"
        )
    source = partition.get("source")
    analysis = source.get("analysis") if isinstance(source, Mapping) else None
    if not isinstance(analysis, Mapping):
        return
    expected = {
        "track": track,
        "candidate_scope": candidate_scope,
        "anchor_policy": anchor_policy,
    }
    for key, value in expected.items():
        if key in analysis and analysis[key] != value:
            raise ValueError(
                f"partition/{key} mismatch: {analysis[key]!r} != {value!r}"
            )


def _data_references(body: FunctionBody) -> Counter[tuple[Any, ...]]:
    """Return normalized data-reference slots, without call identities."""

    return Counter(
        (
            slot.get("kind"),
            slot.get("status"),
            slot.get("value"),
            slot.get("resolver"),
        )
        for instruction in body.instructions
        for slot in instruction.get("slots", ())
        if slot.get("kind") == "data"
    )


def _data_reference_consistency(
    first: FunctionBody,
    second: FunctionBody,
) -> float:
    return _counter_jaccard(_data_references(first), _data_references(second))


def _counter_jaccard(left: Counter[Any], right: Counter[Any]) -> float:
    union = sum((left | right).values())
    return sum((left & right).values()) / union if union else 1.0


def _cfg_colors(body: FunctionBody) -> dict[str, tuple[Any, ...]]:
    """Compute label-free CFG colors without reading an instruction token."""

    labels = [block["label"] for block in body.blocks]
    if not labels:
        return {}
    label_set = set(labels)
    outgoing: dict[str, list[tuple[str, str]]] = {label: [] for label in labels}
    incoming: dict[str, list[tuple[str, str]]] = {label: [] for label in labels}
    for edge in body.edges:
        source = edge["source"]
        target = edge["target"]
        kind = edge.get("kind", "unknown")
        if source not in label_set:
            continue
        outgoing[source].append((kind, target))
        if target in label_set:
            incoming[target].append((kind, source))

    entry = "B0" if "B0" in label_set else min(labels)
    colors: dict[str, tuple[Any, ...]] = {}
    for label in labels:
        colors[label] = (
            label == entry,
            tuple(sorted(kind for kind, _target in outgoing[label])),
            tuple(sorted(kind for kind, _source in incoming[label])),
            not outgoing[label],
        )

    # A bounded local refinement is enough for a pairwise diagnostic and
    # keeps a large collision cluster tractable.  Edges to EXIT/OPAQUE remain
    # explicit terminal symbols; no opcode or operand is consulted.
    for _round in range(min(max(len(labels), 1), 8)):
        refined: dict[str, tuple[Any, ...]] = {}
        for label in labels:
            out_signature = tuple(
                sorted(
                    (
                        (
                            kind,
                            colors[target]
                            if target in label_set
                            else ("external", target),
                        )
                        for kind, target in outgoing[label]
                    ),
                    key=repr,
                )
            )
            in_signature = tuple(
                sorted(
                    (
                        (kind, colors[source])
                        for kind, source in incoming[label]
                    ),
                    key=repr,
                )
            )
            refined[label] = (colors[label], out_signature, in_signature)
        colors = refined
    return colors


def _cfg_features(first: FunctionBody, second: FunctionBody) -> dict[str, float]:
    return _cfg_features_from_profiles(_cfg_profile(first), _cfg_profile(second))


def _cfg_profile(body: FunctionBody) -> dict[str, Any]:
    return {
        "block_count": len(body.blocks),
        "edge_count": len(body.edges),
        "colors": Counter(_cfg_colors(body).values()),
    }


def _cfg_features_from_profiles(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
) -> dict[str, float]:
    first_block_count = int(first["block_count"])
    second_block_count = int(second["block_count"])
    first_edge_count = int(first["edge_count"])
    second_edge_count = int(second["edge_count"])
    first_colors = first["colors"]
    second_colors = second["colors"]
    union = sum((first_colors | second_colors).values())
    return {
        "cfg_block_count_ratio": (
            min(first_block_count, second_block_count)
            / max(first_block_count, second_block_count)
            if max(first_block_count, second_block_count)
            else 1.0
        ),
        "cfg_edge_count_ratio": (
            min(first_edge_count, second_edge_count)
            / max(first_edge_count, second_edge_count)
            if max(first_edge_count, second_edge_count)
            else 1.0
        ),
        "cfg_color_multiset_jaccard": (
            sum((first_colors & second_colors).values()) / union
            if union else 1.0
        ),
    }


def _score_components(comparison: Mapping[str, Any]) -> dict[str, float]:
    structure_values = [float(comparison[name]) for name in STRUCTURE_COMPONENTS]
    slot_values = [float(comparison[name]) for name in SLOT_COMPONENTS]
    structure_score = min(structure_values) if structure_values else 0.0
    slot_score = min(slot_values) if slot_values else 0.0
    return {
        "structure_only": structure_score,
        "slot_only": slot_score,
        "combined": min(structure_score, slot_score),
    }


def _percentile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        return 0.0
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = position - lower
    return (
        sorted_values[lower] * (1.0 - fraction)
        + sorted_values[upper] * fraction
    )


def _histogram(values: Sequence[float]) -> dict[str, int]:
    counts = {f"{index / 10:.1f}-{(index + 1) / 10:.1f}": 0 for index in range(10)}
    for value in values:
        index = min(9, max(0, int(value * 10)))
        label = f"{index / 10:.1f}-{(index + 1) / 10:.1f}"
        counts[label] += 1
    return counts


def _distribution(values: Sequence[float]) -> dict[str, Any]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {
            "count": 0,
            "min": None,
            "p05": None,
            "p25": None,
            "median": None,
            "p75": None,
            "p95": None,
            "max": None,
            "mean": None,
            "histogram": _histogram(ordered),
        }
    return {
        "count": len(ordered),
        "min": ordered[0],
        "p05": _percentile(ordered, 0.05),
        "p25": _percentile(ordered, 0.25),
        "median": statistics.median(ordered),
        "p75": _percentile(ordered, 0.75),
        "p95": _percentile(ordered, 0.95),
        "max": ordered[-1],
        "mean": statistics.fmean(ordered),
        "histogram": _histogram(ordered),
    }


def _example(row: Mapping[str, Any], *, expected: str) -> dict[str, Any]:
    return {
        "pair": list(row["pair"]),
        "expected": expected,
        "origins": list(row["origins"]),
        "score": row["scores"][row["condition"]],
        "metrics": dict(row["metrics"]),
    }


def _condition_report(
    rows: Sequence[Mapping[str, Any]],
    *,
    condition: str,
    threshold: float,
    examples_per_type: int,
) -> dict[str, Any]:
    positive_scores = [
        row["scores"][condition]
        for row in rows
        if row["same_origin"]
    ]
    negative_scores = [
        row["scores"][condition]
        for row in rows
        if not row["same_origin"]
    ]
    tp = fp = fn = tn = 0
    false_positives = []
    false_negatives = []
    for original in rows:
        row = dict(original)
        row["condition"] = condition
        predicted_positive = row["scores"][condition] >= threshold
        if predicted_positive and row["same_origin"]:
            tp += 1
        elif predicted_positive:
            fp += 1
            false_positives.append(row)
        elif row["same_origin"]:
            fn += 1
            false_negatives.append(row)
        else:
            tn += 1

    false_positives.sort(
        key=lambda row: (-row["scores"][condition], tuple(row["pair"]))
    )
    false_negatives.sort(
        key=lambda row: (row["scores"][condition], tuple(row["pair"]))
    )
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    result = {
        "threshold": threshold,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "score_distribution": {
            "positive": _distribution(positive_scores),
            "negative": _distribution(negative_scores),
        },
        "false_positive_examples": [
            _example(row, expected="different-origin")
            for row in false_positives[:examples_per_type]
        ],
        "false_negative_examples": [
            _example(row, expected="same-origin")
            for row in false_negatives[:examples_per_type]
        ],
    }
    result["pairwise"] = {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
    }
    return result


def build_collision_report(
    *,
    partition: Mapping[str, Any],
    body_artifact: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
    cluster_id: str | None = None,
    cluster_size: int | None = DEFAULT_CLUSTER_SIZE,
    threshold: float = DEFAULT_THRESHOLD,
    structure_threshold: float | None = None,
    slot_threshold: float | None = None,
    integrated_threshold: float | None = None,
    expected_same_pairs: int | None = DEFAULT_EXPECTED_SAME_PAIRS,
    expected_different_pairs: int | None = DEFAULT_EXPECTED_DIFFERENT_PAIRS,
    examples_per_type: int = 5,
    body_sha256: str = "",
) -> dict[str, Any]:
    """Score every pair in one persisted V0 cluster.

    The cluster is selected before ``ground_truth`` is inspected.  The GT
    only supplies the same-origin/different-origin label for each already
    fixed pair, which prevents oracle-assisted cluster selection.
    """

    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    thresholds = {
        "structure_only": (
            threshold if structure_threshold is None else structure_threshold
        ),
        "slot_only": threshold if slot_threshold is None else slot_threshold,
        "combined": (
            threshold if integrated_threshold is None else integrated_threshold
        ),
    }
    if any(not 0.0 <= value <= 1.0 for value in thresholds.values()):
        raise ValueError("all thresholds must be between 0 and 1")
    if examples_per_type < 0:
        raise ValueError("examples_per_type must be non-negative")

    # This is intentionally the first operation involving the partition.
    cluster = select_cluster(
        partition,
        cluster_id=cluster_id,
        cluster_size=cluster_size,
    )
    members = tuple(cluster["members"])
    _validate_join_metadata(partition, body_artifact, ground_truth)
    origin_by_member = _ground_truth_index(ground_truth)
    missing_gt = sorted(set(members) - set(origin_by_member))
    if missing_gt:
        raise ValueError(f"selected cluster members missing from ground truth: {missing_gt}")

    bodies = load_body_evidence(body_artifact)
    missing_body = sorted(set(members) - set(bodies))
    if missing_body:
        raise ValueError(f"selected cluster members missing from body evidence: {missing_body}")
    incomplete = sorted(
        member for member in members if not bodies[member].complete
    )
    if incomplete:
        raise ValueError(
            "cannot compare incomplete body evidence for selected cluster: "
            f"{incomplete[:12]}{'...' if len(incomplete) > 12 else ''}"
        )

    pair_count = len(members) * (len(members) - 1) // 2
    same_origin_pairs = sum(
        1
        for first, second in combinations(members, 2)
        if origin_by_member[first] == origin_by_member[second]
    )
    different_origin_pairs = pair_count - same_origin_pairs
    if (
        expected_same_pairs is not None
        and same_origin_pairs != expected_same_pairs
    ):
        raise ValueError(
            "same-origin pair count mismatch: "
            f"observed {same_origin_pairs}, expected {expected_same_pairs}"
        )
    if (
        expected_different_pairs is not None
        and different_origin_pairs != expected_different_pairs
    ):
        raise ValueError(
            "different-origin pair count mismatch: "
            f"observed {different_origin_pairs}, expected {expected_different_pairs}"
        )

    cfg_profiles = {member: _cfg_profile(bodies[member]) for member in members}
    data_profiles = {member: _data_references(bodies[member]) for member in members}
    rows = []
    for first_id, second_id in combinations(members, 2):
        first = bodies[first_id]
        second = bodies[second_id]
        comparison = compare_bodies(first, second).to_dict()
        comparison.update(
            _cfg_features_from_profiles(
                cfg_profiles[first_id],
                cfg_profiles[second_id],
            )
        )
        comparison["data_reference_consistency"] = _counter_jaccard(
            data_profiles[first_id],
            data_profiles[second_id],
        )
        scores = _score_components(comparison)
        rows.append({
            "pair": (first_id, second_id),
            "same_origin": origin_by_member[first_id] == origin_by_member[second_id],
            "origins": (
                origin_by_member[first_id],
                origin_by_member[second_id],
            ),
            "scores": scores,
            "metrics": {
                key: value
                for key, value in comparison.items()
                if key != "pair"
            },
        })

    conditions = {
        condition: _condition_report(
            rows,
            condition=condition,
            threshold=thresholds[condition],
            examples_per_type=examples_per_type,
        )
        for condition in ("structure_only", "slot_only", "combined")
    }
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "artifact": "f4.5-collision-diagnostic",
        "case": partition["case"],
        "build": partition["build"],
        "profile": partition["profile"],
        "mode": partition["mode"],
        "cluster": {
            "id": cluster["id"],
            "member_count": len(members),
            "member_list_sha256": cluster["member_list_sha256"],
            "members": list(members),
        },
        "pair_count_formula": "member_count * (member_count - 1) // 2",
        "pair_count": pair_count,
        "ground_truth": {
            "used_for": "pair labels and scoring only",
            "origin_count": len({origin_by_member[member] for member in members}),
            "same_origin_pairs": same_origin_pairs,
            "different_origin_pairs": different_origin_pairs,
            "expected_same_origin_pairs": expected_same_pairs,
            "expected_different_origin_pairs": expected_different_pairs,
        },
        "score_definition": {
            "aggregation": "minimum component score",
            "structure_only": list(STRUCTURE_COMPONENTS),
            "slot_only": list(SLOT_COMPONENTS),
            "combined": "min(structure_only, slot_only)",
            "positive_when": "score >= threshold",
        },
        "thresholds": thresholds,
        "provenance": {
            "partition_source": partition.get("source", {}),
            "body_evidence_sha256": body_sha256,
            "gt_stripped_sha256": (
                ground_truth.get("provenance", {}).get("stripped_sha256", "")
                if isinstance(ground_truth.get("provenance", {}), Mapping)
                else ""
            ),
        },
        "conditions": conditions,
    }


def _read_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="F4.5: test whether body evidence splits one V0 collision cluster."
    )
    parser.add_argument("case")
    parser.add_argument("--build", default=DEFAULT_BUILD)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--mode", choices=CG_WL_MODES, default=F45_DEFAULT_MODE)
    parser.add_argument("--fixture")
    parser.add_argument("--partition-input")
    parser.add_argument("--partition-output")
    parser.add_argument(
        "--partition-only",
        action="store_true",
        help="only persist the V0 partition; do not load body/GT evidence",
    )
    parser.add_argument("--body-evidence")
    parser.add_argument("--ground-truth")
    parser.add_argument("--output")
    parser.add_argument("--cluster-id")
    parser.add_argument("--cluster-size", type=int, default=DEFAULT_CLUSTER_SIZE)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument(
        "--structure-threshold",
        "--cfg-threshold",
        dest="structure_threshold",
        type=float,
        help="threshold for the structure-only condition (cfg alias accepted)",
    )
    parser.add_argument("--slot-threshold", type=float)
    parser.add_argument("--integrated-threshold", type=float)
    parser.add_argument(
        "--expected-same-pairs",
        type=int,
        default=DEFAULT_EXPECTED_SAME_PAIRS,
    )
    parser.add_argument(
        "--expected-different-pairs",
        type=int,
        default=DEFAULT_EXPECTED_DIFFERENT_PAIRS,
    )
    parser.add_argument("--examples", type=int, default=5)
    # These three options only locate the default V0 fixture.  They do not
    # change the collision score itself.
    parser.add_argument("--track", choices=ANALYSIS_TRACKS, default=F45_DEFAULT_TRACK)
    parser.add_argument(
        "--candidate-scope",
        choices=CANDIDATE_SCOPES,
        default=F45_DEFAULT_CANDIDATE_SCOPE,
    )
    parser.add_argument(
        "--anchor-policy",
        choices=ANCHOR_POLICIES,
        default=F45_DEFAULT_ANCHOR_POLICY,
    )
    return parser


def _write_report(path: str | Path, report: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    build = normalize_build(args.build)
    profile = normalize_profile(args.profile)
    if args.fixture and args.partition_input:
        print("error: --fixture and --partition-input are mutually exclusive", file=sys.stderr)
        return 1
    if not args.fixture and not args.partition_input:
        args.fixture = resolve_fixture_json(
            args.case,
            build,
            profile,
            args.track,
            args.candidate_scope,
            args.anchor_policy,
        )
    partition_output = Path(
        args.partition_output
        or f45_partition_for(
            args.case,
            build,
            profile,
            args.mode,
            args.track,
            args.candidate_scope,
            args.anchor_policy,
        )
    )
    try:
        if args.partition_input:
            partition = load_partition_artifact(args.partition_input)
        else:
            partition = partition_from_fixture(args.fixture, mode=args.mode)
        _validate_requested_partition_config(
            partition,
            track=args.track,
            candidate_scope=args.candidate_scope,
            anchor_policy=args.anchor_policy,
            mode=args.mode,
        )
        write_partition_artifact(partition_output, partition)
        print(f"wrote V0 partition: {partition_output}")

        if args.partition_only:
            return 0
        if not args.body_evidence or not args.ground_truth:
            raise ValueError("--body-evidence and --ground-truth are required for analysis")
        body_path = Path(args.body_evidence)
        report = build_collision_report(
            partition=partition,
            body_artifact=_read_json(body_path),
            ground_truth=_read_json(args.ground_truth),
            cluster_id=args.cluster_id,
            cluster_size=args.cluster_size,
            threshold=args.threshold,
            structure_threshold=args.structure_threshold,
            slot_threshold=args.slot_threshold,
            integrated_threshold=args.integrated_threshold,
            expected_same_pairs=args.expected_same_pairs,
            expected_different_pairs=args.expected_different_pairs,
            examples_per_type=args.examples,
            body_sha256=body_evidence_sha256(body_path),
        )
        output_path = Path(
            args.output
            or f45_result_for(
                args.case,
                build,
                profile,
                args.mode,
                args.track,
                args.candidate_scope,
                args.anchor_policy,
            )
        )
        _write_report(output_path, report)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote collision report: {output_path}")
    print(
        f"cluster={report['cluster']['id']} "
        f"members={report['cluster']['member_count']} "
        f"pairs={report['pair_count']}"
    )
    for condition, result in report["conditions"].items():
        distribution = result["score_distribution"]
        print(
            f"{condition}: TP={result['tp']} FP={result['fp']} "
            f"FN={result['fn']} TN={result['tn']} "
            f"P={result['precision']} R={result['recall']} F1={result['f1']}"
        )
        print(
            f"  scores: positive[min={distribution['positive']['min']}, "
            f"p05={distribution['positive']['p05']}, "
            f"median={distribution['positive']['median']}, "
            f"p95={distribution['positive']['p95']}, "
            f"max={distribution['positive']['max']}] "
            f"negative[min={distribution['negative']['min']}, "
            f"p05={distribution['negative']['p05']}, "
            f"median={distribution['negative']['median']}, "
            f"p95={distribution['negative']['p95']}, "
            f"max={distribution['negative']['max']}]"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
