"""GT-blind matched controls for the retained body2/combined3 study.

The module deliberately keeps selection separate from F6.  Selection only
reads body2/C3 candidate records and local body metadata; old predictions are
used later only as a body-feature cache for replay checks.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from body_similarity import FunctionBody  # noqa: E402
from body_similarity import load_body_evidence  # noqa: E402
from v1_candidates import PairKey, validate_candidate_artifact  # noqa: E402
from v1_engine import (  # noqa: E402
    PairFeatures,
    PairPolicyConfig,
    build_family_artifact,
    pair_features_from_bodies,
)


ELIGIBLE = "complete/noopaque"
ABSTAIN = "abstain"
BODY2_VIEWS = ("token", "cfg")
RELATION_FLAGS = (
    "same_final_color",
    "same_prior_color",
    "same_out_signature",
    "same_in_signature",
)
FEATURE_FIELDS = (
    "structure_score",
    "aligned_instruction_ratio",
    "sequence_ratio",
    "mnemonic_multiset_jaccard",
    "constant_similarity",
    "call_shape_similarity",
    "data_reference_similarity",
    "both_complete",
    "opaque_indirect_jumps",
)

Stratum = tuple[str, Any]


def pair_from_record(record: Mapping[str, Any]) -> PairKey:
    values = record.get("pair")
    if not isinstance(values, list) or len(values) != 2:
        first, second = record.get("first"), record.get("second")
        values = [first, second]
    return PairKey.make(values[0], values[1])


def endpoint_reasons(body: FunctionBody | None) -> tuple[str, ...]:
    """Return all F6 abstain reasons observed for one endpoint."""

    if body is None:
        return ("missing",)
    reasons: list[str] = []
    if not body.complete:
        reasons.append("incomplete")
    if int(body.quality.get("opaque_indirect_jumps", 0)) > 0:
        reasons.append("opaque")
    return tuple(sorted(set(reasons)))


def _positive_cost_bin(cost: int) -> tuple[int, int]:
    if cost <= 0:
        raise ValueError("positive cost bin requires a positive cost")
    exponent = cost.bit_length() - 1
    base = 1 << exponent
    subdivision = ((cost - base) * 16) // base
    return exponent, subdivision


def pair_cost(pair: PairKey, bodies: Mapping[str, FunctionBody]) -> int:
    first, second = bodies.get(pair.left), bodies.get(pair.right)
    if first is None or second is None:
        return 0
    return len(first.instructions) * len(second.instructions)


def pair_stratum(pair: PairKey, bodies: Mapping[str, FunctionBody]) -> Stratum:
    """Return the frozen eligibility/cost stratum for one candidate pair."""

    reasons = tuple(
        sorted(
            {
                reason
                for member in (pair.left, pair.right)
                for reason in endpoint_reasons(bodies.get(member))
            }
        )
    )
    if reasons:
        return ABSTAIN, reasons
    cost = pair_cost(pair, bodies)
    if cost == 0:
        return ELIGIBLE, "cost0"
    return ELIGIBLE, _positive_cost_bin(cost)


def strata_counts(
    records: Iterable[Mapping[str, Any]],
    bodies: Mapping[str, FunctionBody],
) -> Counter[Stratum]:
    counts: Counter[Stratum] = Counter()
    for record in records:
        counts[pair_stratum(pair_from_record(record), bodies)] += 1
    return counts


def _stratum_json(stratum: Stratum) -> dict[str, Any]:
    eligibility, value = stratum
    if eligibility == ELIGIBLE:
        cost_bin: str | list[int] = (
            value if value == "cost0" else [int(value[0]), int(value[1])]
        )
        return {"eligibility": eligibility, "cost_bin": cost_bin}
    return {"eligibility": ABSTAIN, "reasons": list(value)}


def stratum_label(stratum: Stratum) -> str:
    return json.dumps(
        _stratum_json(stratum),
        sort_keys=True,
        separators=(",", ":"),
    )


def _record_pair_set(records: Iterable[Mapping[str, Any]]) -> set[PairKey]:
    return {pair_from_record(record) for record in records}


def _view_score(record: Mapping[str, Any], view: str) -> float:
    views = record.get("views")
    if not isinstance(views, Mapping):
        raise ValueError("body2 control record is missing named views")
    item = views.get(view)
    if not isinstance(item, Mapping) or "score" not in item:
        raise ValueError(f"body2 control record is missing {view} score")
    value = item["score"]
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise ValueError(f"invalid {view} score")
    return float(value)


def body_score(record: Mapping[str, Any]) -> tuple[float, float]:
    """Return the frozen descending min(token,cfg), then mean score."""

    token, cfg = _view_score(record, "token"), _view_score(record, "cfg")
    return min(token, cfg), (token + cfg) / 2.0


def _hash_order(
    seed: str,
    case: str,
    stratum: Stratum,
    pair: PairKey,
) -> str:
    payload = "\0".join(
        (seed, case, stratum_label(stratum), pair.left, pair.right)
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _selection_stats(
    selected: Sequence[Mapping[str, Any]],
    treatment: Sequence[Mapping[str, Any]],
    treatment_pairs: set[PairKey],
    quotas: Mapping[Stratum, int],
    pools: Mapping[Stratum, Sequence[Mapping[str, Any]]],
    bodies: Mapping[str, FunctionBody],
) -> dict[str, Any]:
    selected_counts = strata_counts(selected, bodies)
    treatment_counts = strata_counts(treatment, bodies)
    forced = [stratum for stratum, quota in quotas.items() if quota == len(pools[stratum])]
    candidate_comparisons = 0
    alignment_cells = 0
    for record in selected:
        pair = pair_from_record(record)
        if pair_stratum(pair, bodies)[0] != ELIGIBLE:
            continue
        candidate_comparisons += 1
        alignment_cells += pair_cost(pair, bodies)
    def cells_by_stratum(records: Sequence[Mapping[str, Any]]) -> Counter[Stratum]:
        result: Counter[Stratum] = Counter()
        for record in records:
            pair = pair_from_record(record)
            stratum = pair_stratum(pair, bodies)
            if stratum[0] == ELIGIBLE:
                result[stratum] += pair_cost(pair, bodies)
        return result

    treatment_cells = cells_by_stratum(treatment)
    selected_cells = cells_by_stratum(selected)

    nominal_cost: dict[str, Any] = {}
    strata_rows: list[dict[str, Any]] = []
    for stratum in sorted(quotas, key=stratum_label):
        c3_cells = treatment_cells[stratum]
        selected_stratum_cells = selected_cells[stratum]
        deviation = (
            abs(selected_stratum_cells - c3_cells) / c3_cells
            if c3_cells
            else 0.0
        )
        label = stratum_label(stratum)
        nominal_cost[label] = {
            "c3_alignment_cells": c3_cells,
            "selected_alignment_cells": selected_stratum_cells,
            "absolute_relative_deviation": deviation,
        }
        strata_rows.append(
            {
                **_stratum_json(stratum),
                "quota": quotas[stratum],
                "pool": len(pools[stratum]),
                "selected": selected_counts[stratum],
                "c3_count": treatment_counts[stratum],
                "forced": stratum in forced,
                "c3_alignment_cells": c3_cells,
                "selected_alignment_cells": selected_stratum_cells,
                "absolute_relative_cost_deviation": deviation,
                "nominal_cost_bound_ok": deviation <= 0.0625 + 1e-12,
            }
        )
    c3_total_cells = sum(item["c3_alignment_cells"] for item in nominal_cost.values())
    selected_total_cells = sum(
        item["selected_alignment_cells"] for item in nominal_cost.values()
    )
    total_deviation = (
        abs(selected_total_cells - c3_total_cells) / c3_total_cells
        if c3_total_cells
        else 0.0
    )
    overlap_count = sum(
        pair_from_record(record) in treatment_pairs for record in selected
    )
    forced_pair_count = sum(quotas[key] for key in forced)
    return {
        "selected_count": len(selected),
        "selected_strata": {
            stratum_label(key): selected_counts[key]
            for key in sorted(selected_counts, key=stratum_label)
        },
        "quota_exact": selected_counts == quotas,
        "pool_shortfall": any(quotas[key] > len(pools[key]) for key in quotas),
        "candidate_comparisons": candidate_comparisons,
        "candidate_alignment_cells": alignment_cells,
        "c3_overlap_count": overlap_count,
        "c3_overlap_fraction": overlap_count / len(selected) if selected else 0.0,
        "forced_selection_strata_count": len(forced),
        "forced_selection_pair_count": forced_pair_count,
        "forced_selection_pair_fraction": forced_pair_count / len(selected) if selected else 0.0,
        "c3_alignment_cells": c3_total_cells,
        "selected_alignment_cells": selected_total_cells,
        "absolute_relative_cost_deviation": total_deviation,
        "stratum_quota_pool_selected": strata_rows,
        "nominal_cost_by_stratum": nominal_cost,
        "eligibility_reason_counts": {
            stratum_label(key): selected_counts[key]
            for key in sorted(selected_counts, key=stratum_label)
            if key[0] == ABSTAIN
        },
        "selection_frozen_before_f4_cache": True,
        "gt_used_for_selection": False,
        "relation_flags_used_for_selection": False,
        "candidate_graph_summary": graph_summary(
            selected, bodies.keys()
        ),
    }


def select_control_pairs(
    body2_artifact: Mapping[str, Any],
    treatment_artifact: Mapping[str, Any],
    bodies: Mapping[str, FunctionBody],
    *,
    seed: str,
) -> dict[str, Any]:
    """Select random and body-score controls from the body2 candidate set.

    The treatment candidate set is used only to form exact per-stratum quotas.
    No labels, GT artifacts, decisions, or clusters are read here.
    """

    validate_candidate_artifact(body2_artifact)
    validate_candidate_artifact(treatment_artifact)
    if tuple(body2_artifact["config"].get("views", ())) != BODY2_VIEWS:
        raise ValueError("controls require the named token+CFG body2 artifact")
    if body2_artifact["universe"] != treatment_artifact["universe"]:
        raise ValueError("body2 and treatment universes differ")
    body2_records = list(body2_artifact["pairs"])
    treatment_records = list(treatment_artifact["pairs"])
    case = str(body2_artifact["case"])
    body2_pairs = _record_pair_set(body2_records)
    treatment_pairs = _record_pair_set(treatment_records)
    if not treatment_pairs <= body2_pairs:
        raise ValueError("treatment candidate set is not a body2 subset")
    pools: dict[Stratum, list[Mapping[str, Any]]] = defaultdict(list)
    for record in body2_records:
        pools[pair_stratum(pair_from_record(record), bodies)].append(record)
    quotas = strata_counts(treatment_records, bodies)
    for stratum, quota in quotas.items():
        if quota > len(pools.get(stratum, ())):
            raise ValueError(
                f"body2 pool cannot satisfy C3 quota for {stratum_label(stratum)}"
            )

    selected_random: list[Mapping[str, Any]] = []
    selected_score: list[Mapping[str, Any]] = []
    for stratum in sorted(quotas, key=stratum_label):
        quota = quotas[stratum]
        pool = pools[stratum]
        selected_random.extend(
            sorted(
                pool,
                key=lambda record: (
                    _hash_order(seed, case, stratum, pair_from_record(record)),
                    pair_from_record(record).left,
                    pair_from_record(record).right,
                ),
            )[:quota]
        )
        selected_score.extend(
            sorted(
                pool,
                key=lambda record: (
                    -body_score(record)[0],
                    -body_score(record)[1],
                    pair_from_record(record).left,
                    pair_from_record(record).right,
                ),
            )[:quota]
        )

    selected_random.sort(
        key=lambda record: (pair_from_record(record).left, pair_from_record(record).right)
    )
    selected_score.sort(
        key=lambda record: (pair_from_record(record).left, pair_from_record(record).right)
    )
    for arm, records in (("random", selected_random), ("body-score", selected_score)):
        counts = strata_counts(records, bodies)
        if counts != quotas:
            raise AssertionError(f"{arm} selection did not preserve C3 quotas")
    return {
        "seed": seed,
        "quotas": dict(quotas),
        "random": selected_random,
        "body-score": selected_score,
        "random_stats": _selection_stats(
            selected_random, treatment_records, treatment_pairs, quotas, pools, bodies
        ),
        "body_score_stats": _selection_stats(
            selected_score, treatment_records, treatment_pairs, quotas, pools, bodies
        ),
    }


def make_control_artifact(
    body2_artifact: Mapping[str, Any],
    records: Iterable[Mapping[str, Any]],
    arm: str,
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Project selected body2 records while retaining its named F5 universe."""

    result = copy.deepcopy(dict(body2_artifact))
    selected = [copy.deepcopy(dict(record)) for record in records]
    selected.sort(
        key=lambda record: (pair_from_record(record).left, pair_from_record(record).right)
    )
    result["pairs"] = selected
    provenance = dict(result.get("provenance", {}))
    provenance["relation_control"] = {
        "arm": str(arm),
        **copy.deepcopy(dict(metadata)),
    }
    result["provenance"] = provenance
    validate_candidate_artifact(result)
    return result


def strip_relation_flags(features: PairFeatures) -> PairFeatures:
    """Drop candidate-specific relation annotations from an old F4 record."""

    return replace(features, **{name: None for name in RELATION_FLAGS})


def _candidate_flags(record: Mapping[str, Any] | None) -> dict[str, Any]:
    if record is None:
        return {name: None for name in RELATION_FLAGS}
    return {name: record.get(name) for name in RELATION_FLAGS}


def annotate_features(
    features: PairFeatures,
    record: Mapping[str, Any] | None,
) -> PairFeatures:
    return replace(features, **_candidate_flags(record))


def _feature_from_dict(value: Mapping[str, Any]) -> PairFeatures:
    pair_values = value.get("pair")
    if not isinstance(pair_values, list) or len(pair_values) != 2:
        raise ValueError("cached feature pair is invalid")
    pair = PairKey.make(pair_values[0], pair_values[1])
    required = set(FEATURE_FIELDS) | set(RELATION_FLAGS)
    if not required <= set(value):
        raise ValueError("cached feature record is incomplete")
    return PairFeatures(
        pair=pair,
        structure_score=float(value["structure_score"]),
        aligned_instruction_ratio=float(value["aligned_instruction_ratio"]),
        sequence_ratio=float(value["sequence_ratio"]),
        mnemonic_multiset_jaccard=float(value["mnemonic_multiset_jaccard"]),
        constant_similarity=value["constant_similarity"],
        call_shape_similarity=value["call_shape_similarity"],
        data_reference_similarity=value["data_reference_similarity"],
        same_final_color=value["same_final_color"],
        same_prior_color=value["same_prior_color"],
        same_out_signature=value["same_out_signature"],
        same_in_signature=value["same_in_signature"],
        both_complete=bool(value["both_complete"]),
        opaque_indirect_jumps=int(value["opaque_indirect_jumps"]),
    )


def _validate_feature_body(
    features: PairFeatures,
    bodies: Mapping[str, FunctionBody],
) -> None:
    first, second = bodies.get(features.pair.left), bodies.get(features.pair.right)
    if first is None or second is None:
        raise ValueError(f"cached feature references missing body: {features.pair}")
    expected_complete = first.complete and second.complete
    expected_opaque = max(
        int(first.quality.get("opaque_indirect_jumps", 0)),
        int(second.quality.get("opaque_indirect_jumps", 0)),
    )
    if features.both_complete != expected_complete:
        raise ValueError(f"cached feature completeness mismatch: {features.pair}")
    if features.opaque_indirect_jumps != expected_opaque:
        raise ValueError(f"cached feature opaque count mismatch: {features.pair}")
    for name in (
        "structure_score",
        "aligned_instruction_ratio",
        "sequence_ratio",
        "mnemonic_multiset_jaccard",
    ):
        value = getattr(features, name)
        if not math.isfinite(float(value)) or not 0.0 <= float(value) <= 1.0:
            raise ValueError(f"cached feature {name} is outside [0,1]")
    for name in (
        "constant_similarity",
        "call_shape_similarity",
        "data_reference_similarity",
    ):
        value = getattr(features, name)
        if value is not None and (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or not 0.0 <= float(value) <= 1.0
        ):
            raise ValueError(f"cached feature {name} is invalid")


class BodyFeatureCache:
    """Shared body-only PairFeatures with fresh annotations per F6 arm."""

    def __init__(
        self,
        bodies: Mapping[str, FunctionBody],
        features: Mapping[PairKey | tuple[str, str], PairFeatures] | None = None,
    ) -> None:
        self.bodies = bodies
        self.features: dict[PairKey, PairFeatures] = {}
        self.hits = 0
        self.misses = 0
        self.physical_comparisons = 0
        self.physical_alignment_cells = 0
        for key, value in (features or {}).items():
            pair = key if isinstance(key, PairKey) else PairKey.make(*key)
            if value.pair != pair:
                raise ValueError("cached feature key and pair differ")
            body_only = strip_relation_flags(value)
            _validate_feature_body(body_only, bodies)
            existing = self.features.get(pair)
            if existing is not None and existing != body_only:
                raise ValueError(f"conflicting cached body features: {pair}")
            self.features[pair] = body_only

    def get(self, pair: PairKey) -> PairFeatures:
        cached = self.features.get(pair)
        if cached is not None:
            self.hits += 1
            return cached
        first, second = self.bodies.get(pair.left), self.bodies.get(pair.right)
        if first is None or second is None:
            raise ValueError(f"cannot compute missing body feature: {pair}")
        value = strip_relation_flags(pair_features_from_bodies(first, second))
        self.features[pair] = value
        self.misses += 1
        self.physical_comparisons += 1
        self.physical_alignment_cells += len(first.instructions) * len(second.instructions)
        return value

    def provider(
        self,
        candidate_records: Iterable[Mapping[str, Any]],
    ):
        records: dict[PairKey, Mapping[str, Any]] = {}
        for record in candidate_records:
            pair = pair_from_record(record)
            if pair in records:
                raise ValueError(f"duplicate provider candidate pair: {pair}")
            records[pair] = record

        def provide(pair: PairKey) -> PairFeatures:
            return annotate_features(self.get(pair), records.get(pair))

        return provide

    @classmethod
    def from_old_predictions(
        cls,
        bodies: Mapping[str, FunctionBody],
        prediction_paths: Iterable[str | Path],
        *,
        expected_identity: Mapping[str, Any],
        expected_policy: PairPolicyConfig,
    ) -> "BodyFeatureCache":
        collected: dict[PairKey, PairFeatures] = {}
        for prediction_path in sorted((Path(path) for path in prediction_paths), key=str):
            metadata_path = prediction_path.with_name("metadata.json")
            if not metadata_path.is_file():
                raise ValueError(f"old prediction metadata is missing: {metadata_path}")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata.get("status") != "completed":
                continue
            for key in (
                "body_evidence_sha256",
                "config_sha256",
                "python",
                "base_commit",
            ):
                expected = expected_identity.get(key)
                if expected is not None and metadata.get(key) != expected:
                    raise ValueError(f"old cache {key} identity mismatch: {metadata_path}")
            expected_protocol = expected_identity.get("protocol_sha256")
            if expected_protocol is not None and metadata.get("protocol_sha256") != expected_protocol:
                raise ValueError(f"old cache protocol identity mismatch: {metadata_path}")
            expected_prediction_sha = metadata.get("prediction_sha256")
            if not expected_prediction_sha or not prediction_path.is_file():
                raise ValueError(f"old cache prediction is not retained: {prediction_path}")
            actual_prediction_sha = hashlib.sha256(
                prediction_path.read_bytes()
            ).hexdigest()
            if actual_prediction_sha != expected_prediction_sha:
                raise ValueError(f"old cache prediction hash mismatch: {prediction_path}")
            prediction = json.loads(prediction_path.read_text(encoding="utf-8"))
            actual_policy = PairPolicyConfig.from_dict(prediction.get("config", {}))
            if actual_policy.to_dict() != expected_policy.to_dict():
                raise ValueError(f"old cache F6 policy mismatch: {prediction_path}")
            universe = prediction.get("universe", {})
            if sorted(universe.get("target_ids", ())) != sorted(bodies):
                raise ValueError(f"old cache body universe mismatch: {prediction_path}")
            for item in prediction.get("pair_decisions", ()):
                features = _feature_from_dict(item["features"])
                body_only = strip_relation_flags(features)
                _validate_feature_body(body_only, bodies)
                old = collected.get(body_only.pair)
                if old is not None and old != body_only:
                    raise ValueError(
                        f"old cache body feature disagreement for {body_only.pair}"
                    )
                collected[body_only.pair] = body_only
        return cls(bodies, collected)


def cost_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    """Extract actual F6 logical cost fields for arm comparisons."""

    metrics = value.get("metrics", value)
    return {
        "actual_comparisons": int(metrics.get("total_detailed_comparisons", 0)),
        "actual_alignment_cells": int(metrics.get("total_alignment_cells", 0)),
        "total_comparisons": int(metrics.get("total_detailed_comparisons", 0)),
        "total_alignment_cells": int(metrics.get("total_alignment_cells", 0)),
        "candidate_comparisons": int(metrics.get("candidate_detailed_comparison_count", 0)),
        "on_demand_comparisons": int(metrics.get("on_demand_comparison_count", 0)),
        "candidate_alignment_cells": int(metrics.get("candidate_alignment_cells", 0)),
        "on_demand_alignment_cells": int(metrics.get("on_demand_alignment_cells", 0)),
    }


def actual_cost_ratio(
    control: Mapping[str, Any],
    treatment: Mapping[str, Any],
) -> dict[str, float | None]:
    left, right = cost_summary(control), cost_summary(treatment)
    return {
        "comparisons": (
            left["actual_comparisons"] / right["actual_comparisons"]
            if right["actual_comparisons"]
            else None
        ),
        "alignment_cells": (
            left["actual_alignment_cells"] / right["actual_alignment_cells"]
            if right["actual_alignment_cells"]
            else None
        ),
    }


def graph_summary(
    records: Iterable[Mapping[str, Any]],
    target_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Describe candidate graph degree/components without claiming a match."""

    ids = set(target_ids)
    edges = {pair_from_record(record) for record in records}
    for pair in edges:
        ids.update((pair.left, pair.right))
    neighbors: dict[str, set[str]] = {member: set() for member in ids}
    for pair in edges:
        neighbors.setdefault(pair.left, set()).add(pair.right)
        neighbors.setdefault(pair.right, set()).add(pair.left)
    components: list[list[str]] = []
    unseen = set(neighbors)
    while unseen:
        root = min(unseen)
        stack = [root]
        unseen.remove(root)
        component = []
        while stack:
            member = stack.pop()
            component.append(member)
            for neighbor in sorted(neighbors[member], reverse=True):
                if neighbor in unseen:
                    unseen.remove(neighbor)
                    stack.append(neighbor)
        components.append(sorted(component))
    degrees = sorted(len(neighbors[member]) for member in neighbors)
    return {
        "node_count": len(neighbors),
        "edge_count": len(edges),
        "nonzero_degree_count": sum(value > 0 for value in degrees),
        "degree_min": min(degrees) if degrees else 0,
        "degree_max": max(degrees) if degrees else 0,
        "degree_mean": sum(degrees) / len(degrees) if degrees else 0.0,
        "component_count": len(components),
        "component_sizes": sorted((len(component) for component in components), reverse=True),
    }


def run_f6_pair(
    candidate_artifact: Mapping[str, Any],
    bodies: Mapping[str, FunctionBody],
    policy: PairPolicyConfig,
    *,
    feature_cache: BodyFeatureCache | None = None,
    body_sha256: str | None = None,
    body_provenance: Mapping[str, Any] | None = None,
    candidate_sha256: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    provider = (
        feature_cache.provider(candidate_artifact["pairs"])
        if feature_cache is not None
        else None
    )
    result = build_family_artifact(
        candidate_artifact=candidate_artifact,
        bodies=bodies,
        config=policy,
        feature_provider=provider,
        body_sha256=body_sha256,
        body_provenance=body_provenance,
        candidate_sha256=candidate_sha256,
    )
    return result, cost_summary(result)


def load_bodies(path: str | Path) -> dict[str, FunctionBody]:
    return load_body_evidence(path)


__all__ = [
    "ABSTAIN",
    "BODY2_VIEWS",
    "BodyFeatureCache",
    "ELIGIBLE",
    "actual_cost_ratio",
    "annotate_features",
    "body_score",
    "cost_summary",
    "endpoint_reasons",
    "graph_summary",
    "make_control_artifact",
    "pair_cost",
    "pair_from_record",
    "pair_stratum",
    "run_f6_pair",
    "select_control_pairs",
    "strata_counts",
    "stratum_label",
    "strip_relation_flags",
]
