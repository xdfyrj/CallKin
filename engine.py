# Call-Graph Weisfeiler-Lehman color refinement engine

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass

from loader import load_case
from model import Case
from paths import (
    ANALYSIS_TRACKS,
    BUILD_PROFILES,
    CANDIDATE_SCOPES,
    DEFAULT_ANALYSIS_TRACK,
    DEFAULT_BUILD,
    DEFAULT_CANDIDATE_SCOPE,
    DEFAULT_PROFILE,
    resolve_fixture_json,
    split_case_build,
)


NodeId = str
Color = str
CallCount = int

WeightedEdge = tuple[NodeId, CallCount]
WeightedNeighborColor = tuple[Color, CallCount]
CGWLMode = str

MODE_FULL = "full"
MODE_OUT = "out"
MODE_IN = "in"
MODE_OUT_IN = "out-in"
DEFAULT_CG_WL_MODE = MODE_FULL
CG_WL_MODES: tuple[CGWLMode, ...] = (
    MODE_FULL,
    MODE_OUT,
    MODE_IN,
    MODE_OUT_IN,
)

RelationSignature = tuple[object, ...]


@dataclass(frozen=True)
class RelationGraphView:
    """
    Call graph view used by Call-Graph Weisfeiler-Lehman.

    This view is derived only from Axis 1 call edges.
    Self-edges are lifted into self_call_count and excluded from
    outgoing/incoming multisets.
    """
    node_ids: list[NodeId]

    self_call_count: dict[NodeId, int]

    # Non-self edges only.
    outgoing: dict[NodeId, list[WeightedEdge]]
    incoming: dict[NodeId, list[WeightedEdge]]

    # Number of distinct non-self callees.
    # This is intentionally not total outgoing call count.
    distinct_out_callee_count: dict[NodeId, int]

    # Number of distinct non-self callers.
    distinct_in_caller_count: dict[NodeId, int]


@dataclass(frozen=True)
class CGWLRoundTrace:
    round_index: int
    changed: bool | None
    clusters: tuple[tuple[NodeId, ...], ...]


@dataclass(frozen=True)
class CGWLResult:
    """
    Result of Call-Graph Weisfeiler-Lehman.

    cluster_id_by_node and clusters are restricted to scored nodes.
    """
    mode: CGWLMode
    cluster_id_by_node: dict[NodeId, int]
    clusters: list[list[NodeId]]
    rounds: int
    trace: tuple[CGWLRoundTrace, ...] = ()


def run_cg_wl(
    case: Case,
    *,
    mode: CGWLMode = DEFAULT_CG_WL_MODE,
    trace: bool = False,
) -> CGWLResult:
    """
    Run Call-Graph Weisfeiler-Lehman.

    full mode:
      - Axis 1 only.
      - Directed weighted call graph.
      - Individualized fixed anchors.
      - Seed(user) = (self_call_count, distinct_out_callee_count).
      - Refinement signature = previous color + OUT multiset + IN multiset.
      - OUT/IN multisets aggregate call counts by previous neighbor color.
      - No origin labels, no Axis 2/4, no oracle, no soft merge.
    """
    validate_cg_wl_mode(mode)
    view = build_relation_graph_view(case)
    colors = make_initial_cg_wl_colors(case, view, mode=mode)
    round_trace = (
        [_make_round_trace(case, 0, None, colors)]
        if trace
        else []
    )

    max_rounds = len(view.node_ids)

    for round_index in range(1, max_rounds + 1):
        new_colors = refine_cg_wl_once(case, view, colors, mode=mode)
        changed = not same_partition(view.node_ids, colors, new_colors)
        if trace:
            round_trace.append(
                _make_round_trace(case, round_index, changed, new_colors)
            )

        if not changed:
            clusters = make_scored_clusters(case, new_colors)
            cluster_id_by_node = make_cluster_id_by_node(clusters)

            return CGWLResult(
                mode=mode,
                cluster_id_by_node=cluster_id_by_node,
                clusters=clusters,
                rounds=round_index,
                trace=tuple(round_trace),
            )

        colors = new_colors

    raise RuntimeError("CG-WL did not reach a fixpoint")


def build_relation_graph_view(case: Case) -> RelationGraphView:
    node_ids = [node.id for node in case.nodes]

    self_call_count: dict[NodeId, int] = {
        node.id: 0
        for node in case.nodes
    }
    outgoing: dict[NodeId, list[WeightedEdge]] = {
        node.id: []
        for node in case.nodes
    }
    incoming: dict[NodeId, list[WeightedEdge]] = {
        node.id: []
        for node in case.nodes
    }

    for node in case.nodes:
        src = node.id

        for call in node.calls:
            dst = call.target
            count = call.count

            if src == dst:
                self_call_count[src] += count
                continue

            outgoing[src].append((dst, count))
            incoming[dst].append((src, count))

    distinct_out_callee_count = {
        node_id: len({dst for dst, _count in outgoing[node_id]})
        for node_id in node_ids
    }
    distinct_in_caller_count = {
        node_id: len({src for src, _count in incoming[node_id]})
        for node_id in node_ids
    }

    return RelationGraphView(
        node_ids=node_ids,
        self_call_count=self_call_count,
        outgoing=outgoing,
        incoming=incoming,
        distinct_out_callee_count=distinct_out_callee_count,
        distinct_in_caller_count=distinct_in_caller_count,
    )


def make_initial_cg_wl_colors(
    case: Case,
    view: RelationGraphView,
    *,
    mode: CGWLMode = DEFAULT_CG_WL_MODE,
) -> dict[NodeId, Color]:
    validate_cg_wl_mode(mode)
    colors: dict[NodeId, Color] = {}

    for node in case.nodes:
        if node.type == "anchor":
            colors[node.id] = _anchor_color(node.color_class or node.id)
            continue

        self_count = view.self_call_count[node.id]

        if mode == MODE_IN:
            in_count = view.distinct_in_caller_count[node.id]
            colors[node.id] = f"USER:self={self_count}:distinct_in={in_count}"
        else:
            out_count = view.distinct_out_callee_count[node.id]
            colors[node.id] = f"USER:self={self_count}:distinct_out={out_count}"

    return colors


def refine_cg_wl_once(
    case: Case,
    view: RelationGraphView,
    prev_colors: dict[NodeId, Color],
    *,
    mode: CGWLMode = DEFAULT_CG_WL_MODE,
) -> dict[NodeId, Color]:
    validate_cg_wl_mode(mode)
    signatures: dict[NodeId, RelationSignature] = {}

    for node in case.nodes:
        if node.type == "anchor":
            continue

        out_multiset = _neighbor_color_multiset(
            view.outgoing[node.id],
            prev_colors,
        )
        in_multiset = _neighbor_color_multiset(
            view.incoming[node.id],
            prev_colors,
        )
        signatures[node.id] = make_relation_signature(
            node.id,
            prev_colors[node.id],
            out_multiset,
            in_multiset,
            view,
            mode=mode,
        )

    signature_to_color = _canonicalize_signatures(signatures)

    new_colors: dict[NodeId, Color] = {}

    for node in case.nodes:
        if node.type == "anchor":
            new_colors[node.id] = _anchor_color(node.color_class or node.id)
        else:
            new_colors[node.id] = signature_to_color[signatures[node.id]]

    return new_colors


def make_relation_signature(
    node_id: NodeId,
    previous_color: Color,
    out_multiset: tuple[WeightedNeighborColor, ...],
    in_multiset: tuple[WeightedNeighborColor, ...],
    view: RelationGraphView,
    *,
    mode: CGWLMode,
) -> RelationSignature:
    if mode == MODE_FULL:
        return (previous_color, out_multiset, in_multiset)
    if mode == MODE_OUT:
        return (previous_color, out_multiset)
    if mode == MODE_IN:
        return (previous_color, in_multiset)
    if mode == MODE_OUT_IN:
        if view.distinct_out_callee_count[node_id] == 0:
            return (previous_color, out_multiset, in_multiset)
        return (previous_color, out_multiset)

    raise ValueError(f"unknown CG-WL mode: {mode}")


def validate_cg_wl_mode(mode: CGWLMode) -> None:
    if mode not in CG_WL_MODES:
        raise ValueError(
            f"unknown CG-WL mode: {mode!r}. "
            f"expected one of {', '.join(CG_WL_MODES)}"
        )


def _neighbor_color_multiset(
    edges: list[WeightedEdge],
    prev_colors: dict[NodeId, Color],
) -> tuple[WeightedNeighborColor, ...]:
    # CG-WL compares neighbor groups, not raw neighbor identities:
    # key = previous neighbor color, value += static callsite count.
    count_by_color: dict[Color, int] = {}

    for node_id, count in edges:
        color = prev_colors[node_id]
        count_by_color[color] = count_by_color.get(color, 0) + count

    return tuple(sorted(count_by_color.items()))


def make_scored_clusters(
    case: Case,
    colors: dict[NodeId, Color],
) -> list[list[NodeId]]:
    by_color: dict[Color, list[NodeId]] = defaultdict(list)

    for node in case.nodes:
        if node.scored:
            by_color[colors[node.id]].append(node.id)

    clusters = [
        sorted(node_ids)
        for node_ids in by_color.values()
    ]

    clusters.sort(key=lambda cluster: (cluster[0], len(cluster)))
    return clusters


def make_cluster_id_by_node(
    clusters: list[list[NodeId]],
) -> dict[NodeId, int]:
    cluster_id_by_node: dict[NodeId, int] = {}

    for cluster_id, cluster in enumerate(clusters):
        for node_id in cluster:
            cluster_id_by_node[node_id] = cluster_id

    return cluster_id_by_node


def _make_round_trace(
    case: Case,
    round_index: int,
    changed: bool | None,
    colors: dict[NodeId, Color],
) -> CGWLRoundTrace:
    return CGWLRoundTrace(
        round_index=round_index,
        changed=changed,
        clusters=tuple(
            tuple(cluster)
            for cluster in make_scored_clusters(case, colors)
        ),
    )


def format_cg_wl_trace(trace: tuple[CGWLRoundTrace, ...]) -> str:
    lines = ["trace:"]
    for step in trace:
        if step.round_index == 0:
            state = "seed"
        elif step.changed:
            state = "changed"
        else:
            state = "fixpoint"
        lines.append(f"  round {step.round_index} ({state}):")
        for cluster_index, cluster in enumerate(step.clusters, start=1):
            lines.append(f"    C{cluster_index} = {list(cluster)}")
    return "\n".join(lines)


def same_partition(
    node_ids: list[NodeId],
    colors_a: dict[NodeId, Color],
    colors_b: dict[NodeId, Color],
) -> bool:
    return canonical_partition(node_ids, colors_a) == canonical_partition(
        node_ids,
        colors_b,
    )


def canonical_partition(
    node_ids: list[NodeId],
    colors: dict[NodeId, Color],
) -> tuple[tuple[NodeId, ...], ...]:
    by_color: dict[Color, list[NodeId]] = defaultdict(list)

    for node_id in node_ids:
        by_color[colors[node_id]].append(node_id)

    groups = [
        tuple(sorted(group))
        for group in by_color.values()
    ]

    return tuple(sorted(groups))


def _canonicalize_signatures(
    signatures: dict[NodeId, RelationSignature],
) -> dict[RelationSignature, Color]:
    unique_signatures = sorted(set(signatures.values()))

    return {
        signature: f"C:{index}"
        for index, signature in enumerate(unique_signatures)
    }


def _anchor_color(color_class: str) -> Color:
    return f"ANCHOR:{color_class}"


def run_fixture_path(
    fixture_path: str,
    *,
    mode: CGWLMode = DEFAULT_CG_WL_MODE,
    trace: bool = False,
) -> CGWLResult:
    return run_cg_wl(load_case(fixture_path), mode=mode, trace=trace)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run CG-WL on one fixture JSON."
    )
    parser.add_argument("fixture", help="fixture JSON path, or an example stem")
    parser.add_argument("--build", help=f"build label. Default: {DEFAULT_BUILD}")
    parser.add_argument(
        "--profile",
        choices=BUILD_PROFILES,
        default=DEFAULT_PROFILE,
        help=f"compiler profile. Default: {DEFAULT_PROFILE}",
    )
    parser.add_argument(
        "--track",
        choices=ANALYSIS_TRACKS,
        default=DEFAULT_ANALYSIS_TRACK,
        help=f"analysis track. Default: {DEFAULT_ANALYSIS_TRACK}",
    )
    parser.add_argument(
        "--candidate-scope",
        choices=CANDIDATE_SCOPES,
        default=DEFAULT_CANDIDATE_SCOPE,
        help=f"candidate scope. Default: {DEFAULT_CANDIDATE_SCOPE}",
    )
    parser.add_argument(
        "--mode",
        choices=CG_WL_MODES,
        default=DEFAULT_CG_WL_MODE,
        help=f"relation mode. Default: {DEFAULT_CG_WL_MODE}",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="print the scored partition for seed and every refinement round",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.fixture.endswith(".json"):
        fixture_path = args.fixture
    else:
        case, build = split_case_build(args.fixture, args.build)
        fixture_path = resolve_fixture_json(
            case,
            build,
            args.profile,
            args.track,
            args.candidate_scope,
        )

    try:
        result = run_fixture_path(fixture_path, mode=args.mode, trace=args.trace)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(result.mode)
    print(result.rounds)
    print(result.clusters)
    if args.trace:
        print(format_cg_wl_trace(result.trace))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
