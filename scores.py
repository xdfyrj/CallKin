# 자동 채점기
# scores.py
#
# 자동 채점기 (auto scorer)
#   - 전체 pairwise score
#   - predicted cluster와 origin별 복원 결과
#   - CLI 및 단일 JSON 출력
#
# 규칙
#   엔진은 origin 을 모른다. scorer 만 ground truth 를 본다.
#   ground truth 는 origin partition 과 출력용 demangled symbol 만 담는다.
#   채점 유니버스 = fixture 의 scored 노드 == ground truth 의 전체 member.

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path

from analysis_provenance import AnalysisProvenance
from engine import (
    CG_WL_MODES,
    DEFAULT_CG_WL_MODE,
    CGWLMode,
    CGWLRoundTrace,
    format_cg_wl_trace,
    run_cg_wl,
)
from loader import load_case
from model import Case
from paths import (
    ANALYSIS_TRACKS,
    ANCHOR_POLICIES,
    BUILD_PROFILES,
    CANDIDATE_SCOPES,
    DEFAULT_ANALYSIS_TRACK,
    DEFAULT_ANCHOR_POLICY,
    DEFAULT_BUILD,
    DEFAULT_CANDIDATE_SCOPE,
    DEFAULT_PROFILE,
    SUBJECT_CANDIDATE_SCOPE,
    normalize_candidate_scope,
    normalize_profile,
    resolve_fixture_json,
    resolve_gt_json,
    split_case_build,
)
from provenance import BuildProvenance, parse_provenance


# ---------------------------------------------------------- ground truth model

GROUND_TRUTH_SCHEMA_VERSION = 5
SUPPORTED_GROUND_TRUTH_SCHEMAS = {5, 6}

V0_BASELINE_JOBS: tuple[tuple[str, str], ...] = (
    ("family_graph_01", "O3S"),
    ("family_graph_02", "O3S"),
    ("family_graph_03", "O3S"),
    ("family_graph_03", "O3KS"),
)


@dataclass(frozen=True)
class OriginGroup:
    origin: str
    members: tuple[str, ...]


@dataclass(frozen=True)
class GroundTruth:
    case: str
    build: str
    profile: str
    schema_version: int
    origins: tuple[OriginGroup, ...]
    symbols: dict[str, tuple[str, ...]]
    provenance: BuildProvenance

    def origin_of(self) -> dict[str, str]:
        return {m: g.origin for g in self.origins for m in g.members}


# ---------------------------------------------------------- ground truth loader

def load_ground_truth(path: str) -> GroundTruth:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    _validate_ground_truth(data)
    return GroundTruth(
        case=data["case"],
        build=data["build"],
        profile=data["profile"],
        schema_version=data["schema_version"],
        origins=tuple(
            OriginGroup(
                origin=o["origin"],
                members=tuple(o["members"]),
            )
            for o in data["origins"]
        ),
        symbols={
            member_id: tuple(symbols)
            for member_id, symbols in data["symbols"].items()
        },
        provenance=parse_provenance(
            data["provenance"], where="ground_truth.provenance"
        ),
    )


def _validate_ground_truth(data) -> None:
    if not isinstance(data, dict):
        raise ValueError("ground truth root must be a JSON object")

    required = {
        "case", "build", "profile", "schema_version", "provenance", "origins", "symbols"
    }
    allowed = required | {"note", "cross_origin_aliases"}
    keys = set(data)
    if required - keys:
        raise ValueError(f"missing field(s): {sorted(required - keys)}")
    if keys - allowed:
        raise ValueError(f"unknown field(s): {sorted(keys - allowed)}")
    if data["schema_version"] not in SUPPORTED_GROUND_TRUTH_SCHEMAS:
        raise ValueError(f"unsupported schema_version: {data['schema_version']}")
    normalize_profile(data["profile"])
    parse_provenance(data["provenance"], where="ground_truth.provenance")
    if not isinstance(data["origins"], list) or not data["origins"]:
        raise ValueError("origins must be a non-empty list")

    seen_origins: set[str] = set()
    seen_members: set[str] = set()
    for index, o in enumerate(data["origins"]):
        where = f"origins[{index}]"
        if not isinstance(o, dict) or set(o) != {"origin", "members"}:
            raise ValueError(f"{where} must have exactly origin/members")

        name = o["origin"]
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{where}.origin must be a non-empty string")
        if name in seen_origins:
            raise ValueError(f"duplicate origin name: {name}")
        seen_origins.add(name)

        members = o["members"]
        if not isinstance(members, list) or not members:
            raise ValueError(f"{name}.members must be a non-empty list")
        for m in members:
            if not isinstance(m, str) or not m.strip():
                raise ValueError(f"{name} has an invalid member id")
            if m in seen_members:
                raise ValueError(f"id appears in more than one origin: {m}")
            seen_members.add(m)

    symbols = data["symbols"]
    if not isinstance(symbols, dict):
        raise ValueError("symbols must be an object mapping member id to symbol list")
    if set(symbols) != seen_members:
        raise ValueError(
            "symbols keys must equal origin members. "
            f"missing symbols: {sorted(seen_members - set(symbols))}; "
            f"unknown symbols: {sorted(set(symbols) - seen_members)}"
        )
    for member_id, names in symbols.items():
        if not isinstance(names, list) or not names:
            raise ValueError(f"symbols[{member_id!r}] must be a non-empty list")
        for name in names:
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"symbols[{member_id!r}] has an invalid symbol")

    aliases = data.get("cross_origin_aliases", [])
    if data["schema_version"] == 6 and not aliases:
        raise ValueError("ground truth schema v6 requires cross_origin_aliases")
    if aliases:
        if not isinstance(aliases, list):
            raise ValueError("cross_origin_aliases must be a list")
        seen_alias_members = set()
        for index, alias in enumerate(aliases):
            where = f"cross_origin_aliases[{index}]"
            if not isinstance(alias, dict) or set(alias) != {"member", "origins"}:
                raise ValueError(f"{where} must contain member/origins")
            member = alias["member"]
            origins = alias["origins"]
            if member not in seen_members or member in seen_alias_members:
                raise ValueError(f"invalid or duplicate alias member: {member!r}")
            seen_alias_members.add(member)
            if (
                not isinstance(origins, list)
                or len(origins) < 2
                or any(not isinstance(origin, str) or not origin for origin in origins)
                or len(set(origins)) != len(origins)
            ):
                raise ValueError(f"{where}.origins must contain unique source origins")


# ---------------------------------------------------------- score result types

@dataclass(frozen=True)
class PairwiseScore:
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    ari: float


@dataclass(frozen=True)
class ScoredMember:
    id: str
    symbols: tuple[str, ...]
    origin: str


@dataclass(frozen=True)
class PredictedCluster:
    name: str
    members: tuple[ScoredMember, ...]
    origins: tuple[str, ...]

    @property
    def member_ids(self) -> tuple[str, ...]:
        return tuple(member.id for member in self.members)


@dataclass(frozen=True)
class OriginScore:
    origin: str
    k_obs: int
    predicted_cluster_count: int
    recovered_pairs: int
    total_pairs: int
    colliding_origins: tuple[str, ...]


@dataclass(frozen=True)
class ScoreReport:
    case: str
    build: str
    profile: str
    mode: CGWLMode
    candidate_count: int
    pair_count: int
    rounds: int
    clusters: tuple[PredictedCluster, ...]
    origins: tuple[OriginScore, ...]
    pairwise: PairwiseScore
    provenance: BuildProvenance
    analysis: AnalysisProvenance | None = None
    trace: tuple[CGWLRoundTrace, ...] = ()


# ---------------------------------------------------------- scoring

def score_case(
    fixture_path: str,
    ground_truth_path: str,
    *,
    mode: CGWLMode = DEFAULT_CG_WL_MODE,
    trace: bool = False,
) -> ScoreReport:
    case = load_case(fixture_path)
    gt = load_ground_truth(ground_truth_path)
    _check_join(case, gt)

    result = run_cg_wl(case, mode=mode, trace=trace)
    cluster_of = result.cluster_id_by_node      # scored nodes only
    origin_of = gt.origin_of()

    scored_ids = sorted(cluster_of)

    tp = fp = fn = tn = 0

    for a, b in combinations(scored_ids, 2):
        pred_same = cluster_of[a] == cluster_of[b]
        true_same = origin_of[a] == origin_of[b]

        if pred_same and true_same:
            tp += 1
        elif pred_same and not true_same:
            fp += 1
        elif (not pred_same) and true_same:
            fn += 1
        else:
            tn += 1

    pairwise = _pairwise_score(tp, fp, fn, tn)
    clusters = _make_predicted_clusters(result.clusters, gt, origin_of)
    origins = _make_origin_scores(gt, cluster_of, clusters)

    return ScoreReport(
        case=case.case,
        build=case.build,
        profile=case.profile,
        mode=result.mode,
        candidate_count=len(scored_ids),
        pair_count=len(scored_ids) * (len(scored_ids) - 1) // 2,
        rounds=result.rounds,
        clusters=clusters,
        origins=origins,
        pairwise=pairwise,
        provenance=gt.provenance,
        analysis=case.analysis,
        trace=result.trace,
    )


def score_all_modes(
    fixture_path: str,
    ground_truth_path: str,
    *,
    trace: bool = False,
) -> tuple[ScoreReport, ...]:
    return tuple(
        score_case(fixture_path, ground_truth_path, mode=mode, trace=trace)
        for mode in CG_WL_MODES
    )


def score_v0_baseline(
    *,
    profile: str = DEFAULT_PROFILE,
    mode: CGWLMode = DEFAULT_CG_WL_MODE,
    all_modes: bool = False,
    trace: bool = False,
) -> tuple[ScoreReport, ...]:
    profile = normalize_profile(profile)
    reports = []
    modes = CG_WL_MODES if all_modes else (mode,)
    for case, build in V0_BASELINE_JOBS:
        fixture_path = resolve_fixture_json(
            case, build, profile, candidate_scope=SUBJECT_CANDIDATE_SCOPE
        )
        gt_path = resolve_gt_json(
            case, build, profile, SUBJECT_CANDIDATE_SCOPE
        )
        reports.extend(
            score_case(fixture_path, gt_path, mode=mode, trace=trace)
            for mode in modes
        )
    return tuple(reports)


def _pairwise_score(tp: int, fp: int, fn: int, tn: int) -> PairwiseScore:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return PairwiseScore(tp, fp, fn, tn, precision, recall, f1,
                         _adjusted_rand_index(tp, fp, fn, tn))


def _adjusted_rand_index(tp: int, fp: int, fn: int, tn: int) -> float:
    # ARI from pairwise counts.
    #   index            = sum_ij C(n_ij, 2) = TP
    #   same_cluster     = sum_i  C(a_i,  2) = TP + FP
    #   same_origin      = sum_j  C(b_j,  2) = TP + FN
    #   total node pairs = C(n, 2)           = TP + FP + FN + TN
    index = tp
    same_cluster = tp + fp
    same_origin = tp + fn
    total = tp + fp + fn + tn
    if total == 0:
        return 1.0
    expected = same_cluster * same_origin / total
    maximum = 0.5 * (same_cluster + same_origin)
    if maximum == expected:
        return 1.0
    return (index - expected) / (maximum - expected)


def _check_join(case: Case, gt: GroundTruth) -> None:
    if (
        case.case != gt.case
        or case.build != gt.build
        or case.profile != gt.profile
    ):
        raise ValueError(
            "case/build/profile mismatch: "
            f"fixture={case.case}/{case.build}/{case.profile} "
            f"vs ground_truth={gt.case}/{gt.build}/{gt.profile}"
        )
    if case.provenance != gt.provenance:
        raise ValueError("fixture/ground-truth build provenance mismatch")
    scored_ids = {n.id for n in case.nodes if n.scored}
    gt_ids = {m for g in gt.origins for m in g.members}
    if scored_ids != gt_ids:
        raise ValueError(
            "scored universe mismatch. "
            f"missing in ground truth: {sorted(scored_ids - gt_ids)}; "
            f"present in ground truth but not scored: {sorted(gt_ids - scored_ids)}"
        )


def _make_predicted_clusters(
    raw_clusters: list[list[str]],
    gt: GroundTruth,
    origin_of: dict[str, str],
) -> tuple[PredictedCluster, ...]:
    clusters = []
    for index, member_ids in enumerate(raw_clusters, start=1):
        members = tuple(
            ScoredMember(
                id=member_id,
                symbols=tuple(
                    _display_symbol(symbol, gt.case)
                    for symbol in gt.symbols[member_id]
                ),
                origin=origin_of[member_id],
            )
            for member_id in member_ids
        )
        clusters.append(PredictedCluster(
            name=f"C{index}",
            members=members,
            origins=tuple(sorted({member.origin for member in members})),
        ))
    return tuple(clusters)


def _make_origin_scores(
    gt: GroundTruth,
    cluster_of: dict[str, int],
    clusters: tuple[PredictedCluster, ...],
) -> tuple[OriginScore, ...]:
    origins_by_cluster = {
        index: set(cluster.origins)
        for index, cluster in enumerate(clusters)
    }
    rows = []

    for group in gt.origins:
        cluster_ids = {cluster_of[member] for member in group.members}
        recovered_pairs = sum(
            1
            for a, b in combinations(group.members, 2)
            if cluster_of[a] == cluster_of[b]
        )
        colliding_origins = sorted({
            other
            for cluster_id in cluster_ids
            for other in origins_by_cluster[cluster_id]
            if other != group.origin
        })
        k_obs = len(group.members)
        rows.append(OriginScore(
            origin=group.origin,
            k_obs=k_obs,
            predicted_cluster_count=len(cluster_ids),
            recovered_pairs=recovered_pairs,
            total_pairs=k_obs * (k_obs - 1) // 2,
            colliding_origins=tuple(colliding_origins),
        ))

    return tuple(rows)


def _display_symbol(symbol: str, case: str) -> str:
    prefix = f"{case}::"
    if symbol.startswith(prefix):
        symbol = symbol[len(prefix):]
    return re.sub(r"::h[0-9a-fA-F]{16}$", "", symbol)


# ---------------------------------------------------------- pretty print + CLI

def format_report(r: ScoreReport) -> str:
    p = r.pairwise
    lines = [
        f"case : {r.case} / {r.build} / {r.profile}",
        *([f"track: {r.analysis.track}"] if r.analysis is not None else []),
        *(
            [f"candidate scope: {r.analysis.candidate_scope}"]
            if r.analysis is not None
            else []
        ),
        f"mode: {r.mode}",
        f"candidates: {r.candidate_count}",
        f"candidate pairs: {r.pair_count}",
        f"rounds: {r.rounds}",
        "predicted clusters:",
    ]
    for cluster in r.clusters:
        lines.append(f"  {cluster.name}:")
        lines.extend(
            f"    {member.id} | {' | '.join(member.symbols)} | origin={member.origin}"
            for member in cluster.members
        )
    lines.append("origins:")
    for origin in r.origins:
        collisions = ", ".join(origin.colliding_origins) or "-"
        lines.append(
            f"  {origin.origin}: k_obs={origin.k_obs} "
            f"clusters={origin.predicted_cluster_count} "
            f"pairs={origin.recovered_pairs}/{origin.total_pairs} "
            f"collisions={collisions}"
        )
    lines.extend([
        f"TP={p.tp} FP={p.fp} FN={p.fn} TN={p.tn}",
        f"PR={p.precision:.2f} RE={p.recall:.2f} F1={p.f1:.2f} ARI={p.ari:.2f}",
    ])
    if r.trace:
        lines.extend(["", format_cg_wl_trace(r.trace)])
    return "\n".join(lines)


def score_report_to_dict(report: ScoreReport) -> dict:
    p = report.pairwise
    data = {
        "case": report.case,
        "build": report.build,
        "profile": report.profile,
        "mode": report.mode,
        "provenance": report.provenance.to_dict(),
        "candidate_count": report.candidate_count,
        "pair_count": report.pair_count,
        "rounds": report.rounds,
        "pairwise": {
            "TP": p.tp,
            "FP": p.fp,
            "FN": p.fn,
            "TN": p.tn,
            "precision": p.precision,
            "recall": p.recall,
            "F1": p.f1,
            "ARI": p.ari,
        },
        "clusters": [
            {
                "cluster": cluster.name,
                "origins": list(cluster.origins),
                "members": [
                    {
                        "id": member.id,
                        "symbols": list(member.symbols),
                        "origin": member.origin,
                    }
                    for member in cluster.members
                ],
            }
            for cluster in report.clusters
        ],
        "origins": [
            {
                "origin": origin.origin,
                "k_obs": origin.k_obs,
                "predicted_cluster_count": origin.predicted_cluster_count,
                "recovered_pairs": origin.recovered_pairs,
                "total_pairs": origin.total_pairs,
                "colliding_origins": list(origin.colliding_origins),
            }
            for origin in report.origins
        ],
    }
    if report.trace:
        data["trace"] = [
            {
                "round": step.round_index,
                "state": (
                    "seed"
                    if step.round_index == 0
                    else "changed" if step.changed else "fixpoint"
                ),
                "clusters": [list(cluster) for cluster in step.clusters],
            }
            for step in report.trace
        ]
    if report.analysis is not None:
        data["analysis"] = report.analysis.to_dict()
    return data


def reports_to_dict(reports: tuple[ScoreReport, ...]) -> dict:
    return {
        "schema_version": 4 if any(report.analysis for report in reports) else 3,
        "results": [score_report_to_dict(report) for report in reports],
    }


def write_reports_json(reports: tuple[ScoreReport, ...], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(reports_to_dict(reports), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Score CG-WL clusters against a ground-truth JSON."
    )
    parser.add_argument(
        "fixture",
        nargs="?",
        help="fixture JSON path, or an example stem",
    )
    parser.add_argument(
        "ground_truth",
        nargs="?",
        help="ground-truth JSON path",
    )
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
        "--anchor-policy",
        choices=ANCHOR_POLICIES,
        default=DEFAULT_ANCHOR_POLICY,
        help=f"anchor color policy. Default: {DEFAULT_ANCHOR_POLICY}",
    )
    parser.add_argument(
        "--candidate-scope",
        choices=CANDIDATE_SCOPES,
        default=None,
        help=(
            f"candidate scope. Default: {DEFAULT_CANDIDATE_SCOPE}; "
            "--baseline always uses the frozen subject scope"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=CG_WL_MODES,
        default=DEFAULT_CG_WL_MODE,
        help=f"CG-WL relation mode. Default: {DEFAULT_CG_WL_MODE}",
    )
    parser.add_argument(
        "--all-modes",
        action="store_true",
        help="score full, out, in, and out-in modes",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="score the four canonical case/build combinations for one profile",
    )
    parser.add_argument(
        "--json-output",
        help="write the score result set to one JSON file",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="print and optionally serialize every CG-WL round partition",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.baseline:
            if (
                args.fixture is not None
                or args.ground_truth is not None
                or args.build
                or args.track != DEFAULT_ANALYSIS_TRACK
                or args.anchor_policy != DEFAULT_ANCHOR_POLICY
                or args.candidate_scope not in (None, SUBJECT_CANDIDATE_SCOPE)
            ):
                parser.error(
                    "--baseline is the frozen direct baseline and cannot be "
                    "combined with fixture, ground_truth, --build, another "
                    "--track, a non-address anchor policy, or a non-subject "
                    "candidate scope"
                )
            reports = score_v0_baseline(
                profile=args.profile,
                mode=args.mode,
                all_modes=args.all_modes,
                trace=args.trace,
            )
        else:
            if args.fixture is None:
                parser.error("fixture or --baseline is required")
            candidate_scope = normalize_candidate_scope(args.candidate_scope)
            if args.ground_truth is None:
                case, build = split_case_build(args.fixture, args.build)
                fixture_path = resolve_fixture_json(
                    case,
                    build,
                    args.profile,
                    args.track,
                    candidate_scope,
                    args.anchor_policy,
                )
                gt_path = resolve_gt_json(
                    case,
                    build,
                    args.profile,
                    candidate_scope,
                )
            else:
                fixture_path = args.fixture
                gt_path = args.ground_truth

            if args.all_modes:
                reports = score_all_modes(
                    fixture_path,
                    gt_path,
                    trace=args.trace,
                )
            else:
                reports = (score_case(
                    fixture_path,
                    gt_path,
                    mode=args.mode,
                    trace=args.trace,
                ),)

        print("\n\n".join(format_report(report) for report in reports))
        if args.json_output:
            write_reports_json(reports, args.json_output)
            print(f"\nJSON: {args.json_output}")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
