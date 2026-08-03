import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import _neighbor_color_multiset, run_cg_wl
from model import Call, Case, Node


def check_relation_modes() -> int:
    case = Case(
        case="mode-test",
        build="unit",
        schema_version=3,
        nodes=[
            Node("caller_a", "anchor", False, [Call("leaf_a", 1)]),
            Node("caller_b", "anchor", False, [Call("leaf_b", 1)]),
            Node("leaf_a", "user", True, []),
            Node("leaf_b", "user", True, []),
        ],
    )

    expected_split = [["leaf_a"], ["leaf_b"]]
    checks = {
        "full": expected_split,
        "out": [["leaf_a", "leaf_b"]],
        "in": expected_split,
        "out-in": expected_split,
    }

    for mode, expected in checks.items():
        got = run_cg_wl(case, mode=mode).clusters
        if got != expected:
            print(f"FAIL mode {mode}: expected {expected}, got {got}")
            return 1

    traced = run_cg_wl(case, mode="full", trace=True)
    if len(traced.trace) != traced.rounds + 1:
        print("FAIL trace must include seed and every refinement round")
        return 1
    if traced.trace[0].round_index != 0 or traced.trace[0].changed is not None:
        print("FAIL trace round 0 must be the seed")
        return 1
    if traced.trace[-1].changed is not False:
        print("FAIL trace must end with the fixpoint confirmation round")
        return 1
    if traced.trace[-1].clusters != tuple(tuple(c) for c in traced.clusters):
        print("FAIL final trace partition must match result clusters")
        return 1
    if run_cg_wl(case, mode="full").trace:
        print("FAIL trace must be empty unless requested")
        return 1

    return 0


def check_anchor_color_classes() -> int:
    case = Case(
        case="anchor-color-test",
        build="unit",
        schema_version=5,
        nodes=[
            Node(
                "caller_a",
                "anchor",
                False,
                [Call("leaf_a", 1)],
                anchor_kind="incoming",
                color_class="ROLE:incoming",
            ),
            Node(
                "caller_b",
                "anchor",
                False,
                [Call("leaf_b", 1)],
                anchor_kind="incoming",
                color_class="ROLE:incoming",
            ),
            Node("leaf_a", "user", True, []),
            Node("leaf_b", "user", True, []),
        ],
    )
    if run_cg_wl(case, mode="full").clusters != [["leaf_a", "leaf_b"]]:
        print("FAIL anchors with one color_class must share one fixed color")
        return 1
    return 0


def main() -> int:
    if check_relation_modes() != 0:
        return 1
    if check_anchor_color_classes() != 0:
        return 1

    prev_colors = {
        "callee_a": "C:leaf",
        "callee_b": "C:leaf",
        "callee_c": "C:other",
    }
    edges = [
        ("callee_a", 1),
        ("callee_b", 2),
        ("callee_c", 4),
    ]

    expected = (
        ("C:leaf", 3),
        ("C:other", 4),
    )
    got = _neighbor_color_multiset(edges, prev_colors)

    if got != expected:
        print(f"FAIL expected {expected}, got {got}")
        return 1

    print("neighbor color multiset aggregation PASS")
    print("CG-WL relation modes PASS")
    print("CG-WL round trace PASS")
    print("CG-WL anchor color classes PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
