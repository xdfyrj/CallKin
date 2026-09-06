import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from analysis.wl_depth_baseline import (
        DEFAULT_RIPGREP_ROOT,
        DEFAULT_PROTOCOL,
        _canonical_sha256,
        _jobs,
        evaluate_case,
    )
    try:
        from analysis.wl_depth_baseline import _reference_partition_matches
    except ImportError:
        _reference_partition_matches = None
    try:
        from analysis.wl_depth_baseline import _enforce_cost_cap
    except ImportError:
        _enforce_cost_cap = None
    try:
        from analysis.wl_depth_baseline import _validate_job_identity
    except ImportError:
        _validate_job_identity = None
    try:
        from analysis.wl_depth_baseline import _verify_protocol_commit
    except ImportError:
        _verify_protocol_commit = None
    try:
        from analysis.wl_depth_baseline import _score_with_existing_scorer
    except ImportError:
        _score_with_existing_scorer = None
except ModuleNotFoundError:
    evaluate_case = None

from loader import load_case
from model import Case, Node
from provenance import BuildProvenance
from scores import GroundTruth, OriginGroup, load_ground_truth


def test_early_fixpoint_carry_forward() -> None:
    digest = "0" * 64
    provenance = BuildProvenance("unit", digest, digest, digest)
    case = Case(
        case="early-fixpoint",
        build="O3S",
        schema_version=5,
        profile="plain",
        provenance=provenance,
        nodes=[
            Node("a1", "user", True, []),
            Node("a2", "user", True, []),
            Node("b1", "user", True, []),
            Node("b2", "user", True, []),
        ],
    )
    ground_truth = GroundTruth(
        case="early-fixpoint",
        build="O3S",
        profile="plain",
        schema_version=5,
        origins=(
            OriginGroup("A", ("a1", "a2")),
            OriginGroup("B", ("b1", "b2")),
        ),
        symbols={member: (member,) for member in ("a1", "a2", "b1", "b2")},
        provenance=provenance,
    )

    assert evaluate_case is not None, "WL-depth evaluator is missing"
    result = evaluate_case(case, ground_truth, mode="full")

    assert result["fixpoint_round"] == 1
    assert list(result["depths"]) == ["seed", "r1", "r2", "fixpoint"]
    assert result["depths"]["r2"]["source_round"] == 1
    assert result["depths"]["r2"]["carried_forward"] is True
    assert result["depths"]["r2"]["pairwise"] == {
        "TP": 2,
        "FP": 4,
        "FN": 0,
        "TN": 0,
        "precision": 1 / 3,
        "recall": 1.0,
        "F1": 0.5,
    }
    assert result["depths"]["r2"]["cluster_count"] == 1
    assert result["depths"]["r2"]["singleton_count"] == 0
    assert result["depths"]["r2"]["fragmented_origin_count"] == 0
    assert result["depths"]["r2"]["collision_cluster_count"] == 1
    assert result["validation"] == {
        "target_universe_fixed": True,
        "partition_nesting_monotonic": True,
    }


def test_only_repository_inputs_require_tracking() -> None:
    ripgrep = _jobs(DEFAULT_RIPGREP_ROOT)[-1]
    assert getattr(ripgrep, "fixture_must_be_tracked", None) is False
    assert getattr(ripgrep, "ground_truth_must_be_tracked", None) is False


def test_reference_validation_compares_exact_partition_members() -> None:
    class Cluster:
        def __init__(self, members: tuple[str, ...]) -> None:
            self.member_ids = members

    final = {
        "partition_sha256": _canonical_sha256([["a", "c"], ["b", "d"]]),
    }
    reference_clusters = (Cluster(("a", "b")), Cluster(("c", "d")))
    assert _reference_partition_matches is not None
    assert _reference_partition_matches(final, reference_clusters) is False


def test_cost_cap_failure_records_job_and_stage() -> None:
    assert _enforce_cost_cap is not None
    try:
        _enforce_cost_cap(601.0, "real-world/fd/O3S/plain", "depth scoring")
    except RuntimeError as exc:
        assert "real-world/fd/O3S/plain" in str(exc)
        assert "depth scoring" in str(exc)
    else:
        raise AssertionError("WL-depth run did not enforce the 10-minute cap")


def test_job_labels_cannot_disagree_with_loaded_inputs() -> None:
    class Value:
        case = "actual"
        build = "O3S"
        profile = "plain"

    class Job:
        case = "reported"
        build = "O3S"
        profile = "plain"
        job_id = "controlled/reported/O3S/plain"

    assert _validate_job_identity is not None
    try:
        _validate_job_identity(Job(), Value(), Value())
    except ValueError as exc:
        assert "controlled/reported/O3S/plain" in str(exc)
    else:
        raise AssertionError("mislabeled job inputs were accepted")


def test_protocol_bytes_are_present_in_preregistered_commit() -> None:
    assert _verify_protocol_commit is not None
    _verify_protocol_commit(DEFAULT_PROTOCOL)


def test_changed_depths_match_unchanged_scorer() -> None:
    assert _score_with_existing_scorer is not None
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fixture = os.path.join(root, "fixtures/plain/family_graph_03.O3S.fixture.json")
    gt_path = os.path.join(root, "ground_truth/plain/family_graph_03.O3S.gt.json")
    case = load_case(fixture)
    ground_truth = load_ground_truth(gt_path)
    result = evaluate_case(case, ground_truth, mode="full", include_clusters=True)
    assert (
        result["depths"]["seed"]["partition_sha256"]
        != result["depths"]["r1"]["partition_sha256"]
    )
    for row in result["depths"].values():
        reference = _score_with_existing_scorer(
            fixture,
            gt_path,
            mode="full",
            clusters=row["_clusters"],
            fixpoint_round=result["fixpoint_round"],
        )
        pairwise = reference.pairwise
        assert row["pairwise"] == {
            "TP": pairwise.tp,
            "FP": pairwise.fp,
            "FN": pairwise.fn,
            "TN": pairwise.tn,
            "precision": pairwise.precision,
            "recall": pairwise.recall,
            "F1": pairwise.f1,
        }
        assert _reference_partition_matches(row, reference.clusters)


def main() -> int:
    test_early_fixpoint_carry_forward()
    test_only_repository_inputs_require_tracking()
    test_reference_validation_compares_exact_partition_members()
    test_cost_cap_failure_records_job_and_stage()
    test_job_labels_cannot_disagree_with_loaded_inputs()
    test_protocol_bytes_are_present_in_preregistered_commit()
    test_changed_depths_match_unchanged_scorer()
    print("WL-depth early-fixpoint carry-forward PASS")
    print("WL-depth external input pinning PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
