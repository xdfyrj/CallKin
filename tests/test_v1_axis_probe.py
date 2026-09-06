"""The axis probe refuses mismatched inputs and incomplete families."""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.v1_axis_probe import build_probe, check_inputs_agree  # noqa: E402


STRIPPED = "a" * 64
RAW_SHA = "b" * 64


def _artifact(**overrides):
    record = {
        "case": "demo", "build": "O3S", "profile": "plain",
        "provenance": {"stripped_sha256": STRIPPED},
    }
    record.update(overrides)
    return record


def _body_artifact(functions=(), **overrides):
    record = _artifact(
        provenance={"stripped_sha256": STRIPPED, "raw_graph_sha256": RAW_SHA},
        functions=list(functions),
    )
    record.update(overrides)
    return record


def _function(identifier: str, *, complete: bool = True):
    return {
        "id": identifier,
        "size": 4,
        "instructions": [],
        "normalized_instructions": [],
        "cfg_edges": [],
        "blocks": [],
        "quality": {"complete_decode": complete, "opaque_indirect_jumps": 0},
    }


def _expect(callable_, expected: str):
    try:
        callable_()
    except ValueError as exc:
        assert expected in str(exc), str(exc)
    else:
        raise AssertionError(f"expected a refusal mentioning {expected!r}")


def test_matching_inputs_are_accepted():
    check_inputs_agree(
        _body_artifact(), _artifact(), _artifact(), raw_graph_sha256=RAW_SHA
    )


def test_a_different_profile_is_refused():
    _expect(
        lambda: check_inputs_agree(
            _body_artifact(), _artifact(profile="min"), _artifact(),
            raw_graph_sha256=RAW_SHA,
        ),
        "disagree on profile",
    )


def test_a_different_stripped_binary_is_refused():
    _expect(
        lambda: check_inputs_agree(
            _body_artifact(),
            _artifact(provenance={"stripped_sha256": "c" * 64}),
            _artifact(),
            raw_graph_sha256=RAW_SHA,
        ),
        "disagree on stripped_sha256",
    )


def test_a_raw_graph_the_body_was_not_built_from_is_refused():
    _expect(
        lambda: check_inputs_agree(
            _body_artifact(), _artifact(), _artifact(), raw_graph_sha256="d" * 64
        ),
        "built against raw graph",
    )


def _probe(functions, members, **kwargs):
    return build_probe(
        _body_artifact(functions),
        _artifact(transfers=[]),
        _artifact(origins=[{"origin": "demo::family", "members": members}]),
        ["demo::family"],
        provenance={"raw_graph_sha256": RAW_SHA},
        **kwargs,
    )


def test_a_member_without_a_body_is_refused_by_default():
    _expect(
        lambda: _probe([_function("FUN_00200000")], ["FUN_00200000", "FUN_00200010"]),
        "without a body",
    )


def test_a_member_with_an_incomplete_decode_is_refused_by_default():
    _expect(
        lambda: _probe(
            [_function("FUN_00200000"), _function("FUN_00200010", complete=False)],
            ["FUN_00200000", "FUN_00200010"],
        ),
        "incomplete",
    )


def test_the_opt_out_records_what_it_dropped():
    report = _probe(
        [_function("FUN_00200000"), _function("FUN_00200010"),
         _function("FUN_00200020", complete=False)],
        ["FUN_00200000", "FUN_00200010", "FUN_00200020", "FUN_00200030"],
        allow_incomplete_family=True,
    )

    (family,) = report["families"]
    assert family["member_count"] == 2
    assert family["ground_truth_member_count"] == 4
    assert family["excluded_members"]["no_body"] == ["FUN_00200030"]
    assert family["excluded_members"]["incomplete_decode"] == ["FUN_00200020"]


def main() -> int:
    test_matching_inputs_are_accepted()
    test_a_different_profile_is_refused()
    test_a_different_stripped_binary_is_refused()
    test_a_raw_graph_the_body_was_not_built_from_is_refused()
    test_a_member_without_a_body_is_refused_by_default()
    test_a_member_with_an_incomplete_decode_is_refused_by_default()
    test_the_opt_out_records_what_it_dropped()
    print("F7.3 axis probe input checks PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
