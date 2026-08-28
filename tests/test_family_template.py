"""F7.1 medoid selection."""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import FunctionBody  # noqa: E402
from family_template import (  # noqa: E402
    align_members_to_medoid,
    select_medoid,
    structure_similarity,
)


def _body(identifier: str, mnemonics: list[str]) -> FunctionBody:
    instructions = [
        {
            "offset": offset,
            "mnemonic_class": mnemonic,
            "operands": [],
            "control_flow": "return" if mnemonic == "RET" else "none",
        }
        for offset, mnemonic in enumerate(mnemonics)
    ]
    return FunctionBody(
        id=identifier,
        size=len(mnemonics),
        instructions=tuple(instructions),
        edges=(),
        blocks=({"label": "B0", "instruction_offsets": list(range(len(mnemonics)))},),
        quality={"complete_decode": True, "opaque_indirect_jumps": 0},
    )


def _family(bodies: list[FunctionBody]) -> dict[str, FunctionBody]:
    return {body.id: body for body in bodies}


def test_the_central_member_is_chosen():
    # B sits between A and C, so it matches both better than they match each other.
    bodies = _family([
        _body("A", ["PUSH", "MOV", "MOV", "RET"]),
        _body("B", ["PUSH", "MOV", "XOR", "RET"]),
        _body("C", ["PUSH", "XOR", "XOR", "RET"]),
    ])

    selection = select_medoid(bodies, ["A", "B", "C"])

    assert selection.medoid == "B"
    assert selection.members == ("A", "B", "C")
    assert selection.score == max(selection.mean_similarity.values())
    assert selection.mean_similarity["B"] > selection.mean_similarity["A"]
    assert selection.mean_similarity["B"] > selection.mean_similarity["C"]


def test_the_medoid_is_a_real_member_not_a_synthetic_body():
    bodies = _family([
        _body("A", ["PUSH", "RET"]),
        _body("B", ["PUSH", "MOV", "RET"]),
        _body("C", ["PUSH", "MOV", "MOV", "RET"]),
    ])

    selection = select_medoid(bodies, ["A", "B", "C"])

    assert selection.medoid in bodies
    assert set(selection.mean_similarity) == {"A", "B", "C"}


def test_ties_break_on_the_first_id_and_input_order_does_not_matter():
    bodies = _family([
        _body("A", ["PUSH", "RET"]),
        _body("B", ["PUSH", "RET"]),
        _body("C", ["PUSH", "RET"]),
    ])

    assert select_medoid(bodies, ["C", "B", "A"]).medoid == "A"
    assert select_medoid(bodies, ["A", "B", "C"]).medoid == "A"


def test_identical_members_score_one():
    bodies = _family([_body("A", ["PUSH", "RET"]), _body("B", ["PUSH", "RET"])])

    selection = select_medoid(bodies, ["A", "B"])

    assert selection.score == 1.0
    assert structure_similarity(bodies["A"], bodies["B"]) == 1.0


def test_bad_input_is_refused():
    bodies = _family([_body("A", ["PUSH", "RET"]), _body("B", ["PUSH", "RET"])])
    for members, expected in (
        (["A"], "at least two"),
        (["A", "A", "B"], "unique"),
        (["A", "Z"], "no body"),
    ):
        try:
            select_medoid(bodies, members)
        except ValueError as exc:
            assert expected in str(exc), (members, str(exc))
        else:
            raise AssertionError(f"{members} was accepted")


def test_every_other_member_is_aligned_onto_the_medoid():
    bodies = _family([
        _body("A", ["PUSH", "MOV", "MOV", "RET"]),
        _body("B", ["PUSH", "MOV", "XOR", "RET"]),
        _body("C", ["PUSH", "XOR", "XOR", "RET"]),
    ])
    selection = select_medoid(bodies, ["A", "B", "C"])

    alignments = align_members_to_medoid(bodies, selection)

    assert set(alignments) == {"A", "C"}
    for alignment in alignments.values():
        assert alignment.block_pairs == (("B0", "B0"),)
        assert alignment.instruction_pairs, "the medoid alignment carries instructions"
        # PUSH and RET are shared by every member of this family.
        assert (0, 0) in alignment.instruction_pairs
        assert (3, 3) in alignment.instruction_pairs


def main() -> int:
    test_the_central_member_is_chosen()
    test_the_medoid_is_a_real_member_not_a_synthetic_body()
    test_ties_break_on_the_first_id_and_input_order_does_not_matter()
    test_identical_members_score_one()
    test_bad_input_is_refused()
    test_every_other_member_is_aligned_onto_the_medoid()
    print("F7.1 medoid PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
