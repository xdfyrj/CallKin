"""F7 family templates.

F7.1 picks a medoid: the member that actually exists in the binary and matches
the rest of the family best. No averaged body is synthesised, because averaging
would erase exactly the information F7 is looking for, namely which positions
are common and which vary with the concrete types.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Callable, Mapping, Sequence

from body_similarity import BodyAlignment, FunctionBody, align_function_bodies, compare_bodies


@dataclass(frozen=True)
class FamilyMedoid:
    medoid: str
    members: tuple[str, ...]
    mean_similarity: dict[str, float]

    @property
    def score(self) -> float:
        return self.mean_similarity[self.medoid]

    def to_dict(self) -> dict[str, object]:
        return {
            "medoid": self.medoid,
            "members": list(self.members),
            "mean_similarity": dict(sorted(self.mean_similarity.items())),
            "score": self.score,
        }


def structure_similarity(first: FunctionBody, second: FunctionBody) -> float:
    """The scalar F6 accepts pairs on, reused so F7 centres on the same notion.

    `min` of the three structural ratios, matching
    `v1_engine._pair_features().structure_score`.
    """
    evidence = compare_bodies(first, second)
    return min(
        float(evidence.aligned_instruction_ratio),
        float(evidence.sequence_ratio),
        float(evidence.mnemonic_multiset_jaccard),
    )


def select_medoid(
    bodies: Mapping[str, FunctionBody],
    members: Sequence[str],
    *,
    similarity: Callable[[FunctionBody, FunctionBody], float] = structure_similarity,
) -> FamilyMedoid:
    """Choose the member with the highest mean similarity to the others.

    Costs one comparison per unordered pair, so a family of `m` members costs
    `m * (m - 1) / 2`. Callers that group very large clusters should bound the
    family size before calling.
    """
    unique = sorted(set(members))
    if len(unique) != len(members):
        raise ValueError("family members must be unique")
    if len(unique) < 2:
        raise ValueError("a medoid needs at least two members")
    missing = [member for member in unique if member not in bodies]
    if missing:
        raise ValueError(f"no body for family member {missing[0]!r}")

    totals = {member: 0.0 for member in unique}
    for first, second in combinations(unique, 2):
        score = similarity(bodies[first], bodies[second])
        totals[first] += score
        totals[second] += score

    divisor = len(unique) - 1
    mean_similarity = {member: total / divisor for member, total in totals.items()}
    # Highest mean wins; the lexicographically first id breaks ties so the
    # medoid never depends on iteration order.
    medoid = min(unique, key=lambda member: (-mean_similarity[member], member))
    return FamilyMedoid(
        medoid=medoid,
        members=tuple(unique),
        mean_similarity=mean_similarity,
    )


def align_members_to_medoid(
    bodies: Mapping[str, FunctionBody],
    selection: FamilyMedoid,
) -> dict[str, BodyAlignment]:
    """Align every other member onto the medoid, medoid first in each pair."""
    reference = bodies[selection.medoid]
    return {
        member: align_function_bodies(reference, bodies[member])
        for member in selection.members
        if member != selection.medoid
    }
