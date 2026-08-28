"""F7 family templates.

F7.1 picks a medoid: the member that actually exists in the binary and matches
the rest of the family best. No averaged body is synthesised, because averaging
would erase exactly the information F7 is looking for, namely which positions
are common and which vary with the concrete types.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Any, Callable, Mapping, Sequence

from body_similarity import BodyAlignment, FunctionBody, align_function_bodies, compare_bodies
from slot_overlay import MISSING, RESOLVED, SlotObservation


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


COMMON = "common"
OPTIONAL = "optional"


@dataclass(frozen=True)
class TemplateSlot:
    """One medoid position, observed across every member."""

    block: str
    offset: int
    index: int
    kind: str
    values_by_member: dict[str, Any]
    states_by_member: dict[str, str]

    @property
    def resolved_values(self) -> tuple[Any, ...]:
        values = {
            self.values_by_member[member]
            for member, state in self.states_by_member.items()
            if state == RESOLVED
        }
        return tuple(sorted(values, key=repr))

    @property
    def observed_by_all(self) -> bool:
        return all(state == RESOLVED for state in self.states_by_member.values())

    @property
    def varies(self) -> bool:
        return len(self.resolved_values) > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "block": self.block,
            "offset": self.offset,
            "index": self.index,
            "kind": self.kind,
            "values_by_member": dict(sorted(self.values_by_member.items())),
            "states_by_member": dict(sorted(self.states_by_member.items())),
            "variant_count": len(self.resolved_values),
            "varies": self.varies,
        }


@dataclass(frozen=True)
class FamilyTemplate:
    medoid: str
    members: tuple[str, ...]
    block_roles: dict[str, str]
    member_specific_blocks: dict[str, tuple[str, ...]]
    slots: tuple[TemplateSlot, ...]

    @property
    def variation_slots(self) -> tuple[TemplateSlot, ...]:
        return tuple(slot for slot in self.slots if slot.varies)

    def to_dict(self) -> dict[str, Any]:
        return {
            "medoid": self.medoid,
            "members": list(self.members),
            "block_roles": dict(sorted(self.block_roles.items())),
            "member_specific_blocks": {
                member: list(blocks)
                for member, blocks in sorted(self.member_specific_blocks.items())
            },
            "slots": [slot.to_dict() for slot in self.slots],
            "variation_slot_count": len(self.variation_slots),
        }


def _medoid_block_of_offset(body: FunctionBody) -> dict[int, str]:
    return {
        offset: block["label"]
        for block in body.blocks
        for offset in block.get("instruction_offsets", ())
    }


def build_family_template(
    bodies: Mapping[str, FunctionBody],
    selection: FamilyMedoid,
    observations: Mapping[str, Sequence[SlotObservation]],
    *,
    alignments: Mapping[str, BodyAlignment] | None = None,
) -> FamilyTemplate:
    """Describe a family as medoid positions plus what each member puts there.

    Positions are anchored on the medoid, so the medoid observes itself through
    an identity mapping. Only `CALL_TARGET`, `DATA_REFERENCE` and
    `IMMEDIATE_CONSTANT` are handled: operand width and memory shape change the
    instruction token itself, so the current LCS leaves them unmatched rather
    than pairing them, and reading them here would invent correspondences.
    """
    missing = [member for member in selection.members if member not in observations]
    if missing:
        raise ValueError(f"no slot observations for member {missing[0]!r}")
    if alignments is None:
        alignments = align_members_to_medoid(bodies, selection)

    medoid = selection.medoid
    medoid_body = bodies[medoid]
    block_of_offset = _medoid_block_of_offset(medoid_body)

    # Medoid offset -> member offset. The medoid maps onto itself.
    offset_maps: dict[str, dict[int, int]] = {
        medoid: {offset: offset for offset in block_of_offset}
    }
    for member in selection.members:
        if member == medoid:
            continue
        offset_maps[member] = dict(alignments[member].instruction_pairs)

    observed = {
        member: {item.position: item for item in observations[member]}
        for member in selection.members
    }

    slots: list[TemplateSlot] = []
    for anchor in observations[medoid]:
        values: dict[str, Any] = {}
        states: dict[str, str] = {}
        for member in selection.members:
            member_offset = offset_maps[member].get(anchor.offset)
            found = (
                None
                if member_offset is None
                else observed[member].get((member_offset, anchor.index, anchor.kind))
            )
            values[member] = None if found is None else found.value
            states[member] = MISSING if found is None else found.state
        slots.append(
            TemplateSlot(
                block=block_of_offset.get(anchor.offset, ""),
                offset=anchor.offset,
                index=anchor.index,
                kind=anchor.kind,
                values_by_member=values,
                states_by_member=states,
            )
        )

    block_roles: dict[str, str] = {}
    medoid_labels = {block["label"] for block in medoid_body.blocks}
    for label in sorted(medoid_labels):
        matched = sum(
            1
            for member in selection.members
            if member == medoid
            or any(left == label for left, _ in alignments[member].block_pairs)
        )
        block_roles[label] = COMMON if matched == len(selection.members) else OPTIONAL

    # A block a member owns alone stays that member's own. Two members' orphan
    # blocks are never merged into one optional region: that would need its own
    # alignment between members, which this stage does not attempt.
    member_specific: dict[str, tuple[str, ...]] = {}
    for member in selection.members:
        if member == medoid:
            continue
        paired = {right for _, right in alignments[member].block_pairs}
        orphans = sorted(
            block["label"]
            for block in bodies[member].blocks
            if block["label"] not in paired
        )
        if orphans:
            member_specific[member] = tuple(orphans)

    return FamilyTemplate(
        medoid=medoid,
        members=selection.members,
        block_roles=block_roles,
        member_specific_blocks=member_specific,
        slots=tuple(slots),
    )
