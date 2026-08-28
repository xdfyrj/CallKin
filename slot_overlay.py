"""F7.2a: recover slot observations for one function.

F2 deliberately erases call targets from the normalized body so that F4 stays
local-only. F7 needs them back, so this overlay joins the raw call graph onto
the normalized instructions instead of weakening F2:

    function base address + instruction offset == raw transfer callsite

Data references and immediate constants already survive normalization and are
read straight off the instruction. Nothing here feeds an F4 score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from body_similarity import FunctionBody


CALL_TARGET = "CALL_TARGET"
DATA_REFERENCE = "DATA_REFERENCE"
IMMEDIATE_CONSTANT = "IMMEDIATE_CONSTANT"
SLOT_KINDS = (CALL_TARGET, DATA_REFERENCE, IMMEDIATE_CONSTANT)

RESOLVED = "resolved"
UNRESOLVED = "unresolved"
FILTERED = "filtered"
AMBIGUOUS = "ambiguous"
MISSING = "missing"
SLOT_STATES = (RESOLVED, UNRESOLVED, FILTERED, AMBIGUOUS, MISSING)


@dataclass(frozen=True)
class SlotObservation:
    offset: int
    index: int
    kind: str
    value: Any
    state: str
    resolver: str | None = None
    status: str | None = None
    filter_reason: str | None = None

    @property
    def usable(self) -> bool:
        """Only resolved observations may define a variation axis."""
        return self.state == RESOLVED

    @property
    def position(self) -> tuple[int, int, str]:
        return (self.offset, self.index, self.kind)

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "index": self.index,
            "kind": self.kind,
            "value": self.value,
            "state": self.state,
            "resolver": self.resolver,
            "status": self.status,
            "filter_reason": self.filter_reason,
        }


def transfers_by_source(
    raw_graph: Mapping[str, Any],
) -> dict[int, dict[int, Mapping[str, Any]]]:
    """Index raw transfers as `{source address: {callsite address: transfer}}`."""
    index: dict[int, dict[int, Mapping[str, Any]]] = {}
    for transfer in raw_graph["transfers"]:
        source = int(transfer["source"], 16)
        callsite = int(transfer["callsite"], 16)
        callsites = index.setdefault(source, {})
        if callsite in callsites:
            raise ValueError(
                f"duplicate raw transfer for source 0x{source:x} "
                f"callsite 0x{callsite:x}"
            )
        callsites[callsite] = transfer
    return index


def _call_observation(
    offset: int,
    transfer: Mapping[str, Any] | None,
) -> SlotObservation:
    if transfer is None:
        return SlotObservation(
            offset=offset, index=0, kind=CALL_TARGET, value=None, state=MISSING
        )

    resolver = transfer.get("resolver")
    status = transfer.get("status")
    filter_reason = transfer.get("filter_reason")
    targets = transfer.get("angr_targets") or []

    def build(value: Any, state: str) -> SlotObservation:
        return SlotObservation(
            offset=offset,
            index=0,
            kind=CALL_TARGET,
            value=value,
            state=state,
            resolver=resolver,
            status=status,
            filter_reason=filter_reason,
        )

    # Several candidate targets never collapse into one slot value.
    if len(targets) > 1:
        return build(None, AMBIGUOUS)
    if status == "filtered":
        return build(transfer.get("target"), FILTERED)
    if status == "resolved" and transfer.get("target") is not None:
        return build(transfer["target"], RESOLVED)
    return build(None, UNRESOLVED)


def collect_slot_observations(
    body: FunctionBody,
    base_address: int,
    transfers: Mapping[int, Mapping[str, Any]],
) -> tuple[SlotObservation, ...]:
    """Observe every slot of one function.

    `transfers` maps callsite address to raw transfer for this function only.
    Call slots come from that map because F2 erased their targets; data
    references and constants come from the normalized instruction.
    """
    observations: list[SlotObservation] = []
    for instruction in body.instructions:
        offset = int(instruction["offset"])
        if instruction.get("control_flow") == "call":
            observations.append(
                _call_observation(offset, transfers.get(base_address + offset))
            )

        index = 1
        for slot in instruction.get("slots", ()):
            if slot.get("kind") != "data":
                continue
            value = slot.get("value")
            observations.append(
                SlotObservation(
                    offset=offset,
                    index=index,
                    kind=DATA_REFERENCE,
                    value=value,
                    state=RESOLVED if value is not None else MISSING,
                    resolver=slot.get("resolver"),
                    status=slot.get("status"),
                )
            )
            index += 1
        for constant in instruction.get("constants", ()):
            observations.append(
                SlotObservation(
                    offset=offset,
                    index=index,
                    kind=IMMEDIATE_CONSTANT,
                    value=int(constant),
                    state=RESOLVED,
                )
            )
            index += 1

    observations.sort(key=lambda item: item.position)
    return tuple(observations)
