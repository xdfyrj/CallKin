# fixtures dataclass

from dataclasses import dataclass

from analysis_provenance import AnalysisProvenance
from provenance import BuildProvenance

@dataclass(frozen=True)
class Call:
    target: str
    count: int


@dataclass(frozen=True)
class Observability:
    resolved_out_calls: int
    unresolved_indirect_out_callsites: int
    address_taken_references: int | None
    resolved_in_callers: int


@dataclass(frozen=True)
class Abstention:
    id: str
    reason: str


@dataclass(frozen=True)
class Node:
    id: str
    type: str      # "user" or "anchor"
    scored: bool
    calls: list[Call]
    anchor_kind: str | None = None
    color_class: str | None = None
    observability: Observability | None = None

@dataclass(frozen=True)
class Case:
    case: str
    build: str
    schema_version: int
    nodes: list[Node]
    profile: str = "plain"
    provenance: BuildProvenance | None = None
    analysis: AnalysisProvenance | None = None
    abstentions: tuple[Abstention, ...] = ()
