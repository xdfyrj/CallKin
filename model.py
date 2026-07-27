# fixtures dataclass

from dataclasses import dataclass

from provenance import BuildProvenance

@dataclass(frozen=True)
class Call:
    target: str
    count: int

@dataclass(frozen=True)
class Node:
    id: str
    type: str      # "user" or "anchor"
    scored: bool
    calls: list[Call]

@dataclass(frozen=True)
class Case:
    case: str
    build: str
    schema_version: int
    nodes: list[Node]
    profile: str = "plain"
    provenance: BuildProvenance | None = None
